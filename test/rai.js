process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var RAIServer = require("../lib/rai").RAIServer,
    runClientMockup = require("../lib/rai").runClientMockup,
    testCase = require('nodeunit').testCase,
    utillib = require("util"),
    netlib = require("net"),
    crypto = require("crypto"),
    tlslib = require("tls"),
    assert = require('assert');

var PORT_NUMBER = 8397;

// monkey patch net and tls to support nodejs 0.4
if(!netlib.connect && netlib.createConnection){
    netlib.connect = netlib.createConnection;
}

if(!tlslib.connect && tlslib.createConnection){
    tlslib.connect = tlslib.createConnection;
}

describe('General tests', function() {
  it('Create and close a server', function(done) {
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
      if (err) return done(err);
      server.end(function(){
        return done();
      });
    });
  });

  it('Create a secure server', function(done){
    var server = new RAIServer({secureConnection: true});
    server.listen(PORT_NUMBER, function(err){
      if (err) return done(err);
      server.end(function(){
        return done();
      });
    });
  });

  it('Duplicate server fails', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
      if (err) return done(err);
      
      var duplicate = new RAIServer();
      duplicate.listen(PORT_NUMBER, function(err){
        try {
          assert.ok(err, "Responds with error");
          server.end(function(){
            return done();
          });
        } catch(err) {
          return done(err);
        }
      });
        
    });
  });
  
  it('Connection event', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
        
      server.on("connect", function(socket){
        try {
          assert.ok(socket, "Client connected");
        } catch (err) {
          return done(err);
        }
        
        socket.on("end", function(){
          
          server.end(function(){
            return done();
          });
        });
        
        socket.on("error", function(err){
          if (err) return done(err);
        });
      });
      
      var client = netlib.connect(PORT_NUMBER, function(){
        client.end();
      });

    });
  });

  it('Close client socket', function(done){
    let connectionOpened,
      connectionClosed;

    var server = new RAIServer();

    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        try {
          assert.ok(socket, "Client connected");
        } catch (err) {
          return done(err);
        }

        socket.on("end", function(){
          server.end(function(){
            try {
              assert.ok(connectionOpened, 'Client connect returned');
              assert.ok(connectionClosed, 'Client end event fired');
            } catch (err) {
              return done(err);
            }
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });

        socket.end();
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        connectionOpened = true;
      });
      client.on("end", function(){
        connectionClosed = true;
      });

    });
  });

  it('Send data to client', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.send("HELLO");

        socket.on("end", function(){
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        client.on("data", function(chunk){
          try {
            assert.equal(chunk.toString(), "HELLO\r\n");
          } catch (err) {
            return done(err);
          }
          client.end();
        });
      });

    });
  });
});

describe('Secure connection', function() {
  it('STARTTLS with event', function(done){
    let secureConnectionOpened;

    var server = new RAIServer({ debug: true });
    server.listen(PORT_NUMBER, function(err){
      debugger;

      server.on("connect", function(socket){

        debugger;
        socket.on("tls", function(){
          debugger;
          secureConnectionOpened = true;
          socket.send("TEST");
        });


        socket.startTLS();

        socket.on("end", function(){
          server.end(function(){
            try {
              assert.ok(secureConnectionOpened, 'Secure Connection Opened');
            } catch(err) {
              return done(err);
            }
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      debugger;

      var sslcontext = tlslib.createSecureContext();
      var clientSocket = tlslib.connect({port: PORT_NUMBER, secureContext: sslcontext}, function(){
        debugger;

        clientSocket.on("data", function(chunk){
          try {
            assert.equal(chunk.toString(), "TEST\r\n");
          } catch (err) {
            return done(err);
          }
          clientSocket.end();
        });
      });

    });
  });
  it('STARTTLS Callback', function(done){
    var server = new RAIServer({ debug: true} );
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.startTLS(function(){
          socket.send("TEST");
        });

        socket.on("tls", function(){
          return done(new Error('Should not occur'));
        });

        socket.on("end", function(){
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var sslcontext = tlslib.createSecureContext();
      var clientSocket = tlslib.connect({port: PORT_NUMBER, secureContext: sslcontext}, function(){

        clientSocket.on("data", function(chunk){
          try {
            assert.equal(chunk.toString(), "TEST\r\n");
          } catch (err) {
            return done(err);
          }
          clientSocket.end();
        });
      });


    });
  });
  it('STARTTLS clears command buffer', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.on("command", function(command){
          if(command == "STARTTLS"){
            socket.startTLS();
            socket.send("OK");
          }else if(command == "KILL"){
            return done(new Error('Should not occur'));
          }else if(command == "OK"){
            assert.ok(1, "OK");
          }

        });

        socket.on("tls", function(){
          assert.ok(1, "Secure connection opened");
          socket.send("TEST");
        });

        socket.on("end", function(){
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){

        client.write("STARTTLS\r\nKILL\r\n");

        client.on("data", function(chunk){
          if(chunk.toString("utf-8").trim() == "OK"){

            var sslcontext = crypto.createCredentials();
            const secureClient = tlslib.connect({ socket: client, secureContext: sslcontext});

            secureClient.on("secureConnect", function(){
              secureClient.write("OK\r\n");
              secureClient.end();
            });
          }
        });

      });

    });
  });
  it('STARTTLS on secure server fails', function(done){
    var server = new RAIServer({secureConnection: true});
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.on("error", function(err){
          assert.ok(err);
          socket.end();
          server.end(function(){
            return done();
          });
        });

        socket.on("command", (function(command){
          process.nextTick(socket.startTLS.bind(socket, function(){
            server.end();
            return done(new Error('Secure connection opened')); // should not occur
          }));

        }).bind(this));

        socket.on("tls", function(){
          return done(new Error('Should not occur'));
        });

      });

      var client = tlslib.connect(PORT_NUMBER, function(){
        client.write("HELLO!\r\n");
      });

    });
  });
});

describe('Client commands', function() {
  it('Receive Simple Command', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.on("command", function(command, payload){
          try {
            assert.equal(command, "STATUS");
            assert.equal(payload.toString(), "");
          } catch (err) {
            return done(err);
          }
          socket.end();
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        client.write("STATUS\r\n");
      });

    });
  });

  it('Receive Command with payload', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
        
      server.on("connect", function(socket){
          
        socket.on("command", function(command, payload){
          try {
            assert.equal(command, "MAIL");
            assert.equal(payload.toString(), "TO:");
          } catch (err) {
            return done(err);
          }
          socket.end();
          
          server.end(function(){
            return done();
          });
        });
        
        socket.on("error", function(err){
          if (err) return done(err);
        });
      });
      
      var client = netlib.connect(PORT_NUMBER, function(){
        client.write("MAIL TO:\r\n");
      });

    });
  });
});

describe('Data mode', function() {
  it('DATA mode', function(done){
    var server = new RAIServer(),
      datapayload = "tere\r\nvana kere";
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.startDataMode();


        socket.on("data", function(chunk){
          try {
            assert.equal(datapayload, chunk.toString());
          } catch (err) {
            return done(err);
          }
        });

        socket.on("ready", function(){
          assert.ok(1,"Data ready");
          server.end(function(){
            done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        client.write(datapayload+"\r\n.\r\n");
        client.end();
      });

    });
  });
  it('Small chunks DATA mode', function(done){
    var server = new RAIServer(),
      datapayload = "tere\r\nvana kere õäöü\r\n.\r",
      databytes = [],
      fullpayload = datapayload+"\r\n.\r\n";
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.startDataMode();

        socket.on("data", function(chunk){
          databytes = databytes.concat(Array.prototype.slice.call(chunk));
        });

        socket.on("ready", function(){
          try {
            assert.equal(new Buffer(databytes).toString("utf-8"), datapayload);
          } catch (err) {
            return done(err);
          }
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });

        for(var i=0, len = fullpayload.length; i<len; i++){
          socket._onReceiveData(new Buffer(fullpayload.charAt(i), "utf-8").toString("binary"));
        }

      });

      var client = netlib.connect(PORT_NUMBER, function(){
        client.end();
      });

    });
  });
});

describe('Pipelining support', function() {
  it("Pipelining", function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){

        socket.on("command", function(command, payload){
          if(command == "STATUS"){
            assert.ok(1, "Status received");
          }else if(command=="DATA"){
            assert.ok(1, "data command received");
            socket.startDataMode();
          }else if(command=="END"){
            assert.ok(1, "all received");
          }else{
            return done(new Error("Unexpected command: "+command));
          }
        });

        socket.on("data", function(chunk){
          try {
            assert.equal(chunk.toString(), "TE\r\nST");
          } catch (err) {
            return done(err);
          }
        });

        socket.on("ready", function(){
          assert.ok(1, "Data mode ended");
        });

        socket.on("end", function(){
          assert.ok(1, "All ready");
          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        client.write("STATUS\r\nSTATUS\r\nSTATUS\r\nDATA\r\nTE\r\nST\r\n.\r\nEND\r\n");
        client.end();
      });

    });
  });
});

describe('Timeout tests', function() {
  it('Timeout', function(done){
    var server = new RAIServer({timeout: 300, disconnectOnTimeout: true});

    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){
        try {
          assert.ok(socket, "Client connected");
        } catch (err) {
          return done(err);
        }
        socket.on("timeout", function(){
          assert.ok(1, "Connection closed");

          server.end(function(){
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var client = netlib.connect(PORT_NUMBER, function(){
        assert.ok(1, "Connected to server");
      });

    });
  });
  it('Timeout with TLS', function(done){
    let secureConnection;

    var server = new RAIServer({timeout: 300, disconnectOnTimeout: true});
    server.listen(PORT_NUMBER, function(err){


      server.on("connect", function(socket){

        socket.startTLS();
        socket.on("tls", function(){
          assert.ok(1, "Secure connection opened");
          socket.send("TEST");
        });

        socket.on("timeout", function(){
          assert.ok(1, "Timeout occurred");
          server.end(function(){
            try {
              assert.ok(secureConnection, "secure connection");
            } catch (err) {
              return done(err);
            }
            return done();
          });
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var sslcontext = crypto.createCredentials();

      // This bit where we manually wrap a socket
      // and then call connect on the wrapped socket
      // is a workaround for a nodeJS issue where
      // end events aren't properly being triggered
      // by sockets connected via tls.connect
      // See: https://github.com/nodejs/node/issues/10871
      var socket = new netlib.Socket();
      var tlsOptions = {
        port: PORT_NUMBER,
        socket: socket,
        secureContext: sslcontext
      };
      var client = tlslib.connect(tlsOptions);
      socket.connect({
        port: PORT_NUMBER
      });


      client.on("secureConnect", function(){
        secureConnection = true;
      });

      socket.on('end', function() {
        socket.end();
      });

    });
  });
});

describe('Client Mockup', function() {
  it('All command', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
      server.on("connect", function(socket){
        socket.send("220 Welcome");
        socket.on("command", function(command, payload){
          switch(command) {
            case "HELO": socket.send("250 HI"); break;
            case "NOOP": socket.send("250 OK"); break;
            case "QUIT": socket.send("221 Bye"); socket.end(); break;
            default: socket.send("500");
          }
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var cmds = ["HELO", "NOOP", "QUIT"];
      runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse, allResponses){
        allResponses = allResponses.map(function(value) { return value.toString("utf-8"); });
        try {
          assert.deepEqual(allResponses, [ "220 Welcome\r\n", "250 HI\r\n", "250 OK\r\n", "221 Bye\r\n" ]);
        } catch (err) {
          return done(err);
        }
        server.end(function(){
          return done();
        });

      });

    });
  });
  it('Last commands', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){
      server.on("connect", function(socket){
        socket.send("220 HI");
        socket.on("command", function(command, payload){
          switch(command) {
            case "HELO": socket.send("250 HI"); break;
            case "NOOP": socket.send("250 OK"); break;
            case "QUIT": socket.send("221 Bye"); socket.end(); break;
            default: socket.send("500");
          }
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var cmds = ["HELO", "NOOP", "QUIT"];
      runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse){
        try {
          assert.equal(lastResponse.toString("utf-8"), "221 Bye\r\n");
        } catch (err) {
          return done(err);
        }
        server.end(function(){
          return done();
        });

      });

    });
  });
  it('All command(STARTTLS)', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){
        socket.tlsStatus = 0;
        socket.send("220 Welcome");
        socket.on("command", function(command, payload){
          switch(command){
            case "EHLO":
              if(socket.tlsStatus===0){
                socket.send("250-HI\r\n250 STARTTLS");
              }else{
                socket.send("250 HI");
              }
              break;
            case "NOOP": socket.send("250 OK"); break;
            case "QUIT": socket.send("221 Bye"); socket.end(); break;
            case "STARTTLS": socket.startTLS(); socket.send("220 Go ahead"); break;
            default: socket.send("500");
          }
        });

        socket.on("tls", function(){
          assert.ok(1, "Secure connection opened");
          socket.tlsStatus = 1;
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var cmds = ["EHLO", "STARTTLS", "EHLO", "NOOP", "QUIT"];
      runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse, allResponses){
        allResponses = allResponses.map(function(value) { return value.toString("utf-8"); });
        try {
          assert.deepEqual(allResponses, ["220 Welcome\r\n", "250-HI\r\n250 STARTTLS\r\n", "220 Go ahead\r\n",
                                          "250 HI\r\n", "250 OK\r\n", "221 Bye\r\n" ]);
        } catch (err) {
          return done(err);
        }
        server.end(function(){
          return done();
        });

      });

    });
  });
  it('Last commands(STARTTLS)', function(done){
    var server = new RAIServer();
    server.listen(PORT_NUMBER, function(err){

      server.on("connect", function(socket){
        socket.tlsStatus = 0;
        socket.send("220 Welcome");
        socket.on("command", function(command, payload){
          switch(command){
            case "EHLO":
              if(socket.tlsStatus===0){
                socket.send("250-HI\r\n250 STARTTLS");
              }else{
                socket.send("250 HI");
              }
              break;
            case "NOOP": socket.send("250 OK"); break;
            case "QUIT": socket.send("221 Bye"); socket.end(); break;
            case "STARTTLS": socket.startTLS(); socket.send("220 Go ahead"); break;
            default: socket.send("500");
          }
        });

        socket.on("tls", function(){
          assert.ok(1, "Secure connection opened");
          socket.tlsStatus = 1;
        });

        socket.on("error", function(err){
          if (err) return done(err);
        });
      });

      var cmds = ["EHLO", "STARTTLS", "EHLO", "NOOP", "QUIT"];
      runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse){
        try {
          assert.equal(lastResponse.toString("utf-8"), "221 Bye\r\n");
        } catch (err) {
          return done(err);
        }
        server.end(function(){
          done();
        });

      });

    });
  });
});
