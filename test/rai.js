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
    var server = new RAIServer();
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

      var client = netlib.connect(PORT_NUMBER, function(){
        var sslcontext = crypto.createCredentials();
        var pair = tlslib.createSecurePair(sslcontext, false);

        pair.encrypted.pipe(client);
        client.pipe(pair.encrypted);
        pair.fd = client.fd;

        pair.on("secure", function(){
          pair.cleartext.on("data", function(chunk){
            try {
              assert.equal(chunk.toString(), "TEST\r\n");
            } catch (err) {
              return done(err);
            }
            pair.cleartext.end();
          });
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
            var pair = tlslib.createSecurePair(sslcontext, false);

            pair.encrypted.pipe(client);
            client.pipe(pair.encrypted);
            pair.fd = client.fd;

            pair.on("secure", function(){
              pair.cleartext.write("OK\r\n");
              pair.cleartext.end();
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
//
//exports["Client commands"] = {
//    "Receive Simple Command":  function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//            
//            server.on("connect", function(socket){
//                
//                socket.on("command", function(command, payload){
//                    test.equal(command, "STATUS");
//                    test.equal(payload.toString(), "");
//                    socket.end();
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                client.write("STATUS\r\n");
//            });
//
//        });
//    },
//    "Receive Command with payload":  function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//            
//            server.on("connect", function(socket){
//                
//                socket.on("command", function(command, payload){
//                    test.equal(command, "MAIL");
//                    test.equal(payload.toString(), "TO:");
//                    socket.end();
//                    
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                client.write("MAIL TO:\r\n");
//            });
//
//        });
//    }
//};
//
//exports["Data mode"] = {
//    "DATA mode": function(test){
//        var server = new RAIServer(),
//            datapayload = "tere\r\nvana kere";
//        server.listen(PORT_NUMBER, function(err){
//            
//            server.on("connect", function(socket){
//                
//                socket.startDataMode();
//
//                test.expect(2);
//
//                socket.on("data", function(chunk){
//                    test.equal(datapayload, chunk.toString());
//                });
//                
//                socket.on("ready", function(){
//                    test.ok(1,"Data ready");
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                client.write(datapayload+"\r\n.\r\n");
//                client.end();
//            });
//
//        });
//    },
//    "Small chunks DATA mode": function(test){
//        var server = new RAIServer(),
//            datapayload = "tere\r\nvana kere õäöü\r\n.\r",
//            databytes = [],
//            fullpayload = datapayload+"\r\n.\r\n";
//        server.listen(PORT_NUMBER, function(err){
//            
//            server.on("connect", function(socket){
//                
//                socket.startDataMode();
//
//                test.expect(1);
//
//                socket.on("data", function(chunk){
//                    databytes = databytes.concat(Array.prototype.slice.call(chunk));
//                });
//                
//                socket.on("ready", function(){
//                    test.equal(new Buffer(databytes).toString("utf-8"), datapayload);
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//                
//                for(var i=0, len = fullpayload.length; i<len; i++){
//                    socket._onReceiveData(new Buffer(fullpayload.charAt(i), "utf-8").toString("binary"));
//                }
//                
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                client.end();
//            });
//
//        });
//    }
//};
//
//exports["Pipelining support"] = {
//    "Pipelining": function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//            
//            test.expect(8);
//            
//            server.on("connect", function(socket){
//                
//                socket.on("command", function(command, payload){
//                    if(command == "STATUS"){
//                        test.ok(1, "Status received");
//                    }else if(command=="DATA"){
//                        test.ok(1, "data command received");
//                        socket.startDataMode();
//                    }else if(command=="END"){
//                        test.ok(1, "all received");
//                    }else{
//                        test.ok(0, "Unexpected command: "+command);
//                    }
//                });
//                
//                socket.on("data", function(chunk){
//                    test.equal(chunk.toString(), "TE\r\nST");
//                });
//                
//                socket.on("ready", function(){
//                    test.ok(1, "Data mode ended");
//                });
//                
//                socket.on("end", function(){
//                    test.ok(1, "All ready");
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                client.write("STATUS\r\nSTATUS\r\nSTATUS\r\nDATA\r\nTE\r\nST\r\n.\r\nEND\r\n");
//                client.end();
//            });
//
//        });
//    }
//};
//
//exports["Timeout tests"] = {
//    "Timeout": function(test){
//        var server = new RAIServer({timeout: 300, disconnectOnTimeout: true});
//        test.expect(3);
//        server.listen(PORT_NUMBER, function(err){
//            
//            server.on("connect", function(socket){
//                test.ok(socket, "Client connected");
//                
//                socket.on("timeout", function(){
//                    test.ok(1, "Connection closed");
//                    
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                test.ok(1, "Connected to server");
//            });
//
//        });
//    },
//    "Timeout with TLS":  function(test){
//        var server = new RAIServer({timeout: 300, disconnectOnTimeout: true});
//        server.listen(PORT_NUMBER, function(err){
//            
//            test.expect(3);
//            
//            server.on("connect", function(socket){
//                
//                socket.startTLS();
//                socket.on("tls", function(){
//                    test.ok(1, "Secure connection opened");
//                    socket.send("TEST");
//                });
//                
//                socket.on("timeout", function(){
//                    test.ok(1, "Timeout occurred");
//                    server.end(function(){
//                        test.done();
//                    });
//                });
//                
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//            
//            var client = netlib.connect(PORT_NUMBER, function(){
//                var sslcontext = crypto.createCredentials();
//                var pair = tlslib.createSecurePair(sslcontext, false);
//                
//                pair.encrypted.pipe(client);
//                client.pipe(pair.encrypted);
//                pair.fd = client.fd;
//                
//                pair.on("secure", function(){
//                    test.ok(1, "secure connection");
//                });
//            });
//
//        });
//    } 
//};
//
//exports["Client Mockup"] = {
//    "All command": function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//            server.on("connect", function(socket){
//                socket.send("220 Welcome");
//                socket.on("command", function(command, payload){
//                    switch(command) {
//                        case "HELO": socket.send("250 HI"); break;
//                        case "NOOP": socket.send("250 OK"); break;
//                        case "QUIT": socket.send("221 Bye"); socket.end(); break;
//                        default: socket.send("500");
//                    }
//                });
//
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//
//            var cmds = ["HELO", "NOOP", "QUIT"];
//            runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse, allResponses){
//                allResponses = allResponses.map(function(value) { return value.toString("utf-8"); });
//                test.deepEqual(allResponses, [ "220 Welcome\r\n", "250 HI\r\n", "250 OK\r\n", "221 Bye\r\n" ]);
//                server.end(function(){
//                    test.done();
//                });
//
//            });
//
//        });
//    },
//    "Last commands":  function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//            server.on("connect", function(socket){
//                socket.send("220 HI");
//                socket.on("command", function(command, payload){
//                    switch(command) {
//                        case "HELO": socket.send("250 HI"); break;
//                        case "NOOP": socket.send("250 OK"); break;
//                        case "QUIT": socket.send("221 Bye"); socket.end(); break;
//                        default: socket.send("500");
//                    }
//                });
//
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//
//            var cmds = ["HELO", "NOOP", "QUIT"];
//            runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse){
//                test.equal(lastResponse.toString("utf-8"), "221 Bye\r\n");
//                server.end(function(){
//                    test.done();
//                });
//
//            });
//
//        });
//    },
//    "All command(STARTTLS)": function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//
//            test.expect(2);
//
//            server.on("connect", function(socket){
//                socket.tlsStatus = 0;
//                socket.send("220 Welcome");
//                socket.on("command", function(command, payload){
//                    switch(command){
//                        case "EHLO":
//                            if(socket.tlsStatus===0){
//                                socket.send("250-HI\r\n250 STARTTLS");
//                            }else{
//                                socket.send("250 HI");
//                            }
//                            break;
//                        case "NOOP": socket.send("250 OK"); break;
//                        case "QUIT": socket.send("221 Bye"); socket.end(); break;
//                        case "STARTTLS": socket.startTLS(); socket.send("220 Go ahead"); break;
//                        default: socket.send("500");
//                    }
//                });
//
//                socket.on("tls", function(){
//                    test.ok(1, "Secure connection opened");
//                    socket.tlsStatus = 1;
//                });
//
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//
//            var cmds = ["EHLO", "STARTTLS", "EHLO", "NOOP", "QUIT"];
//            runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse, allResponses){
//                allResponses = allResponses.map(function(value) { return value.toString("utf-8"); });
//                test.deepEqual(allResponses, ["220 Welcome\r\n", "250-HI\r\n250 STARTTLS\r\n", "220 Go ahead\r\n",
//                                              "250 HI\r\n", "250 OK\r\n", "221 Bye\r\n" ]);
//                server.end(function(){
//                    test.done();
//                });
//
//            });
//
//        });
//    },
//    "Last commands(STARTTLS)":  function(test){
//        var server = new RAIServer();
//        server.listen(PORT_NUMBER, function(err){
//
//            test.expect(2);
//
//            server.on("connect", function(socket){
//                socket.tlsStatus = 0;
//                socket.send("220 Welcome");
//                socket.on("command", function(command, payload){
//                    switch(command){
//                        case "EHLO":
//                            if(socket.tlsStatus===0){
//                                socket.send("250-HI\r\n250 STARTTLS");
//                            }else{
//                                socket.send("250 HI");
//                            }
//                            break;
//                        case "NOOP": socket.send("250 OK"); break;
//                        case "QUIT": socket.send("221 Bye"); socket.end(); break;
//                        case "STARTTLS": socket.startTLS(); socket.send("220 Go ahead"); break;
//                        default: socket.send("500");
//                    }
//                });
//
//                socket.on("tls", function(){
//                    test.ok(1, "Secure connection opened");
//                    socket.tlsStatus = 1;
//                });
//
//                socket.on("error", function(err){
//                    test.isError(err);
//                });
//            });
//
//            var cmds = ["EHLO", "STARTTLS", "EHLO", "NOOP", "QUIT"];
//            runClientMockup(PORT_NUMBER, "localhost", cmds, function(lastResponse){
//                test.equal(lastResponse.toString("utf-8"), "221 Bye\r\n");
//                server.end(function(){
//                    test.done();
//                });
//
//            });
//
//        });
//    }
//};
