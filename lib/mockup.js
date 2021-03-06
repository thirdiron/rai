"use strict";

var net = require("net"),
    crypto = require("crypto"),
    tlslib = require("tls");

// monkey patch net and tls to support nodejs 0.4
if(!net.connect && net.createConnection){
    net.connect = net.createConnection;
}

if(!tlslib.connect && tlslib.createConnection){
    tlslib.connect = tlslib.createConnection;
}

/**
 * @namespace Mockup module
 * @name mockup
 */
module.exports = runClientMockup;

/**
 * <p>Runs a batch of commands against a server</p>
 *
 * <pre>
 * var cmds = ["EHLO FOOBAR", "STARTTLS", "QUIT"];
 * runClientMockup(25, "mail.hot.ee", cmds, function(resp){
 *     console.log("Final:", resp.toString("utf-8").trim());
 * });
 * </pre>
 *
 * @memberOf mockup
 * @param {Number} port Port number
 * @param {String} host Hostname to connect to
 * @param {Array} commands Command list to be sent to server
 * @param {Function} callback Callback function to run on completion,
 *        has the last response from the server as a param
 * @param {Boolean} [debug] if set to true log all input/output
 */
function runClientMockup(port, host, commands, callback, debug){
    host = host || "localhost";
    port = port || 25;
    commands = Array.isArray(commands) ? commands : [];

    var command, ignore_data = false, responses = [], sslcontext, pair;

    var socket = net.connect(port, host);
    socket.on("connect", function(){
      socket.on("data", function(chunk){
        if(ignore_data){
          return;
        }

        if(debug){
          console.log("S: "+chunk.toString("utf-8").trim());
        }

        if(!commands.length){
          socket.end();
          if(typeof callback == "function"){
            responses.push(chunk);
            callback(chunk, responses);
          }
          return;
        }else{
          responses.push(chunk);
        }

        if(["STARTTLS", "STLS"].indexOf((command || "").trim().toUpperCase())>=0){
          ignore_data = true;
          if(debug){
              console.log("Initiated TLS connection");
          }
			    if (tlslib.createSecureContext) {
			    	sslcontext = tlslib.createSecureContext();
			    } else {
			    	sslcontext = crypto.createCredentials();
			    }
          const secureSocket = tlslib.connect({socket: socket});
          secureSocket.on('secureConnect', function() {

            if(debug){
                console.log("TLS connection secured");
            }
            command = commands.shift();
            if(debug){
                console.log("C: "+command);
            }
            secureSocket.write(command+"\r\n");

            secureSocket.on("data", function(chunk){
              if(debug){
                console.log("S: "+chunk.toString("utf-8").trim());
              }

              if(!commands.length){
                secureSocket.end();
                if(typeof callback == "function"){
                  responses.push(chunk);
                  callback(chunk, responses);
                }
                return;
              }else{
                responses.push(chunk);
              }
              command = commands.shift();
              secureSocket.write(command+"\r\n");
              if(debug){
                console.log("C: "+command);
              }
            });
          });
        }else{
          command = commands.shift();
          socket.write(command+"\r\n");
          if(debug){
              console.log("C: "+command);
          }
        }
      });
    });

}
