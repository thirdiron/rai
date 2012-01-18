# RAI - Request-Answer-Interface

**rai** is a node.js module to easily generate text based command line servers.
When a client sends something to the server, the first word of the line is
treated as a command and the rest of the line as binary payload.

In addition to line based commands, there's also a data mode, to transmit
everygting received. And there's also an option to switch to TLS mode for
secure connections.

This way it is trivial to create SMTP, POP3 or similar servers.

## Documentation

Autogenerated docs can be seen [here](http://node.ee/raidoc/).

## Installation

    npm install rai
    
## Usage

### Simple server

    var RAIServer = require("rai").RAIServer;
    
    // create a RAIServer on port 1234
    var server = new RAIServer();
    server.listen(1234);
    
    // Start listening for client connections
    server.on("connection", function(client){
    
        // Greet the client
        client.send("Hello!");
        
        // Wait for a command
        client.on("command", function(command, payload){
        
            if(command == "STATUS"){
                client.send("Status is OK!");
            }else if(command == "QUIT"){
                client.send("Goodbye");
                client.end();
            }else{
                client.send("Unknown command");
            }
        
        });
    
    });

Server only emits `connection` events, while the client objects emit `timeout`,
`error` and `end` in addition to data related events.

### Closing server

Server can be closed with `server.end([callback])` where callback is run when
the server is finally closed.

### Sending data

Data can be sent with `client.send(data)` where `data` is either a String or
a Buffer. `"\r\n"` is automatically appended to the data.

    client.send("Greetings!");

### Forcing connection close

Connections can be ended with `client.end()`

    if(command == "QUIT"){
        client.send("Good bye!");
        client.end();
    }

### TLS mode

TLS can be switched on with `client.startTLS([credentials])` and the status can
be listened with `'tls'` (emitted when secure connection is established)

`credentials` is an object with strings of pem encoded `key`, `cert` and optionally an
array `ca`. If `credentials` is not supplied, an autogenerated value is used.

    if(command == "STARTTLS"){
        client.startTLS();
    }
    
    client.on("tls", function(){
        console.log("Switched to secure connection");
    });

### Data mode

Data mode can be turned on with `client.startDataMode([endSequence])` and incoming
chunks can be received with `'data'`. The end of data mode can be detected by
`'ready'`.

`endSequence` is a RegExp object or a String for matching the end of the data
stream. By default it's `"\r\n.\r\n"` which is suitable for SMTP and POP3.

    if(command == "DATA"){
        client.send("End data with <CR><LF>.<CR><LF>");
        client.startDataMode();
    }

    client.on("data", function(chunk){
        console.log("Data from client:", chunk);
    });
    
    client.on("ready", function(){
        client.send("Data received");
    });

## License

**MIT**