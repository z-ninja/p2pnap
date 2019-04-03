# p2pnap
Peer-to-Peer Network Access Point

This project allows you to create Network Access Point server and use client to connect to the server to discover other peers in network interesting in a same channel name easily.
Whole communication is done via tor network.


Server Example
```javascript
const path = require("path");
const p2pnapServer = require("p2pnap").Server; 
var p2pnapS = p2pnapServer({dataDir:path.join(__dirname,"server-data")});
p2pnapS.once("ready",()=>{
console.log("server ready",p2pnapS.address(),p2pnapS.port()); 
});
p2pnapS.once("error",(error)=>{
  console.error("server error",error);
  process.exit(1);
});
```

Client Example
```javascript
const path = require("path");
const p2pnapClient = require("p2pnap").Client; 
const {onion_service_address_for_public_key} = require("p2pnap/lib/util.js");
const net = require("net");

var channel_local_port = 8001;
var service_address = "b248bb9a1202b245...onion"; // Network access point server address
var sevice_port = 80; // Network access point server port
/// create client
 var p2pnapC = p2pnapClient({
  dataDir:path.join(__dirname,"client-data"),
  channel:"test-channel-1",
  channel_port:80,
  channel_local_port:channel_local_port
}); 
p2pnapC.on("address",(addr,port,lts)=>{
  var peer = p2pnapC.open(onion_service_address_for_public_key(addr),port);
 peer.once("connect",()=>{
   console.log("outgoing peer connected to peer success");
   peer.write("hello");
   /// add peer to list in you application
 });
 peer.on("data",(data)=>{
   console.log(data.toString());
 });
 peer.once("error",(err)=>{
   console.log("peer connection error",err);
 });
 peer.once("close",()=>{
   console.log("peer connectio close");
 });
});
p2pnapC.once("ready",()=>{
console.log("client ready",p2pnapC.address(),p2pnapC.port()); 
p2pnapC.scan(service_address,sevice_port,(err)=>{
  console.log("scan finished",err);
});

});
p2pnapC.once("error",(error)=>{
  console.error("Client error",error);
  process.exit(1);
});
/* create server for incomming connection for channel on channel local port so we can accept 
incomming connections form peers for our channel
*/
var server = net.createServer((sock)=>{
  console.log("incomming peer connection",sock.remoteAddress);
  sock.on("data",(data)=>{
    console.log("received",data.toString(),"from peer");
    sock.write("You said: '"+data.toString()+"'");
  });
  sock.once("error",()=>{
  });
  sock.once("close",()=>{
  });
});
server.listen(channel_local_port,"localhost");
```
