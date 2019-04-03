const path = require("path");
const p2pnapClient = require("../").Client; 
const {onion_service_address_for_public_key} = require("../lib/util.js");
const net = require("net");
module.exports = (addr,port,tor)=>{
 
  createClient(addr,port,tor,8001);
  createClient(addr,port,tor,8002);

};

function createClient(addr,port,tor,channel_local_port){

var p2pnapC = p2pnapClient({
  dataDir:path.join(__dirname,"client-data-"+channel_local_port),
  tor:tor,
  channel:"test-channel-1",
  channel_port:80,
  channel_local_port:channel_local_port,
  service:{
    port:65536 -channel_local_port
  }
});
var server = net.createServer((sock)=>{
  console.log("server connection",sock.remoteAddress);
  sock.once("data",(data)=>{
    console.log("server received",data.toString());
    sock.write("You said: '"+data.toString()+"'");
  });
  sock.once("error",()=>{
    
  });
  sock.once("close",()=>{
    
  });
});
server.listen(channel_local_port,"localhost");
p2pnapC.on("address",(addr,port,lts)=>{
  console.log("new address",addr.toString("hex"),port,lts);
 var peer = p2pnapC.open(onion_service_address_for_public_key(addr),port);
 peer.once("connect",()=>{
   console.log("peer connected to server success");
   peer.write("hello");
 });
 peer.once("data",(data)=>{
   console.log(data.toString());
   console.log("peer test success");
   process.exit(0);
 });
 peer.once("error",(err)=>{
   console.log("peer connection error",err);
 });
 peer.once("close",()=>{
   console.log("peer connectio close");
 });
});
p2pnapC.on("discovery-begin",(secret,len)=>{
  console.log("secret discovery begin",secret.toString("hex"),len);
});
p2pnapC.on("discovery-done",(secret,len)=>{
  console.log("secret discovery done",secret.toString("hex"),len);
  console.log("discovery test success");
});
p2pnapC.once("ready",()=>{
  
console.log("client ready",p2pnapC.address(),p2pnapC.port()); 
p2pnapC.scan(addr,port,(err)=>{
  console.log("scan finished",err);
});
});
p2pnapC.once("error",(error)=>{
  console.error("service error",error);
  process.exit(1);
});
}
