const path = require("path");
const p2pnapServer = require("../").Server; 

module.exports = (cb)=>{
var p2pnapS = p2pnapServer({dataDir:path.join(__dirname,"server-data")});
p2pnapS.once("ready",()=>{
console.log("server ready",p2pnapS.address(),p2pnapS.port()); 
  cb(p2pnapS);
});
p2pnapS.once("error",(error)=>{
  console.error("service error",error);
  process.exit(1);
});
};