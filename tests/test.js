const clientTest = require("./client-test.js"); 
const serverTest = require("./server-test.js"); 


serverTest((server)=>{
clientTest(server.address(),server.port(),server.tor());
});