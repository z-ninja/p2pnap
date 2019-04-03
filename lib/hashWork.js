
const crypto = require("crypto");

function checkHashProof(content,nonce,strength,charCode){
strength = parseInt(strength) || 3;
if(isNaN(strength)){
strength = 3;
}
charCode = parseInt(charCode) || 48
if(isNaN(charCode)){
charCode = 48; 
}
var hash = crypto.createHash('sha1').update(content).update(nonce.toString()).digest('hex');
for(var i=0;i<strength;i++){
 if(hash.charCodeAt(i)!= charCode)
  return false;
}
return true;
}

function doHashProof(content,strength,nonce){
 nonce = nonce || -1;
 while(!checkHashProof(content,++nonce,strength)){}
 return nonce;
} 
module.exports = {
  checkHashProof:checkHashProof,
  doHashProof:doHashProof
};