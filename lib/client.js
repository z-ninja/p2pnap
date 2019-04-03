const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const ed25519_1 = require("@stablelib/ed25519");
const moment = require('moment-timezone');
const net = require('net');
const granax = require("@deadcanaries/granax");
const socks = require("socks5-client");
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');
const sqlite3 = require("sqlite3").verbose();
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;

const replies = require('@deadcanaries/granax/lib/replies');
const old_getinfo = replies.GETINFO;
replies.GETINFO = (output)=>{
  if(output.length&&output[0] == "onions/current="){
   output[0] = output[0].split('=')[1];
   var ret = [];
   if(output[0].length)
     ret.push(output[0]);
    for(var i=1;i<output.length;i++){
      if(output[i].length>16){
	ret.push(output[i]);
      }
    }
    return ret;
  }
  return old_getinfo(output);
};

const {onion_service_id_for_public_key,
  onion_service_address_for_public_key,
  onion_public_key_from_expanded_key,
  onion_service_public_key_form_id,
  expand_onion_private_key,
  createNewServiceKey,
  checkHashProof,
  doHashProof
} = require("./util.js");

function getRandomPort(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function Client(options){
  options = options||{};
  var self = this;
  EventEmitter.call(self);
  options = Object.assign(
      {
	
        tor:null,
	socks:null,
	dataDir:null,
	service:null,
	channel:null,
	channel_port:null,
	channel_local_port:null
      },
      options
    );
    if(!options.channel){
     throw "channel is missing"; 
    }
    if(!options.channel_local_port){
      throw "channel_local_port is missing";
    }
    if(!options.channel_port){
      options.channel_port = 80;
    }
    var channel = crypto.createHash("sha256").update(options.channel).digest();
    var random_Port = getRandomPort(3000,60000);
    options.socks = options.socks || {};
  options.service = options.service || {};
   options.service = Object.assign(
	{
	port:9008,
	host:"127.0.0.1",
	nacl_pair:null,
	seed:null,
	port_mapping:[{"virtualPort":random_Port,"target":options.service.port||9008}]
	},options.service);
   options.service.port_mapping.push({"virtualPort":options.channel_port,"target":options.channel_local_port});
   options.socks = Object.assign(
	{
	port:0,
	host:null,
	},options.socks);
   if( !options.tor){
      if(!options.dataDir){
	throw "service dataDir is missing"; 
      }
    if(!fs.existsSync(options.dataDir)){
      fs.mkdir(options.dataDir, { recursive: true }, (err) => {
      if (err) throw err;
      });
    }
    }
    if(!options.service.nacl_pair){
     options.service.nacl_pair = nacl.box.keyPair();
    }
    if(!options.service.nacl_pair.publicKey||options.service.nacl_pair.publicKey.length!= 32){
     throw "invalid nacl_pair publicKey"; 
    }
    if(!options.service.nacl_pair.secretKey||options.service.nacl_pair.secretKey.length!= 32){
     throw "invalid nacl_pair secretKey"; 
    }
    
    if(!options.service.seed){
      options.service.seed = crypto.randomBytes(32);
    }
    if(options.service.seed.length != 32){
      throw "service expanded key length not valid"; 
    }
    options.service.pair = ed25519_1.generateKeyPairFromSeed(options.service.seed);
    options.service.expKey = expand_onion_private_key(options.service.pair.secretKey);
    var serviceId = onion_service_id_for_public_key(options.service.pair.publicKey);
    var servicePort = false;
    var server = net.createServer((sock)=>{
      if(tor_status != 2){
	sock.destroy();
	return;
      }
      var tm = setTimeout(()=>{
	if(!sock.destroyed){
	 sock.destroy(); 
	}
      },15000);
      
      
      sock.once("data",(data)=>{
	var length = data.length;
	   if(length<138){
	    sock.destroy();
	     return;
	   }
	   var command = data.readInt8(0);
	   switch(command){
	     case 1:{
	      var box = ExtractBox(data,1,true); 
	      if(box){
	      var query = nacl.box.open(box.box, box.nonce, box.key, options.service.nacl_pair.secretKey);
	      if(query){
		if(query.length>=59){
		  query= Buffer(query);
		  var offset = 0;
		  var secret_key_len = query.readInt8(offset++);
		if(secret_key_len == 24){
		  var secret_key = query.slice(offset,offset+secret_key_len);
		  offset += secret_key_len;
		   var secret_index = options.secrets.indexOf(secret_key.toString("hex"));
		  if(secret_index!=-1){
		    options.secrets.splice(secret_index,1);
		  var channel_len = query.readInt8(offset++);
		  if(channel_len == 32){
		    var channell = query.slice(offset,offset+channel_len);
		    if(channell.equals(channel)){
		    offset += channel_len;
		    var entry_len = query.readInt8(offset++);
		    self.emit("discovery-begin",secret_key,entry_len);
		    if(entry_len>0){
		     if(length>=entry_len*40+offset){
		       for(var i=0;i<entry_len;i++){
			 var key = query.slice(offset,offset+32);
			 offset+=32;
			 var lts = query.readUInt32LE(offset);
			 offset+=4;
			 var port = query.readUInt16LE(offset);
			 offset+=4;
			 self.emit("address",key,port,lts);
		       }
	}else {
	  console.log("length>=entry_len*40+offset");
	}
	}
	self.emit("discovery-done",secret_key,entry_len);
		  }else console.log("channel name not equeals");
	}else console.log("channel len not valid");
	}else console.log("unknown secret");
	}else console.log("secret key len not valid",secret_key_len);
	}else console.log("quary less the n 59 bytes");
	}else console.log("query not decrypted");
	}else console.log("box not extracted");
	}
	     break;
	     default:{
	       
	     }
	   }
	   sock.destroy();
      });
      sock.once("close",()=>{
	
      });
      
    });
    server.listen(options.service.port, options.service.host);
  var _tor_ready = (data)=>{
      tor_status =2;
      serviceId = data.serviceId;
      servicePort = data.servicePort;
      self.removeListener("tor-error",_tor_error);
      self.scan = scan.bind(null,self,options);
      self.emit("ready");
  };
  var _tor_error = (error)=>{
    tor_status =1;
    self.removeListener("tor-ready",_tor_ready);
    self.emit("error",error);
  };
  
   
  
  
    self.once("tor-ready",_tor_ready);
    self.once("tor-error",_tor_error);
   var tor_info = (err, result) => {
      if(err){
	self.emit("tor-error",err);
      }else {
	var a = result.split('"').join('').split(':');
	if(!options.socks.port){
	options.socks.port = parseInt(a[1]);
	}
	if(!options.socks.host){
	options.socks.host = a[0];
	}
	options.tor.getInfo('onions/current', (err,data,b,c)=>{
	  var onion_found = false;
	  if(data.length){
	    for(var i in data){
	     if(data[i] == serviceId){
	      onion_found = true;
	      break;
	     }
	    }
	  }
	  if(!onion_found){
	   options.tor.createHiddenService(options.service.port_mapping,
			 {
			 "keyType":"ED25519-V3",
			 "keyBlob":options.service.expKey.toString("base64")
			},tor_service);
	  }else {
	var _servicePort = 0;
      for(var i in options.service.port_mapping){
	if(options.service.port_mapping[i].target = options.service.port){
	  _servicePort = options.service.port_mapping[i].virtualPort;
	  break;
	}
      }
	   self.emit("tor-ready",{"serviceId":serviceId,servicePort:_servicePort});
	  }
	});
      }};
    var tor_service = (err, data) => {
    if (err) {
      self.emit("tor-error",err);
    } else {
      var _servicePort = 0;
      for(var i in options.service.port_mapping){
	if(options.service.port_mapping[i].target = options.service.port){
	  _servicePort = options.service.port_mapping[i].virtualPort;
	  break;
	}
      }
      self.emit("tor-ready",{serviceId:data.serviceId,servicePort:_servicePort});
    }
  };
  if(!options.tor){
    var tor_error = (err)=>{
      self.emit("tor-error",err);
      options.tor.removeListener("ready",tor_ready)
    };
    var tor_ready = (err)=>{
      if(err){
      self.emit("tor-error",err);
      }else {
	options.tor.getInfo('net/listeners/socks', tor_info);
      } 
    };
    var TorDataDirectory = path.join(options.dataDir,'tor-data');
    options.tor = granax({ authOnConnect: true },
    {
      DataDirectory: TorDataDirectory
    });
    options.tor.once("ready",tor_ready);
    options.tor.once("error",tor_error);
  }else {
    options.tor.getInfo('net/listeners/socks', tor_info);    
  }
  self.tor = ()=>{
    return options.tor;
  };
  self.address = ()=>{
    return serviceId+".onion";
  };
  self.port = ()=>{
    return servicePort;
  };
  self.channel = ()=>{
   return channel; 
  };
  self.serviceKeys = ()=>{
    return options.service.pair;
  };
  self.open = ( addr, port)=>{
      return socks.createConnection( {"hostname":addr,"port":port||80,"socksHost":options.socks.host,"socksPort":options.socks.port});
  };
}
inherits(Client, EventEmitter);

function scan(client,options,addr,port,cb){
  options.hosts = options.hosts||{};
  options.secrets = options.secrets || [];
  if(typeof port == "function"){
   cb = port;
   port = undefined;
  }
  if(typeof cb != "function"){
   cb = (err,data)=>{
     if(err)
       throw err;
    }; 
  }
  var now = moment().unix();
  if(typeof options.hosts[addr] != "undefined"){
     
  if(options.hosts[addr].lts+60>now){
    setTimeout(()=>{
      client.scan(addr,port,cb);
    },(options.hosts[addr].lts+60-now)*1000);
    return;
  }
  }else {
    options.hosts[addr] = {"port":port||80,"lts":now};
  }
  
 // console.log("options",options);
  
  var sock = socks.createConnection( {"hostname":addr,"port":port||80,"socksHost":options.socks.host,"socksPort":options.socks.port});
  var ctm = setTimeout(()=>{
     if(!sock.socket.destroyed){
       sock.destroy();
     }
    },40000);
  sock.once("connect",()=>{
    clearTimeout(ctm);
   var msg = createBasicPacket(2,options);
    sock.write(msg);
  });
  sock.once("error",(err)=>{
      console.error("socks client error",err.message);
  });
  sock.once("data",(data)=>{
    var length = data.length;
  if(length<2){
   console.log("length too small",length);
   cb("wrong packet size");
   sock.destroy();
   return;
  }
  
  var command = data.readInt8(0);
  switch(command){
    case 2:{
      var box = ExtractBox(data,1,true);
      if(!box){
	cb("Invalid box");
	sock.destroy();
	return;
      }
      var work = extractHashWork(box,options);
      if(!work){
	cb("invalid work extraction");
	sock.destroy();
	return;
      }
      var hashNonce = doHashProof(work.hash,work.level);
      do_query(client,addr,port,client.port(),hashNonce,work,box,options,cb);
    }
    break;
    case 4:{
      if(length == 5){
      var tm = data.readUInt32LE(1);
      console.log("waiting timeout",tm,"seconds");
      setTimeout(()=>{
      client.scan(addr,port,cb);
      },(tm*1000)+500);
      }else {
	cb("invalid timeout packet");
      }
    }
    break;
    default:
   sock.destroy();
   return;
  }
  });
  sock.once("close",()=>{
  });
}
function do_query(client,addr,port,servicePort,hashNonce,work,_box,options,cb){
var sock = socks.createConnection( {"hostname":addr,"port":port||80,"socksHost":options.socks.host,"socksPort":options.socks.port});
  var ctm = setTimeout(()=>{
     if(!sock.socket.destroyed){
       sock.destroy();
     }
    },40000);
  sock.once("connect",()=>{
    clearTimeout(ctm);
   var msg = createRequestPacket(servicePort,work.time,hashNonce,work.level,_box.key,options.channel,options);
    sock.write(msg);
  });
  sock.once("error",(err)=>{
      console.error("socks client error",err.message);
      cb(err);
  });
  sock.once("data",(data)=>{
    var length = data.length;
  if(length<2){
   console.log("length too small",length);
   cb("wrong packet size");
   sock.destroy();
   return;
  }
  var command = data.readInt8(0);
  switch(command){
    case 1:{
      var box = ExtractBox(data,1,false);
      if(!box){
	cb("Invalid box");
	sock.destroy();
	return;
      }
      var secret = nacl.box.open(box.box, box.nonce, _box.key, options.service.nacl_pair.secretKey);
	  if(secret){
	    options.secrets.push(Buffer(secret).toString("hex"));
	     cb(null);
	     setTimeout(()=>{
	       var index = options.secrets.indexOf(Buffer(secret).toString("hex"));
	       if(index != -1){
		options.secrets.splice(index,1);
		console.log("some glich happen in tor network"); 
	       }
	    },150000);
	  }else {
	   cb("unable to open secret box"); 
	  }
	 
    }
    break;
    case 3:{
      if(length == 5){
      console.log("command 3 bre");
      client.scan(addr,port);
      }else {
	cb("invalid offset time packet");
      }
    }
    break;
    case 4:{
      if(length == 5){
      var tm = data.readUInt32LE(1);
      console.log("waiting timeout",tm,"seconds");
      setTimeout(()=>{
      client.scan(addr,port,cb);
      },(tm*1000)+500);
      }else {
	cb("invalid timeout packet");
      }
    }
    break;
    default:
   sock.destroy();
   return;
  }
  });
  sock.once("close",()=>{
  });
}
function createRequestPacket(servicePort,hashTime,hashNonce,hashLevel,serviceKey,channel,options){
var packet = createBasicPacket(1,options);
var hashProof = new Buffer(9+33+4+4);
hashProof.writeUInt32LE(hashTime,0);
hashProof.writeUInt32LE(hashNonce,4);
hashProof.writeInt8(hashLevel,8);
hashProof.writeInt8(32,9);
crypto.createHash("sha256").update(channel).digest().copy(hashProof,10,0,32);
hashProof.writeUInt16LE(servicePort,42);
hashProof.writeUInt16LE(options.channel_port,46);
var nonce = crypto.randomBytes(24);

var box = nacl.box(
	  hashProof,
	  nonce,
	  serviceKey,
	  options.service.nacl_pair.secretKey);
box = packBox(box,nonce);
var msg = new  Buffer(box.length+packet.length);
packet.copy(msg,0,0,packet.length);
box.copy(msg,packet.length,0,box.length);
return msg;
}
function extractHashWork(data,options){
  var hashdata = nacl.box.open(data.box, data.nonce, data.key, options.service.nacl_pair.secretKey);
    if(!hashdata||hashdata.length!=38){
     return null; 
    }
    hashdata = Buffer(hashdata);
    var hash_len = hashdata.readInt8(0);
      if(hash_len != 32){
	return null;
      }
      var hash = hashdata.slice(1,33);
      var time = hashdata.readUInt32LE(33);
      var level = hashdata.readInt8(37);
      return {hash:hash,time:time,level:level};
}
function packBox(box,nonce,publicKey){
var msg = new Buffer(4+box.length+1+24+((publicKey)?publicKey.length+1:0));
var offset = 0;
msg.writeInt32LE(box.length,offset);
offset+= 4;
Buffer(box).copy(msg,offset,0,box.length);
offset += box.length;
msg.writeInt8(nonce.length,offset++);
nonce.copy(msg,offset,0,24);
offset += 24;
if(publicKey){
msg.writeInt8(publicKey.length,offset++); 
Buffer(publicKey).copy(msg,offset,0,publicKey.length);
}

return msg;
}
function ExtractBox(data,offset,extractKey){
  var length = data.length;
  var box_len = data.readInt32LE(offset);
  offset += 4;
   if(length<offset+box_len){
     console.log("offset box len");
    return false; 
   }
   var box = data.slice(offset,offset+box_len);
   offset += box_len;
   var nonce_len  = data.readInt8(offset++);
   if(length<offset+nonce_len){
          console.log("offset nonce len");

    return false; 
   }
   var nonce = data.slice(offset,offset+nonce_len);
   offset += nonce_len;
   if(extractKey){
     if(length<offset+1){
            console.log("offset extractKey len");

       return false;
     }
    var key_len = data.readInt8(offset++);
    if(key_len != 32||length<offset+key_len){
           console.log("offset KEY len",key_len,length,offset+key_len);

     return false; 
    }
     var key = data.slice(offset,offset+key_len);
     return {key:key,nonce:nonce,box:box};
   }
   return {nonce:nonce,box:box};
}
function createBasicPacket(command,options){
  
      var msg = new Buffer(1+1+32+1+64+1+10+1+32);
      var offset = 0;
      msg.writeInt8(command,offset++);
      msg.writeInt8(options.service.pair.publicKey.length,offset++);
      Buffer(options.service.pair.publicKey).copy(msg, offset, 0,32);
      offset +=32;
      var sig_time = Buffer.from(moment().unix().toString(),"utf8");
      var sig_msg = new Buffer(42);
      sig_time.copy(sig_msg,0,0,10);
      Buffer(options.service.nacl_pair.publicKey).copy(sig_msg,10,0,32);
      var sig = ed25519_1.sign(options.service.pair.secretKey,sig_msg.slice(0,42));
      msg.writeInt8(sig.length,offset++);
      Buffer(sig).copy(msg,offset,0,64);
      offset+= 64;
      msg.writeInt8(sig_time.length,offset++);
      sig_time.copy(msg,offset,0,10);
      offset+=10;
      msg.writeInt8(options.service.nacl_pair.publicKey.length,offset++);
      Buffer(options.service.nacl_pair.publicKey).copy(msg,offset,0,32);
      return msg;
}
module.exports = (options)=>{
  return new Client(options);
};