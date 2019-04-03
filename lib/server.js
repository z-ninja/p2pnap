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
const old_getConf = replies.GETCONF;

replies.GETCONF = (output)=>{
  return old_getConf(output);
}
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
  checkHashProof
} = require("./util.js");

function Server(options){
  options = options||{};
  var self = this;
  EventEmitter.call(self);
  options = Object.assign(
      {
	hashLevel:4,
	hashSalt:null,
	maxRows:40,
        tor:null,
	socks:null,
	db:null,
	dataDir:null,
	service:null,
      },
      options
    );
  options.socks = options.socks || {};
  options.service = options.service || {};
  options.maxRows = parseInt(options.maxRows);
  if(isNaN(options.maxRows)){
   options.maxRows = 40; 
  }
  options.service = Object.assign(
	{
	port:9007,
	host:"127.0.0.1",
	nacl_pair:null,
	expKey:null,
	port_mapping:[{"virtualPort":80,"target":options.service.port||9007}]
	},options.service);
  
  options.socks = Object.assign(
	{
	port:0,
	host:null,
	},options.socks);
  
    if(!options.db || !options.tor){
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
    
    if(!options.service.expKey){
      options.service.expKey = createNewServiceKey();
    }
    if(options.service.expKey.length != 64){
      throw "service expanded key length not valid"; 
    }
    var database_status = 0;
    var tor_status = 0;
      var serviceId = onion_service_id_for_public_key(onion_public_key_from_expanded_key(options.service.expKey));;
    var servicePort = false;
    if(!options.hashSalt)
    options.hashSalt = crypto.randomBytes(24);
    var server = net.createServer((sock)=>{
      if(database_status == 2 && tor_status == 2){
	onConnection(
	  options.socks.port,options.socks.host,options.service.nacl_pair,options.db,
	  options.hashSalt,options.hashLevel,options.maxRows,sock);
      }
    });
    server.listen(options.service.port, options.service.host);
  var database_ready = ()=>{
     database_status = 2;
     self.removeListener("database-error",database_error);
     if(tor_status == 2){
      self.emit("ready");
     }
  };
  var _tor_ready = (data)=>{
      tor_status =2;
      serviceId = data.serviceId;
      servicePort = data.servicePort;
      self.removeListener("tor-error",_tor_error); 
      if(database_status == 2){
      self.emit("ready");
      }
      /*
      options.tor.getConfig("HiddenServiceOptions",(err,data)=>{
	console.log("HiddenServiceOptions",err,data);
      });*/
  };
  var database_error = (error)=>{
     database_status = 1;
     self.removeListener("database-ready",database_ready);
     self.emit("error",error);
  }
  var _tor_error = (error)=>{
    tor_status =1;
    self.removeListener("tor-ready",_tor_ready);
    self.emit("error",error);
  };
  
   self.once("database-ready",database_ready);
   self.once("database-error",database_error);
  if(!options.db){
    var db_file = path.join(options.dataDir,"db.sqlite3");
    options.db = new sqlite3.Database(db_file,createTable.bind(null,self,options));
  }else {
   createTable(self,options); 
  }
  
  
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
  self.db = ()=>{
    return options.db;
  };
  self.address = ()=>{
    return serviceId+".onion";
  };
  self.port = ()=>{
    return servicePort;
  };
  
  
}
inherits(Server, EventEmitter);

function createTable(server,options,error) {
      if(error){
	server.emit("database-error",error);
      }else {
    options.db.run("CREATE TABLE IF NOT EXISTS networks_channels_table (id INTEGER PRIMARY KEY,\
    pk blob, lts INTEGER,`port` INTEGER,`channel` blob )", (error)=>{
      if(error){
options.db.close();
server.emit("database-error",error);
      }else {
server.emit("database-ready");	
      }
    });
      }
}

function onConnection(sockPort,sockHost,servicePair,db,hashSalt,hashLevel,maxRows,sock){
 var sock_tm = setTimeout(function(){
      if(!sock.destroyed){
      sock.destroy();
      }
    },10000); 
  sock.once('data',(data)=>{
    var length = data.length;
        if(length < 1){
	  sock.destroy();
	  return;
	}
    var request = parseRequest(data);
    if(!request){
     sock.destroy();
     return;
    }
    switch(request.command){
      case 1:{
	var box = openBox(data,request.offset,request.nacl_key,servicePair.secretKey);
	var work = validate_box_work(box,hashSalt);
	if(!work){
	 sock.destroy(); 
	 return;
	}
	clearTimeout(sock_tm);
	shereSecret(sockPort,sockHost,servicePair,db,request,work,maxRows,sock);
      }
      break;
      case 2:{
	giveHashWork(servicePair,db,request,hashSalt,hashLevel,sock);
      }
      break;
      default:{
	sock.destroy();
	return;
      }
    }
    
  });
  sock.on('close', (data)=>{});
  
}
function giveHashWork(servicePair,db,request,hashSalt,hashLevel,sock){
   var param = ["select * from  networks_channels_table where pk=? order by lts desc limit 1",request.publicKey];
   var stmt = db.prepare.apply(db,param);  
    stmt.on("error",(e)=>{
      console.error("database error stmt",e);
      sock.destroy();
      stmt.finalize();
  });
    stmt.get((err,row)=>{
   stmt.finalize();
   if(err){
    console.error("stmp get error",err);
    sock.destroy();
   }else {
     var level = hashLevel;
     var now = moment().unix();
     if(!row){
       level+=1;  
     }else {
       var lts =  parseInt(row.lts)*10000;
       if(lts+60>now){
	var msg = new Buffer(5);
	msg.writeInt8(4,0);
	msg.writeUInt32LE(lts+60-now,1);
	sock.write(msg);
	sock.destroy();
	return;
      }
     }
   var hashmsg = new Buffer(1+32+4+1);
   var nonce = crypto.randomBytes(24);
   var hash = crypto.createHash('sha256').update([hashSalt,now,level,""].join(":")).digest();
   var offset = 0;
   hashmsg.writeInt8(32,offset++);
   hash.copy(hashmsg,offset,0,32);
   offset += 32;
   hashmsg.writeUInt32LE(now,offset);
   offset += 4;   
   hashmsg.writeInt8(level,offset);
  var box = nacl.box(
  hashmsg,
  nonce,
  request.nacl_key,
  servicePair.secretKey
  );
  if(!sock.destroyed){
   sock.write(packBoxPacket(2,box,nonce,servicePair.publicKey));	 
   sock.destroy();
  }
   }
    });
}
function shereSecret(sockPort,sockHost,servicePair,db,request,work,maxRows,sock){
 var param = ["select * from  networks_channels_table where pk=? and channel=? limit 1",request.publicKey,work.channel];
   var stmt = db.prepare.apply(db,param); 
  stmt.on("error",(e)=>{
     console.error("database error stmt",e);
     sock.destroy();
      stmt.finalize();
  }); 
  stmt.get((err,row)=>{
   stmt.finalize();
   if(err){
    console.error("stmp get error",err);
   }else {
     if(row){
       var lts =  parseInt(row.lts)*10000;
       var now = moment().unix();
       if(lts>work.time){
	var msg = new Buffer(5);
	msg.writeInt8(3,0);
	msg.writeUInt32LE(lts,1);
	sock.write(msg);
	sock.destroy();
	  return;
	}
      if(lts+60>now){
	var msg = new Buffer(5);
	msg.writeInt8(4,0);
	msg.writeUInt32LE(lts+60-now,1);
	sock.write(msg);
	sock.destroy();
	return;
      }
     }
  var secret = crypto.randomBytes(24);
  var nonce = crypto.randomBytes(24);
  var box = nacl.box(
  secret,
  nonce,
  request.nacl_key,
  servicePair.secretKey
);
var msg = packBoxPacket(1,box,nonce);
sock.end(msg);
//sock.destroy();

doRespond(sockPort,sockHost,servicePair,db,request,work,secret,maxRows,(row)?true:false);

   }});
}
function doRespond(sockPort,sockHost,servicePair,db,request,work,secret,maxRows,updating_records){
  var onionAddress = onion_service_address_for_public_key(request.publicKey);
  var port = work.port;
  var sock = socks.createConnection( {"hostname":onionAddress,"port":port,"socksHost":sockHost,"socksPort":sockPort});
   var ctm = setTimeout(()=>{
     if(!sock.socket.destroyed){
       sock.destroy();
     }
    },40000);
   sock.once("connect",(err)=>{
    var param = ["select * from  networks_channels_table where pk!=? and channel=? order by lts desc limit "+maxRows,request.publicKey,work.channel];
  var stmt = db.prepare.apply(db,param); 
  stmt.on("error",(e)=>{
     console.error("database error stmt",e);
      stmt.finalize();
  }); 
  stmt.all(function(err,rows){
    if(err){
      console.error("stmt all error",err);
      stmt.finalize();
    }else {
     var msg = new Buffer(1+24+1+32+1+(rows.length*40));
     var offset = 0;
     msg.writeInt8(24,offset++);
     secret.copy(msg,offset,0,24);
     offset += 24;
     msg.writeInt8(32,offset++);
      work.channel.copy(msg,offset,0,32);
      offset += 32;
    msg.writeInt8(rows.length,offset++);
      rows.forEach(function (row) {
            Buffer(row.pk).copy(msg,offset,0,32);
	    offset += 32;
	    msg.writeUInt32LE(parseInt(row.lts*10000),offset);
	    offset+=4;
	    msg.writeUInt16LE(parseInt(row.port),offset);
	    offset+=4;
      });
var nonce = crypto.randomBytes(24);
var box = nacl.box(
  msg,
  nonce,
  request.nacl_key,
  servicePair.secretKey
);
      var reply = packBoxPacket(1,box,nonce,servicePair.publicKey);
      sock.end(reply);
      var lts = moment().unix() / 10000;
      if(updating_records){
	param = ["update  networks_channels_table set lts=?,port=? where pk=? and channel=?",lts,work.servicePort,request.publicKey,work.channel];
    }else {
	 param = ["insert into networks_channels_table (pk,lts,port,channel)values(?,?,?,?)",request.publicKey,lts,work.servicePort,work.channel];
    }
    stmt.finalize();
      stmt = db.prepare.apply(db,param);
    stmt.on("error",(e)=>{
      console.error("db update stmt error",e);
      stmt.finalize();
      });
      stmt.run((err)=>{
      if(err){
	console.error("db update stmt run error",err);
      }
      stmt.finalize();
      });
    }
    
  });
  
  
   });
   sock.once("error",(err)=>{
      console.error("socks client error",err.message);
    });
    sock.once("data",(data)=>{});
    sock.once("close",()=>{
    });
   
  
}
function packBoxPacket(command,box,nonce,publicKey){
var msg = new Buffer(1+4+box.length+1+24+((publicKey)?publicKey.length+1:0));
var offset = 0;
msg.writeInt8(command,offset++);
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
function validate_box_work(box,hashSalt){
var length = (box)?box.length:0;
if(length<50){
  console.log("box less tehen 50",length);
 return null;
}  
var offset = 0;
var data = Buffer(box);
var time = data.readUInt32LE(offset);
offset +=4;
var hashNonce = data.readUInt32LE(offset);
offset += 4;
var level = data.readInt8(offset++);
var channel_len = data.readInt8(offset++);
if(channel_len != 32){
return null;
}
var channel = data.slice(offset,offset+channel_len);
offset += channel_len;
var port = data.readUInt16LE(offset);
offset+=4;
var servicePort = data.readUInt16LE(offset);
var now = moment().unix();
if(now+180<time){
return null;
}
var content = crypto.createHash('sha256').update([hashSalt,time,level,""].join(":")).digest();
if(!checkHashProof(content,hashNonce,level)){
return null;
}
return {"channel":channel,port:port,time:time,servicePort:servicePort};
}
function openBox(data,offset,nacl_key,secretKey){
  var length = data.length;
  if(length < offset+4){
	  return null;
  }
var box_len = data.readUInt32LE(offset);
offset += 4;
if(length < offset+box_len){
  return null;
}
var box = data.slice(offset,offset+box_len);
offset += box_len;
if(length < offset+25){
  return null;
}
var nonce_len = data.readInt8(offset++);
if(nonce_len != 24||length<offset+nonce_len){
 return null;
}
var nonce = data.slice(offset,offset+nonce_len);
return nacl.box.open(box, nonce, nacl_key,secretKey);
}
function parseRequest(data){
	var offset = 0;
        var command = data.readInt8(offset++);
	var length = data.length;
	if(length < 2){
	  return null;
	}
	var key_len = data.readInt8(offset++);
	if(key_len!=32||length<key_len+offset){
	  return null;
	}
	var publicKey = data.slice(offset,key_len+offset);
	offset+=32;
	if(length<=offset){
	  return null;
	}
	var sig_len = data.readInt8(offset++);
	if(sig_len != 64 || length<= sig_len+offset){
	  return null;
	}
	var signature = data.slice(offset,sig_len+offset);
	offset+= sig_len;
	var msg_len = data.readInt8(offset++);
	if(msg_len!= 10||length< msg_len+offset){
	  return null;
	}
	var message = data.slice(offset,msg_len+offset);
	offset+=10;
	if(length< offset||isNaN(parseInt(message.toString("utf8")))){
	  return null;
	}
	var nacl_key_len = data.readInt8(offset++);
	if(nacl_key_len!= 32||length< nacl_key_len+offset){
	  return null;
	}
	nacl_key = data.slice(offset,nacl_key_len+offset);
	offset += nacl_key_len;
	var sign_msg = new Buffer(42);
	message.copy(sign_msg,0,0,10);
	nacl_key.copy(sign_msg,10,0,32);
	if(!ed25519_1.verify(publicKey, sign_msg.slice(0,42), signature)){
	  return null;
	}
      return {"command":command,"nacl_key":nacl_key,"publicKey":publicKey,"offset":offset};
}



module.exports = (options)=>{
  return new Server(options);
};