var ip_util = require('ip');

var CONFIG = {
  limit: 10,
  refresh: 5,
  block_undetected: false,
  action: 'close',
  message: 'Forbidden',
  duration: 120,
  blacklist: null,
  whitelist: null,
  log: true,
  callback: null
};

var BANS = {};
var IPS = {};

function detectIP(req){
  var ip_address = req.connection.remoteAddress;

  if (!ip_address) return null;

  if (ip_address == '::1') return '127.0.0.1';
  if (ip_util.isV6Format(ip_address) && ~ip_address.indexOf('::ffff')) ip_address = ip_address.split('::ffff:')[1];

  return ip_address;
}

function ban(req,res,ip){
  if(CONFIG.action == 'close') req.connection.end();
  else if(typeof CONFIG.action === 'number'){
    res.status(CONFIG.action);
    if(CONFIG.message) res.send(CONFIG.message);
  }else res.status(403);
  if(CONFIG.log) console.log('Rejecting request from '+ip+' at '+(new Date()));
  if(CONFIG.callback && typeof CONFIG.callback === 'function') CONFIG.callback(ip);
}

function BotIPS(){
  for(var k in IPS){
    if(IPS[k].counter === 1) delete IPS[k];
    else IPS[k].counter--;
  }

  setTimeout(function(){
    BotIPS();
  },CONFIG.refresh);
}

function BotBANS(){
  for(var k in BANS){
    if(BANS[k] === 1) delete BANS[k];
    else BANS[k]--;
  }

  console.log(BANS,IPS)

  setTimeout(function(){
    BotBANS();
  },1000);
}

exports = module.exports = function(config){
  CONFIG = Object.assign(CONFIG,config);
  CONFIG.refresh *= 1000;
  BotBANS();
  BotIPS();
};

exports.verify = function(req,res,next){
  var ip = detectIP(req);

  req.ddos = {
    blacklist: function(){
      CONFIG.blacklist[ip] = true;
      ban(req,res,ip);
    },
    removeFromBlacklist: function(){
      delete CONFIG.blacklist[ip];
    },
    ban: function(){
      BANS[ip] = CONFIG.duration;
      ban(req,res,ip);
    }
  };

  if(!ip && CONFIG.block_undetected) ban(req,res,ip);
  else if(CONFIG.blacklist && ip in CONFIG.blacklist) ban(req,res,ip);
  else if(CONFIG.whitelist && ip in CONFIG.whitelist) next();
  else if(ip in BANS) ban(req,res,ip);
  else{
    var data = IPS[ip];
    if(data){
      if(IPS[ip].counter == CONFIG.limit - 1){
        BANS[ip] = CONFIG.duration;
        ban(req,res,ip);
      }else{
        IPS[ip].counter++;
        next();
      }
    }else{
      IPS[ip] = {counter: 1};
      next();
    }
  }
}
