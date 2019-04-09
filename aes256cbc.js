(function() {
    
    'use strict';
    var crypto = require('crypto');
    
	var cryptkey    = "c0ba4d01b2206ce903559b2e9e7ef951";
	var iv         = "0000000000000000";

	module.exports.encrypt = function(plaintext) {
    	var encipher = crypto.createCipheriv('aes-256-cbc', cryptkey, iv),
       	encryptdata = encipher.update(plaintext, 'utf8', 'binary');
    	encryptdata += encipher.final('binary');
    	var encode_encryptdata = new Buffer(encryptdata, 'binary').toString('hex');
    	return encode_encryptdata;
	};
	
	module.exports.decrypt = function(encodetext) {
    	var encryptdata = new Buffer(encodetext, 'hex').toString('binary');    
   		var decipher = crypto.createDecipheriv('aes-256-cbc', cryptkey, iv),
       	decoded = decipher.update(encryptdata, 'binary', 'utf8');
   		decoded += decipher.final('utf8');
   		return decoded;
    };    
})();
