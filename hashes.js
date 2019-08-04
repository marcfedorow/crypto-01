const sha256 = require("crypto-js").SHA256;
const sha1 = require("crypto-js").SHA1;
const md5 = require("crypto-js").MD5;

var hash_functions = [
	sha256,
	sha1,
	md5,
]

/*
var data = "The quick brown fox jumps over the lazy dog";
var hash = sha256(data).toString();
console.log("data = " + data + "\nhash = " + hash + "\nlength = " + hash.length);
*/

var getVarName = function tmp(){
	let n = /getVarName\(([^)]+?)\)/.exec(tmp.caller !== null ? tmp.caller.toString() : '');
	return n !== null ? n[1] : false;
}

var data = [];
for (var step = 0; step < 256 * 255 + 255; data[step++] = Math.random().toString(36));

var trash, t;
for (var hash = 0; hash < hash_functions.length; ++hash){
	console.log(hash == 0? "sha256:" : hash == 1? "sha1:" : "md5:");
	t = - (new Date().getTime());
	for (var step = 0; step < 256 * 255 + 255; trash = hash_functions[hash](data[step++]));
	t += new Date().getTime();
	console.log(t + " milliseconds");
}
