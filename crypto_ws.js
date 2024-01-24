const cjs = require('crypto-js');
const http = require('http');
const LoremIpsum = require("lorem-ipsum").LoremIpsum;
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

const lorem = new LoremIpsum({
  sentencesPerParagraph: {
    max: 8,
    min: 4
  },
  wordsPerSentence: {
    max: 16,
    min: 4
  }
});

http.createServer(function (req, res) {
	let helpMsg = "Valid endpoints:\r\nPOST /legacy_encrypt\r\nPOST /legacy_decrypt\r\nPOST /pbkdf2_encrypt\r\nPOST /pbkdf2_decrypt\r\nGET /plaintext?p=<paragraphs, default is 1> - lorem ipsum text generation\r\nGET accepts plaintext. POSTS expect plaintext body.\r\n";
	let textIn = '';
	let pwdIn = ''
	if (req.headers['x-crypto-pass'] != null)
		pwdIn = atob(req.headers['x-crypto-pass'])
	else
		pwdIn = process.env.pwd;
	
	try
	{
		req.on("data", (chunk) => { textIn += chunk; });
		req.on("end", () => {
			try
			{
				//console.log("Original text:\r\n" + textIn);
				if (req.method == "POST" || req.method == "OPTIONS")
				{
					//console.log(req);
					if (req.url == "/legacy_encrypt")
					{
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass'});
						res.write(cjs.AES.encrypt(textIn, pwdIn).toString() + "\r\n");
						res.end();
						//console.log(res);
					}
					else if (req.url == "/legacy_decrypt")
					{
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass'});
						res.write(cjs.AES.decrypt(textIn, pwdIn).toString(cjs.enc.Utf8) + "\r\n");
						res.end();
						//console.log(res);
					}
					else if (req.url.startsWith("/pbkdf2_encrypt"))
					{
						var salt = cjs.lib.WordArray.random(128 / 8);
						var params = new URLSearchParams(req.url.substring(req.url.indexOf('?')));
						var n = params.get("i") ?? '2000000';
						var i = parseInt(n);
						var iterKey = cjs.PBKDF2(pwdIn, salt, { keySize: 512 / 32, iterations: i });
						var iterIV = cjs.MD5(pwdIn);
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass','Content-Type': 'application/json'});
						var resp = {"cipherText": cjs.AES.encrypt(textIn, iterKey.toString(cjs.enc.Hex), {iv: iterIV.toString(cjs.enc.Hex)}).toString(), "key": iterKey.toString(cjs.enc.Hex), "iv" : iterIV.toString(cjs.enc.Hex)}
						res.write(JSON.stringify(resp));
						res.end();
						//console.log(res);
					}
					else if (req.url.startsWith("/pbkdf2_decrypt"))
					{
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass'});
						var cipherObj = JSON.parse(textIn);
						res.write(cjs.AES.decrypt(cipherObj.cipherText, cipherObj.key, {iv: cipherObj.iv}).toString(cjs.enc.Utf8));
						res.end();
						//console.log(res);
					}
					else
					{
						res.writeHead(404, {'Content-Type': 'text/plain'});
						res.write(helpMsg);
						res.end();
						
					}
				}
				else if (req.method == "GET" && req.headers['accept'] == 'text/plain')
				{
					if (req.url.startsWith("/plaintext"))
					{
						var params = new URLSearchParams(req.url.substring(req.url.indexOf('?')));
						var n = params.get("p") ?? '1';
						var p = parseInt(n);
						textIn = lorem.generateParagraphs(p);
						res.writeHead(200, {'Access-Control-Allow-Origin': '*','Access-Control-Allow-Methods': 'OPTIONS, POST, GET','Transfer-Encoding':'chunked','Accept': 'text/plain'});
						res.write(textIn);
						res.end();
					}
					else
					{
						res.writeHead(404, {'Content-Type': 'text/plain'});
						res.write(helpMsg);
						res.end();
					}
				}
				else if (req.headers['Accept'] != "text/plain")
				{
					res.writeHead(415, {'Content-Type': 'text/plain'});
					res.write(helpMsg);
					res.end();
				}
				else
				{
					res.writeHead(405, {'Content-Type': 'text/plain'});
					res.write(helpMsg);
					res.end();
				}
			}
			catch(e) {
				res.writeHead(401, {'Content-Type': 'text/plain'});
				res.write(`${e.message}: Password probably invalid!\r\n`);
				res.end();
			}
		});
	}
	catch (e) {
		console.log(e.message);
	}
	
	req.on('error', (e) => {
			console.error(`problem with request: ${e.message}`);
	});
	
	res.on('error', (e) => {
			console.error(`problem with response: ${e.message}`);
	});
}).listen(9843);