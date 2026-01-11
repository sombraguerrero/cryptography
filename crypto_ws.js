import {
  encryptText,
  decryptText,
  generateLuhn19Batch
} from "./crypto_utils.js";
import http from "http";
import { LoremIpsum } from "lorem-ipsum";
import crypto from "crypto";
import fs from "fs";
import dotenv from "dotenv";
dotenv.config();

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

http.createServer(async function (req, res) {
	let helpMsg = "Valid endpoints:\r\nPOST /enc\r\nPOST /dec\r\nGET /lorem?p=<paragraphs, default is 1> - lorem ipsum text generation\r\n/luhn?q=<quantity, default is 1> - Luhn checksum numbers\r\nGET accepts plaintext. POSTS expect plaintext body.\r\n";
	let textIn = '';
	let pwdIn = process.env.pwd;
	
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
					if (req.url == "/enc")
					{
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'http://settersynology','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass'});
						res.write(encryptText(textIn));
						res.end();
						//console.log(res);
					}
					else if (req.url == "/dec")
					{
						res.writeHead(200, {'Accept':'text/plain','Access-Control-Allow-Origin':'http://settersynology','Access-Control-Allow-Methods':'OPTIONS, POST, GET','Access-Control-Allow-Headers':'x-crypto-pass'});
						res.write(decryptText(textIn));
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
					if (req.url.startsWith("/lorem"))
					{
						var params = new URLSearchParams(req.url.substring(req.url.indexOf('?')));
						var n = params.get("p") ?? '1';
						var p = parseInt(n);
						textIn = lorem.generateParagraphs(p);
						res.writeHead(200, {'Access-Control-Allow-Origin': 'http://settersynology','Access-Control-Allow-Methods': 'OPTIONS, POST, GET','Transfer-Encoding':'chunked','Accept': 'text/plain'});
						res.write(textIn);
						res.end();
					}
					else if (req.url.startsWith("/luhn"))
					{
						var params = new URLSearchParams(req.url.substring(req.url.indexOf('?')));
						var n = params.get("q") ?? '1';
						var q = parseInt(n);
						textIn = generateLuhn19Batch(q).toString();
						res.writeHead(200, {'Access-Control-Allow-Origin': 'http://settersynology','Access-Control-Allow-Methods': 'OPTIONS, POST, GET','Transfer-Encoding':'chunked','Accept': 'text/plain'});
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