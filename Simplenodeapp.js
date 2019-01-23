const express = require('express')
const app = express()

var tpmLocation = '/home/pi/tpm2-tss/src/'
var path = require('path');
var fs = require('fs');

app.get('/', function (req, res) {
  res.send('hello world')
})

var bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
//app.use(bodyParser({ uploadDir: path.join(__dirname, 'files'), keepExtensions: true }));
var IncomingForm = require('formidable').IncomingForm
var formidable = require('formidable')

var jsonParser = bodyParser.json()

app.post('/symEnc', function (req, res) {
		var body = req.body;
		var keyName = body['keyName']
		var data = body['data']
		var fs = require('fs');
		fs.writeFile(keyName+'.dat', data, function(err) {
			if(err){
				console.log("Error "+err);
			}
			else {
				var exec = require('child_process').exec;
                                exec('./symEncrypt.sh '+keyName, function (e, stdout, stderr) {
					console.log(stdout)
					console.log(stderr)
					var data = fs.readFileSync(keyName+'enc.dat')
					var b64encode = data.toString('base64');
					res.send(b64encode);
				});
			}
		})
	})


app.post('/symmetricKeyGen', function (req,res) {
	var body = req.body;
	var content = JSON.stringify(body);
	var keyName = body['keyName']
	var keyContent = body['symKey']
	console.log("Symmetric request is "+content);

	fs.writeFileSync(keyName+".key", keyContent, 'utf8');

	var cwd = __dirname;
	var exec = require('child_process').exec;
        console.log('Prepare to run encryptMeta')
//        exec('sudo tpm2_create -C 0x81000000 -u '+cwd+'/uploads/'+keyName+'.pub -r '+cwd+'/uploads/'+keyName+'.priv');
//	exec('sudo tpm2_create -C 0x81000000 -u '+cwd+'/uploads/'+keyName+'.pub -r ./uploads/'+keyName+'.priv');
	console.log("Start with key Name "+keyName+" at "+(new Date).getTime())
	exec('sudo ./symCreate.sh '+keyName, function (e, stdout, stderr){
		console.log("End with key name "+keyName+" at "+(new Date).getTime());
		console.log(stdout)
		console.log(stderr)
			var fs = require('fs');
			var bitmap = fs.readFileSync(keyName+"encrypt.key");
			var b64encode = new Buffer(bitmap).toString('base64');
			var hash = require('hash-files');
			console.log("Start hash with key Name "+keyName+" at "+(new Date).getTime())
			hash('--files ./uploads/'+keyName+'.priv --algorithm sha256', function(error, hash){
                            if(error){
                                 console.log("Error when hashing")
                            }
                            else {
                                 console.log("Hash is "+hash)
				console.log("End hash with key Name "+keyName+" at "+(new Date).getTime())
                                 res.json({"hash": hash, "EncryptSymKey": b64encode});
                            }
			})
	});

/*	var hash = require('hash-files');
	hash('--files ./uploads/'+keyName+'.priv --algorithm sha1', function(error, hash){
		if(error){
			console.log("Error when hashing")
		}
		else {
			console.log("Hash is "+hash)
			res.send(hash);
		}
	}) */
})

app.post('/encryptMeta',jsonParser, function (req, res) {
	var policies = req.get("Policies");
	console.log("Header is "+policies)
	var arr = policies.split("/")
	console.log("Array "+arr);
//	arr = arr.map(function (val) { return +val + 1; });
        var content = JSON.stringify(req.body);
	console.log("Body is "+content)
	arr.forEach(function(value) {
		console.log(value)
		var temp = value.split(",")
		var fs = require('fs');
		fs.writeFile(temp[0], temp[1], function(err) {
			if(err) {
				return console.log(err);
		}
		});
	})
//	console.log('File is '+req.file)
// create an incoming form object
//  var form = new formidable.IncomingForm();

  // specify that we want to allow the user to upload multiple files in a single request
//  form.multiples = true;

  // store all uploads in the /uploads directory
//  form.uploadDir = path.join(__dirname, '/uploads');

  // every time a file has been uploaded successfully,
  // rename it to it's orignal name
//  form.on('file', function(field, file) {
//    fs.rename(file.path, path.join(form.uploadDir, 'temp.tmp'));
//  });

  // log any errors that occur
//  form.on('error', function(err) {
//    console.log('An error has occured: \n' + err);
//  });
  // once all the files have been uploaded, send a response to the client
//  form.on('end', function() {
//    res.end('success');
//  });

  // parse the incoming request containing the form data
//  form.parse(req);
//	req.on('data', function(chunk) {
//		console.log("Received body data: "+chunk.toString())
//	});
//	var content = req.body;//"..."
	console.log("Request is "+content);
	fs.writeFile("temp.tmp", content,function(err) {
		if(err) {
			return console.log(err);
		}
		else {
			console.log("The file was saved!");
			require('child_process').execSync;
			console.log('Prepare to run encryptMeta')
			exec('sudo ./encryptMeta.sh');

		//        fs.rename('final.tmp', req.file, function(err) {
		//                if(err) console.log('ERROR: ' + err)
		//        })
			var bitmap = fs.readFileSync('final.tmp')
			fs.unlink('temp.tmp', function(err){
				if(err) {
					console.log("Error when delete file temp.tmp!!");
				}
				else {
					console.log("Delete temp successfully!!!");
				}
			});
			fs.unlink('final.tmp', function (err) {
				if(err) {
					console.log("Error when delete final.temp");
				}
				else {
					console.log("Delete final file done!!!")
					var b64encode = new Buffer(bitmap).toString('base64');
					console.log(b64encode)
					res.send(b64encode);
				}
			});
		}
		console.log("The file was saved!");
	});
})

app.post('/decryptMeta', function (req, res){
// var policies = req.get("Policies");
	// There must be some task to write to NV Entry
	// Then pick an appropriate key
	var content = JSON.stringify(req.body);
	console.log("Body is "+req.body)
	var objectValue = JSON.parse(content);
        var cipher = objectValue['cipher'];
	console.log("Cipher is "+cipher);
	var buf = new Buffer(cipher, 'base64'); // Ta-da
	var randomstr = require("randomstring");
	var randomstring = randomstr.generate(7);
	var filePath = path.join(__dirname, 'tempDec'+randomstring+'.tmp')

                var dirname = "/home/pi/SimpleNode";
                var newPath = dirname + "/uploads/tempDec"+randomstring+".tmp";
		var fs = require('fs');
                fs.writeFileSync(newPath, buf, 'binary') /* function (err) {
                        if(err){
                                res.json({'response':"Error"});
                        }else {
                                res.json({'response':"Saved"});
                        }
                });*/

	if (fs.existsSync(newPath)) {
		console.log("File existed!!!!")
		var exec = require('child_process').execSync;
		exec('sudo ./decryptMeta.sh '+randomstring);
	}
	else {
		console.log("File temp Dec not existed!!!")
	}

//        fs.rename('final.tmp', req.file, function(err) {
//		if(err) console.log('ERROR: ' + err)
//        })
	var file = fs.readFileSync("finalDec"+randomstring+".tmp", "utf8");
	fs.unlink('tempDec'+randomstring+'.tmp', function(err){
		if(err) {
			console.log("Error when delete file temp.tmp!!")
		}
		else {
			console.log("Delete temp successfully!!!")
		}
	})
	fs.unlink('finalDec'+randomstring+'.tmp', function (err) {
		if(err) {
			console.log("Error when delete final.temp");
		}
		else {
			console.log("Delete final file done!!!")
			console.log(file);
			res.send(file);
		}
	})
})

app.post('/tpmDec', function (req, res) {
	var keyInfo = req.body;
	console.log("Content is "+JSON.stringify(keyInfo));
	var cont = keyInfo;
//	var cont = keyInfo;
	var arr = [];
	var i = 0;
	var length;
//	for (var key in cont) {
//		i++;
//		if (cont.hasOwnProperty(key)) {
//			var val = cont[key];
//			console.log(val);
//			var element = val;
			var keyName = cont['keyName']
			var symEnc = cont['SymEnc']
			console.log("Before TPM decrypt "+(new Date).getTime())
			console.log("Sym Enc and keyName "+symEnc+" "+keyName)
			tpmDecrypt(keyName, symEnc, i, function (result, time, nameofKey){
				console.log("After TPM decrypt "+(new Date).getTime())
				var jsonString = {"keyName": nameofKey, "KeyContent":result}
			//	arr.push(jsonString);
				console.log("Key Name "+nameofKey+" and "+result);
			//	if(time == length)
				res.send(jsonString);
			});
//		}
//	}
	length = i;
})

function tpmDecrypt(keyName, symEnc, time, callback){
	var fs = require('fs')
	console.log("Sym Enc is "+symEnc);
	var buf = new Buffer(symEnc, 'base64');
	fs.writeFileSync(__dirname + "/"+keyName+".txt", buf, 'binary');
	var exec = require('child_process').exec;
	console.log("Prepare to decrypt for metadata "+keyName);
	exec("./decryptMeta.sh "+keyName, function(err, stdout, stderr){
             try{
		var file = fs.readFileSync(keyName+"Plain.txt", 'utf8')
		console.log("Finish decrypt metadata for "+keyName)
                callback(file, time, keyName)
             }
             catch(err){
                console.log(err)
             }
	});
}
app.get('/public', function (req, res){
	var exec = require('child_process').execSync;
	var fileLocation = tpmLocation +'pub.txt';
//	var command = ['./keybackup.out']
	exec('cd '+tpmLocation+' && ./keybackup.out');
/*	exec(command, function(err, pid, result) {
		console.log("Result of tpm "+result);
		callback(result){
			console.log("Final result is "+result);
			console.log("Prepare to send file "+fileLocation)
			res.download(fileLocation)
		};
	}) */
	console.log("Prepare to send file "+fileLocation)
	res.download(fileLocation)
});

app.post('/import', function (req, res){
	var body = req.body;
	var keyblob = body['keyblob'];
	var keyName = body['keyName'];
	var buf = new Buffer(keyblob, 'base64');
	var fs = require('fs');
	console.log("Inside import")
	fs.writeFileSync('./ImportKey/'+keyName+'keyblob.txt', buf, 'binary');
	var exec = require('child_process').exec;
	exec("./import.sh "+keyName, function(err, stdout, stderr){
		res.send("Success");
	});

})
app.post('/duplicate', function (req, res) {
        console.log('A duplicate request is coming!');
	var fs = require('fs');
	var body = req.body;
	var keyName = body['keyName'];
	var targetUrl = body['targetUrl'];
	var newKey = body['newKey'];
	var buf = new Buffer(newKey, 'base64');
	fs.writeFileSync('newPar.pub',buf,'binary');
	var exec = require('child_process').exec;
	exec("./duplicate.sh "+keyName, function (err, stdout, stderr){
		var bitmap = fs.readFileSync(keyName+"keyblob.txt");
		var b64blob = new Buffer(bitmap).toString('base64');

		var request = require('request');
		console.log("Inside getDataPoint")

                // Set the headers
		var headers = {
		'User-Agent':       'Super Agent/0.0.1',
                'Content-Type':     'application/json',
                }
                timeout = 200000;
                // Configure the request
                var options = {
                    url: 'http://141.223.121.191:4567/import',
                    method: 'POST',
                    headers: headers,
                    form: {'keyblob': b64blob, 'keyName': keyName}
                }

                // Start the request
                request(options, function (error, response, body) {
		    if (!error && response.statusCode == 200) 
		    {
			// Print out the response body
			var res = response.body;
			console.log(res)
			return res;
		    }
		})
	})

})

app.post('/directDuplicate', function (req, res) {
        console.log('A duplicate request is coming!');
	var fs = require('fs');
	var body = req.body;
	var keyName = body['keyName'];
	var newKey = body['newKey'];
	var buf = new Buffer(newKey, 'base64');
	fs.writeFileSync('newPar.pub',buf,'binary');
	var exec = require('child_process').exec;
	exec("./duplicate.sh "+keyName, function (err, stdout, stderr){
		if(err)
		    console.log("Error when duplicate "+err)
		var bitmap = fs.readFileSync(keyName+"keyblob.txt");
		var b64blob = new Buffer(bitmap).toString('base64');

		res.send({'keyblob': b64blob, 'keyName': keyName})
	})

})

app.listen(3000, () => console.log('Example app listening on port 3000!'))
