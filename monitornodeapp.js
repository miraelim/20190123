const express = require('express')
const app = express()
var dataLocation="/home/pi/healthData"
var async = require('asyncawait/async')
var await = require('asyncawait/await')

var bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	      extended: true
	      }));
//app.use(bodyParser({ uploadDir: path.join(__dirname, 'files'), keepExtensions: true }));
var IncomingForm = require('formidable').IncomingForm
var formidable = require('formidable')

var jsonParser = bodyParser.json()

app.get("/collect/:dataType", function (req, res){
    console.log("Start to collect data "+(new Date).getTime())
    var dataType = req.params.dataType;
    var directory = dataLocation+"/"+dataType
    var allContent = '';
    console.log("A request coming to "+dataType);

    var fs = require('fs');
    fs.readdir(directory, function(err, filenames){
	    if(err){
		console.log("Error "+error)
	    }
	    else {
		filenames.forEach(function(filename){
			    console.log("Filename "+directory+"/"+filename)
			    var content = fs.readFileSync(directory +"/"+ filename, 'utf-8')
				console.log("Content is "+content);
				if(allContent === '')
				    allContent = allContent + content
				else
				    allContent = allContent + content
		})
//		console.log("All content is "+allContent);
		res.send(allContent) 
		/*
		Promise.all(allContent)
		.then((result) => { 
				    console.log("All content is "+allContent);
				    res.send(allContent)} )
		.catch((err) => res.send(err)) 
		*/
	    }
    })
})

app.post("/collect", function(req, res){
	console.log("Start tag and encrypt data "+(new Date).getTime())
	console.log("Body "+req.body)
	var jsonArr = req.body;
	var fs = require('fs');
//	for(var i= 0; i<jsonArr.length; i++){
//	    console.log("Loop number "+i+" out of "+jsonArr.length)
	    var fileContent = jsonArr//[i];
	    console.log("Element content "+fileContent);
	    var header = fileContent['header'];
	    var policy = fileContent['Policy']
	    var id = header['id'];
	    var body = JSON.stringify(fileContent['body']);
	    console.log("Prepare to write tagged data "+body);
	    var fileTagContent = JSON.stringify(jsonArr)//[i]);
	    var secureRandom = require('secure-random')
	    var keyBuff = secureRandom.randomBuffer(16);
	    var keyString = keyBuff.toString('base64');
	    delete fileContent['body'];
	    var newBody = {};
	    newBody['Policy'] = policy;

	    var cryp = require('crypto')
	    console.log((new Date).getTime()+": Before AES")
	    var iv = new Buffer(0);
	    var cipher = cryp.createCipheriv('aes-128-ecb', keyBuff, iv)
	    cipher.setAutoPadding(false);
	    var crypt = cipher.update(body,'utf-8', 'base64')
	    console.log("After AES "+(new Date).getTime())
	    newBody['crypt'] = crypt;
	    console.log("Crypt "+crypt)

	    var keyName = Math.random().toString(36).substring(10).toUpperCase(); 
	    fs.writeFileSync(keyName+".key", keyString)
	    var exec = require('child_process').exec
	    console.log("Before TPM operations "+(new Date).getTime())
	    exec('sudo ./symCreate.sh '+keyName, function (e, stdout, stderr){
		    console.log("Finish TPM "+(new Date).getTime())
		    console.log(stdout)
		    var bitmap = fs.readFileSync(keyName+"encrypt.key");
		    var SymEnc = new Buffer(bitmap).toString('base64');
		    var hash = require('hash-files');
		    console.log("Before hash "+(new Date).getTime())
		    hash("--files ./uploads/"+keyName+".priv --algorithm sha256", function(error, hash){
			    if(error)
				console.log('Error when hashing')
			    else {
			        console.log("Finish hash "+(new Date).getTime())
				newBody['keyName'] = keyName;
				newBody['SymEnc'] = SymEnc;
				newBody['hashKey'] = hash;
				fileContent['body'] = newBody;
			        console.log('Hash is '+hash)
				console.log('End hash with key Name '+keyName+" at "+(new Date).getTime())
				fs.writeFile(dataLocation+"/taggedData/"+id+".txt", JSON.stringify(fileContent), function(err){ 
					if(err) 
					    throw err;
					else {
					    console.log("Write data successfully "+(new Date).getTime());
					    
					}
				})

			  }
		    })
	    })
//	}
	res.send("Success");
})

app.post("/upload", function (req, res){
    console.log("Start uploading "+(new Date).getTime())
    var body = req.body;
    var token = body['token'];
    var request = require('request');
    var headers = {
          'User-Agent':       'Super Agent/0.0.1',
	  'Content-Type':     'application/json',
    }
    timeout = 200000;
    fs = require('fs')
    var directory = dataLocation+"/taggedData";
    fs.readdir(directory, function(err, filenames){
	    if(err){
		console.log("Error "+error)
	    }
	    else {
		filenames.forEach(function(filename){
			    console.log("Filename "+directory+"/"+filename+":"+(new Date).getTime())
			    var content = fs.readFileSync(directory +"/"+ filename, 'utf-8')
			    var jsonContent = JSON.parse(content);
			    var header = jsonContent['header'];
			    var id = header['id']
			    var body = jsonContent['body']
			    var keyName = body['keyName'];
			    var SymEnc = body['SymEnc']
			    var hashKey = body['hashKey']
			    var policy = body['Policy']
//			    var options = {
//				url: 'http://141.223.121.191:5000/metaencrypt',
//				method: 'POST',
//				headers: headers,
//				form: {'keyName' : keyName, 'hashKey' : hashKey, 'SymEnc' : SymEnc, 'attrs' : policy}
//			    }
//			    request(options, function (error, response, body){
//				    if(!error && response.statusCode == 200){
//					var result = JSON.stringify(response.body)
//					console.log("Meta encrypt result "+result)
    
			    jsonBody = {};
			    jsonBody['keyName'] = keyName;
			    jsonBody['hashKey'] = hashKey
			    jsonBody['SymEnc'] = SymEnc
			    jsonBody['attrs'] = policy
			      request.post('http://141.223.121.191:5000/metaencrypt', {
			      json: jsonBody
			    }, (error, res, body) => {
				if (error) {
				    console.error(error)
				    return
				} 
				else{
				    uploadMeta(policy, id, res.body, token)
				    console.log("Content and token "+content+" "+token)
				    uploadDataPoint(content, token)
				}
				    console.log(`statusCode: ${res.statusCode}`)
				    console.log(body)
			    })

				})
				res.send("Success") 
			   }
    })

})

function uploadMeta(policy, id, result, token){
    var meta = {}
    meta['id'] = id;
    meta['metacrypt'] = result;
    var pols = JSON.parse(policy);
    console.log("Policy "+policy)
//    for (var key in policy) {
//	if (policy.hasOwnProperty(key)) {
//	          var val = policy[key];
//		//  console.log(val);
//		  meta[key] = val;
//		}
//    }
    Object.keys(pols).forEach(function(key) {
	console.log('Key : ' + key + ', Value : ' + pols[key])
	meta[key] = pols[key]
    })

    var request = require('request');

    request.post('http://141.223.83.26:3000/posts', {
	      json: meta
	    }, (error, res, body) => {
		if (error) {
		    console.error(error)
		} 
		else{
		    
		}
		    console.log(`statusCode: ${res.statusCode}`)
		    console.log((new Date).getTime()+'Upload meta body '+JSON.stringify(meta))
	    })

}

function uploadDataPoint(dataPoint, token){
    console.log("Inside upload dataPoint")
    var request = require('request');
    console.log("Token "+token)
      // Set the headers
      var headers = {
	'Accept':       'application/json',
	'Content-Type':     'application/json',
	'Authorization':    'Bearer '+token
      }
      timeout = 200000;

      var jsonDataPoint = JSON.parse(dataPoint)
      delete jsonDataPoint['id'];
      delete jsonDataPoint['Policy']

      // Configure the request
	 
      var options = {
	    url: 'http://141.223.83.26/dsu/dataPoints',
	    method: 'POST',
	    headers: headers,
	    json: jsonDataPoint
      }
      console.log("DataPoint content "+dataPoint)     
      // Start the request
      request(options, function (error, response, body) {
		    var result = response.body;
		    console.log((new Date).getTime()+"Result of uploading dataPoint "+result+" "+response.statusCode)
	})
}

app.listen(3001, () => console.log('Example app listening on port 3000!'))

