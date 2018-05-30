forge.options.usePureJavaScript = true;
var service=function(){
var serverpublicKey;
var serviceKey;
var serverpublicKey = axios.get('http://110.164.179.154/node/fintechShare/secure/getPublicKey')
.then(function (response) {
      setserverpublicKey(response.body);
      })
.catch(function (error) {
       console.log(error);
       });

function setserverpublicKey(pk) {
    serverpublicKey = key;
}


var instance = forge.rsa.generateKeyPair({
                                         bits: 2048,
                                         workers: -1
                                         }, function (err, keypair) {
                                         
                                         serviceKey = keypair;
                                         });
function handShake(api,token) {
    return instance.then(function () {
                         return serverpublicKey.then(function () {
                                                     var encrypted = serverpublicKey.encrypt(serviceKey.publicKey, 'RSA-OAEP');
                                                     return encrypted.then(function(chipher){
                                                                           axios.post('http://110.164.179.154/node/fintechShare/secure/handShake/',{
                                                                                      cypher: chipher,
                                                                                      })
                                                                           .then(function (response) {
                                                                                 
                                                                                 var decrypted = keystore.privateKey.decrypt(response.body, 'RSA-OAEP');
                                                                                 if(pack(decrypted) == 'handShake success'){
                                                                                 return pack(decrypted);
                                                                                 }
                                                                                 else{
                                                                                 Promise.reject('Hand shake not complete');
                                                                                 }
                                                                                 })
                                                                           .catch(function (error) {
                                                                                  return error;
                                                                                  });
                                                                           });
                                                     });
                         });
}
function decryptedAndload(ticker) {
    return serverpublicKey.encrypt(ticker, 'RSA-OAEP', {
                                   md: forge.md.sha256.create(),
                                   mgf1: {
                                   md: forge.md.sha1.create()
                                   }
                                   }).then(function(cypherToServer){
                                           axios.get('http://110.164.179.154/node/fintechShare/secure/load/', {
                                                     params: {
                                                     cypher: cypherToServer
                                                     }
                                                     })
                                           .then(function (response) {
                                                 var decrypted = serviceKey.privateKey.decrypt(response, 'RSA-OAEP', {
                                                                                               md: forge.md.sha256.create(),
                                                                                               mgf1: {
                                                                                               md: forge.md.sha1.create()
                                                                                               }
                             /Users/user/Desktop/untitled folder/Quick-Chat/QuickChat/Main.storyboard
                                                                                               }).then(function(data){
                                                                                                       return ejs.render('candlechart', {
                                                                                                                         items: res
                                                                                                                         });
                                                                                                       
                                                                                                       })
                                                 .catch(function (error) {
                                                        Promise.reject(error);
                                                        });
                                                 });
                                           
                                           });
}

function pack(bytes) {
    var chars = [];
    for (var i = 0, n = bytes.length; i < n;) {
        chars.push(((bytes[i++] & 0xff) << 8) | (bytes[i++] & 0xff));
    }
    return String.fromCharCode.apply(null, chars);
}

function unpack(str) {
    var bytes = [];
    for (var i = 0, n = str.length; i < n; i++) {
        var char = str.charCodeAt(i);
        bytes.push(char >>> 8, char & 0xFF);
    }
    return bytes;
}



}

