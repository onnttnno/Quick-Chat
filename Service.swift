  //
//  Service.swift
//  QuickChat
//
//  Created by user on 19/3/2561 BE.
//  Copyright © 2561 Mexonis. All rights reserved.
//
import JavaScriptCore
import Foundation
import SwiftyRSA
import CryptoSwift
final class Service{
    static var sharedInstance = try! Service()
    private var servicePK:PublicKey!
    private var servicePrK:PrivateKey!
    private var serverPK:PublicKey!
    private var serviceIV:Array<UInt8>!
    private var serviceAesKey:Array<UInt8>!

    //js data
    private var jsContext: JSContext!
    private var jsVakue :JSManagedValue!
    private var forgePKI:JSManagedValue!
    private var forg:JSManagedValue!
     init() throws {
        // perform some initialization here
        if #available(iOS 10.0, *) {
            let jsvm = JSVirtualMachine()
            self.jsContext = JSContext(virtualMachine: jsvm)
            if let jsPath = Bundle.main.path(forResource: "forge.min", ofType: "js") , let axiosPath = Bundle.main.path(forResource: "axios.min", ofType: "js"),let servicePath = Bundle.main.path(forResource: "service", ofType: "js"){
                let jslib = try! String(contentsOfFile: jsPath)
                let axioslib = try! String(contentsOfFile: axiosPath)
                let servicelib = try! String(contentsOfFile: servicePath)
                //print(jslib)
                //print(axioslib)
                //print(servicelib)
                self.jsContext.evaluateScript(jslib)
                self.jsContext.evaluateScript(axiosPath)
                self.jsContext.evaluateScript(servicePath)
                //self.forg = JSManagedValue(value: self.jsContext.objectForKeyedSubscript("forge"))
                self.jsContext.exceptionHandler = { context, exception in
                    if let exc = exception {
                        print("JS Exception:", exc.toString())
                    }
                }
            
            let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 2048)
            let privateKey = keyPair.privateKey
            let publicKey = keyPair.publicKey
            self.servicePK = publicKey
            self.servicePrK = privateKey
            self.serviceIV = AES.randomIV(AES.blockSize)
            self.serviceAesKey = Array("Secrete".utf8)
            let url = URL(string: "http://110.164.179.154/node/fintechShare/secure/getPublicKey")
            if let usableUrl = url {
                let request = URLRequest(url: usableUrl)
                let task = URLSession.shared.dataTask(with: request, completionHandler: { (data, response, error) in
                    if let data = data {
                        do {
                            if let stringData = String(data: data, encoding: String.Encoding.utf8) {
                                print(stringData) //JSONSerialization
                               // self.serverPK = stringData
                                let serverPublicKey = stringData
                             
                                let publicKeySV = try PublicKey(pemEncoded: serverPublicKey)
                                self.serverPK=publicKeySV
                                self.jsContext.evaluateScript("var pki = forge.pki;")
                                var str = try! self.servicePK.pemString()
                                str = str.replacingOccurrences(of: "\'", with: "\\\'")
                                str = str.replacingOccurrences(of: "\"", with: "\\\"")
                                str = str.replacingOccurrences(of: "\n", with: "\\n")
                                str = str.replacingOccurrences(of: "\r", with: "")
                                
                                let strJS = "var publicKeySV = pki.publicKeyFromPem(\'\(str)\');";
                                self.jsContext.evaluateScript(strJS)
                                let jsonObject = [
                                    [
                                        "aesKey": self.serviceAesKey,
                                        "iv": self.serviceIV,

                                    ]
                                ]
                                var jsonStr = self.jsonToString(json: jsonObject )
                                print(jsonStr)
                                jsonStr = jsonStr.replacingOccurrences(of: "\n", with: "\\n")

                                //encrypt
                                /*let clear = try ClearMessage(string: "HI i am", using: .utf8)
                                let encrypted = try clear.encrypted(with: self.serverPK, padding: .OAEP)
                                
                                // Then you can use:
                                let data = encrypted.data
                                let base64String = encrypted.base64String
                                print(base64String)*/
                               // self.jsContext.evaluateScript("var buffer = forge.util.createBuffer(\(jsonStr),'utf8');")
                                
                                /*json data*/
                                self.jsContext.evaluateScript("var pwd = forge.random.getBytesSync(32).toString('binary');")
                                self.jsContext.evaluateScript("var json = {'key': 24, 'iv': 8, 'pwd': pwd};")
                                self.jsContext.evaluateScript("var jsonStr = JSON.stringify(json)")
                                
                                self.jsContext.evaluateScript("var buffer = forge.util.encodeUtf8(jsonStr);")
                                let cypher2 = self.jsContext.evaluateScript("forge.util.encode64(publicKeySV.encrypt(buffer, 'RSA-OAEP'));")
                               // print(cypher2?.toString())
                                var x = cypher2?.toString()
                                /*x = x?.replacingOccurrences(of: "\'", with: "\\\'")
                                x = x?.replacingOccurrences(of: "\"", with: "\\\"")
                                x = x?.replacingOccurrences(of: "\n", with: "\\n")
                                x = x?.replacingOccurrences(of: "\r", with: "")*/
                                
                                var strPvr = try! self.servicePrK.pemString()
                                strPvr = strPvr.replacingOccurrences(of: "\'", with: "\\\'")
                                strPvr = strPvr.replacingOccurrences(of: "\"", with: "\\\"")
                                strPvr = strPvr.replacingOccurrences(of: "\n", with: "\\n")
                                strPvr = strPvr.replacingOccurrences(of: "\r", with: "")
                                let strJSs = "var privateKeySV = pki.privateKeyFromPem(\'\(strPvr)\');"
                                self.jsContext.evaluateScript(strJSs)
                                self.jsContext.evaluateScript("var prv = forge.util.decode64('\(x!)');")
                                let decypher = self.jsContext.evaluateScript("privateKeySV.decrypt(prv, 'RSA-OAEP');")
                                var t = decypher?.toString()
                                print(t!)
                            //hand shake
                                //
                                 /* self.sendRequest("http://110.164.179.154/node/fintechShare/secure/handShake/", parameters: ["cypher": base64String]) { responseObject, error in
                                    guard let responseObject = responseObject, error == nil else {
                                        print(error ?? "Unknown error")
                                        return
                                    }
                                    
                                    // use `responseObject` here http://110.164.179.154/node/fintechShare/secure/handShake/?cypher=\(base64String)
                                    print(responseObject)
                                }*/
                                var SV = try! publicKeySV.pemString()
                                SV = SV.replacingOccurrences(of: "\'", with: "\\\'")
                                SV = SV.replacingOccurrences(of: "\"", with: "\\\"")
                                SV = SV.replacingOccurrences(of: "\n", with: "\\n")
                                SV = SV.replacingOccurrences(of: "\r", with: "")
                                let p = "var publicKeySVr = pki.publicKeyFromPem(\'\(SV)\');"
                                self.jsContext.evaluateScript(p)
                                
                                let cypher = self.jsContext.evaluateScript("publicKeySVr.encrypt(buffer, 'RSA-OAEP');")
                                var dataStr = cypher?.toString()
                                
                                //var l: String  = String(describing: dataStr)
                                
                                self.postData("http://110.164.179.154/node/fintechShare/secure/handShake/", postData: dataStr!) { responseString, error in
                                    guard let responseString = responseString, error == nil else {
                                        print(error ?? "Unknown error")
                                        return
                                    }
                                    
                                    //print(responseString)
                                    var strCy = responseString
                                    strCy = strCy.replacingOccurrences(of: "\'", with: "\\\'")
                                    strCy = strCy.replacingOccurrences(of: "\"", with: "\\\"")
                                    strCy = strCy.replacingOccurrences(of: "\n", with: "\\n")
                                    strCy = strCy.replacingOccurrences(of: "\r", with: "")
                                    
                                    self.jsContext.evaluateScript("var input = forge.util.createBuffer(\'\(strCy)\','raw');")
                                    self.jsContext.evaluateScript("input.getBytes('Salted__'.length);")
                                    self.jsContext.evaluateScript("var salt = input.getBytes(8);")
                                    self.jsContext.evaluateScript("var derivedBytes = forge.pbe.opensslDeriveBytes( pwd, salt, 32);")
                                    self.jsContext.evaluateScript("var buffer = forge.util.createBuffer(derivedBytes);")
                                    self.jsContext.evaluateScript("var key = buffer.getBytes(24);")
                                    self.jsContext.evaluateScript("var iv = buffer.getBytes(8);")
                                    self.jsContext.evaluateScript("var decipher = forge.cipher.createDecipher('3DES-CBC', key);")
                                    self.jsContext.evaluateScript("decipher.start({iv: iv});")
                                    self.jsContext.evaluateScript("decipher.update(input);")
                                    self.jsContext.evaluateScript("var result = decipher.finish();")
                                    let x = self.jsContext.evaluateScript("decipher.output")

                                    print(x?.toString()!)

                                   
                                }
                            }
                        }
                        catch let error as NSError {
                            print(error.localizedDescription)
                        }
                        
                    }
                })
                task.resume()
            }
            }
                
        } else {
            // Fallback on earlier versions
            print("error can create rsa Key")
        }
        
    }
    
    func sendRequest(_ url: String, parameters: [String: String], completion: @escaping ([String: Any]?, Error?) -> Void) {
        var components = URLComponents(string: url)!
        components.queryItems = parameters.map { (key, value) in
            URLQueryItem(name: key, value: value)
        }
        components.percentEncodedQuery = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        let request = URLRequest(url: components.url!)
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,                            // is there data
                let response = response as? HTTPURLResponse,  // is there HTTP response
                (200 ..< 300) ~= response.statusCode,         // is statusCode 2XX
                error == nil else {                           // was there no error, otherwise ...
                    completion(nil, error)
                    return
            }
            
            let responseObject = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            completion(responseObject, nil)
        }
        task.resume()
    }
    func postData(_ strurl: String,postData:String, completion: @escaping (String?, Error?) -> Void) {
        print(postData)
        let url = URL(string: strurl)!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        //let json: [String: Any] = postData
        //let jsonData = try? JSONSerialization.data(withJSONObject: json)
        var dict = Dictionary<String,Any>()
        dict = ["cypher": postData]
        var jsdata = NSData()
        do {
            jsdata = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted) as NSData
        } catch  {
            print(error.localizedDescription)
        }
        request.setValue("\(jsdata.length)", forHTTPHeaderField: "Content-Length")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsdata as Data//Data(base64Encoded: postString, options: Data.Base64DecodingOptions.ignoreUnknownCharacters)//postString.data(using: .utf8)//jsonData//postString.data(using: .utf8)
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {                                                 // check for fundamental networking error
                print("error=\(error)")
                return
            }
            
            if let httpStatus = response as? HTTPURLResponse, httpStatus.statusCode != 200 {           // check for http errors
                print("statusCode should be 200, but is \(httpStatus.statusCode)")
                print("response = \(response)")
            }
            
            let responseString = String(data: data, encoding: .utf8)
            print("responseString = \(responseString)")
            
            //let responseObject = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            completion(responseString, nil)
        }
        task.resume()
    }
    
    func load(triket: String, completion: @escaping (String?, Error?) -> Void) {

        /**  let SharedDefaults = UserDefaults.init(suiteName: "group.com.service")!
         SharedDefaults.set(stringDataHS, forKey: chanel)*/
        do {
            let str = triket
            self.jsContext.evaluateScript("var triket = \'\(triket)\';")
            self.jsContext.evaluateScript("var salt = forge.random.getBytesSync(8);")
            self.jsContext.evaluateScript("var derivedBytes = forge.pbe.opensslDeriveBytes(pwd, salt, 32);")
            self.jsContext.evaluateScript("var buffer = forge.util.createBuffer(derivedBytes);")
            self.jsContext.evaluateScript(" var key = buffer.getBytes(24);")
            self.jsContext.evaluateScript(" var iv = buffer.getBytes(8);")
            self.jsContext.evaluateScript(" var cipher = forge.cipher.createCipher('3DES-CBC', key);")
            self.jsContext.evaluateScript(" cipher.start({iv: iv});")
            self.jsContext.evaluateScript(" cipher.update(forge.util.createBuffer(triket, 'raw'));")
            self.jsContext.evaluateScript(" cipher.finish();")
            self.jsContext.evaluateScript(" var output = forge.util.createBuffer();")
            self.jsContext.evaluateScript(" if(salt !== null) { output.putBytes('Salted__'); output.putBytes(salt);  }")
            self.jsContext.evaluateScript(" output.putBuffer(cipher.output);")
            let data = self.jsContext.evaluateScript("output.getBytes()")
            print(data?.toString()!)
            let dataCypher = data?.toString()
            
            self.postData("http://110.164.179.154/node/fintechShare/secure/load/",postData: dataCypher!){ responseString, error in
                guard let responseObject = responseString, error == nil else {
                    print(error ?? "Unknown error")
                    return
                }
                
                print(responseString)
                
                /*var strCy = responseString
                var se = self.jsContext.evaluateScript("pwd")
                print(se!)
                self.jsContext.evaluateScript("var bytes = forge.util.hexToBytes(\'\(strCy)\');")
                self.jsContext.evaluateScript("var input = forge.util.createBuffer(bytes);")
                self.jsContext.evaluateScript("input.getBytes('Salted__'.length);")
                self.jsContext.evaluateScript("var salt = input.getBytes(8);")
                self.jsContext.evaluateScript("var derivedBytes = forge.pbe.opensslDeriveBytes( pwd, salt, 32);")
                self.jsContext.evaluateScript("var buffer = forge.util.createBuffer(derivedBytes);")
                self.jsContext.evaluateScript("var key = buffer.getBytes(24);")
                self.jsContext.evaluateScript("var iv = buffer.getBytes(8);")
                self.jsContext.evaluateScript("var decipher = forge.cipher.createDecipher('3DES-CBC', key);")
                self.jsContext.evaluateScript("decipher.start({iv: iv});")
                self.jsContext.evaluateScript("decipher.update(input);")
                var res = self.jsContext.evaluateScript("decipher.finish()")
                print(res!.toBool())
                var x = self.jsContext.evaluateScript("decipher.output")
                print(x!)*/
                //let responseObject = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                completion(responseString, nil)
            }
        } catch let error as NSError {
            print(error.localizedDescription)
            
        }

 
    }
    func jsonToString(json: Any)-> String{
        do {
            let data1 =  try JSONSerialization.data(withJSONObject: json, options: JSONSerialization.WritingOptions.prettyPrinted) // first of all convert json to the data
            let convertedString = String(data: data1, encoding: String.Encoding.utf8) // the data will be converted to the string
            return convertedString! // <-- here is ur string
            
        } catch let myJSONError {
            print(myJSONError)
            return myJSONError as! String
        }
        
    }

}
