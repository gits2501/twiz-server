var https = require('https');
var hmacSha1 = require('hmac_sha1') // require('hmac_sha1');
var net; // client http lib
var url = require('url');
var HmacSha1 = new hmacSha1();
    console.log(HmacSha1.digest('key','The quick brown fox jumps over the lazy dog'));
var key = "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&";
var baseStr = "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fgits2501.github.io%252FQuoteOwlet%252Findex.html%26oauth_consumer_key%3DZuQzYI8B574cweeef3rCKk2h2%26oauth_nonce%3DakFXZTd1bXB2dWdIYTc0V0pOcldseWsyd1BGRzRMaw%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1504095247%26oauth_version%3D1.0";
console.log(new hmacSha1('base64').digest(key, baseStr));

  // var rqst = request();// returns the object that has access to request API, indirectly through closures.
   var percentEncode = function percentEncode(str){
     return encodeURIComponent(str).replace(/[!'()*]/g, function(c){ // percent encodes unsafe chars, then
                                                                     // it follows RFC3986 and percent encodes
                                                                     // reserved characters in sqere brackets.
         return '%' + c.charCodeAt(0).toString(16);   // takes binary representation of every reserved char
                                                      // , coverts it to hex string char and appends to "%".
     })
   }
   
   function twtOAuthServer (args){
      this.request;  // request stream
      this.responce; // responce stream 

      var vault = {           // sensitive data in private var
        "consumer_key": "",   // app's consumer key
        "consumer_secret": "",
        "cert": "",           // certificate (can be selfsigned)
        "key": ""             // private key (used for https encription)
      }
      
      var reqHeaders = {      // holds headers of a request
         'accept': "",
         'authorization': "",
         'accept-language': "",
         'content-length': '0' // must be zero when method is POST with no body
      }  
     

      var optionUtils = {

        missingVal_SBS:{
          consumer_key: 'consumer_key',// Name of consumer key as it stands in OAuth (for SBS), without 'oauth' 
                                       // prefix
          signature: 'signature',      // Name of sugnature OAuth param for SBS
          token: 'token',              // Name of access token param for SBS string. Used for inserting token val
          marker: percentEncode("=&"), // "%3D%26" missing value marker for signature base string
          offset: 3                    // Esentialy length of percent encoded "&", we place missing between "="
                                       // and "&" 
        },

        missingVal_AHS: { 
          //signature:'signature'            
          marker: "=\"\"",             // ="" - missing value marker for authorization header string (AHS) 
          offset: 1                   
        },

         SBS_AHS_insert: function(pref, key, value){
            var sbs = this[pref + 'SBS'];       // sbs (of some prefix)
            this[pref + 'SBS'] = this.insertKey(sbs, this.missingVal_SBS, key, value); // set key in SBS
          
            // key and value are like in those for SBS                                         
            var ahs = this[pref + 'AH'];        // ah (of some prefix)
            this[pref + 'AH'] = this.insertKey(ahs, this.missingVal_AH, key , value, true);// set key in AHS

         },
     
         insertKey: function(insertString, missingVal, keyName, keyValue, ah){
            var str = insertString; 
            var len = (keyName.length + missingVal.marker.length) - missingVal.offset;// calcualte idx from where                                                                                      // we insert the value
            var idx = str.indexOf(keyName);          // take idx of key we search for  
            // console.log("marker: "+missingVal.marker, "consumer_key: "+ value, "idx: "+idx, "len: "+len) 
            var front = str.slice(0, idx + len); // taking first part 
            var end = str.slice(idx + len )      // taking second part 
            // console.log("front: " + front)
            keyValue =  ah ? percentEncode(keyValue) : percentEncode(percentEncode(keyValue)); 
                                                                                   // single encoding if 
                                                                                   // insertString is AHS
            str = front + keyValue + end;
                                       // Since keys are percent encoded twice (by twitter docs), here we do it 
                                       // also
            console.log("inserted: "+ str); 
            return str; 
        }

      } 

      var api_options = Object.create(optionUtils)   // options used for api calls (linked to optionUtils)
      api.options.apiSBS = '';                       // SBS for api calls
      api_options.apiAH = '';           
      

      var oauth_options = Object.create(api_options) // options for 3-leg oauth requests  
      oauth_options.legSBS = '',                     // signature base string 
      oauth_options.legAH = ''                       // authorization header string
      
      var options = Object.create(oauth_options)     // HTTP server request options
      options.host = "",
      options.path = "",
      options.method = "",
      options.headers = "",
      options.key = "",
      options.cert = ""

   
      this.init =  function init(){          // Encompases server logic
         this.setUserParams(args, vault);    // Params needed for this lib to work
         this.getOptions(reqHeaders);        // Options sent in query portion of client request url and headers
         this.setOptions(vault, reqHeaders, options);        // sets options used for twitter request
         this.oauth('leg');                  // sends to 3-leg authentication       
      //   this.insertSignature(vault,reqHeaders);
      //   this.setOptions(options, vault);           // Options used to set request to twitter api
      }
      this.oauth = function (pref){              // joins the 
          this.sendRequest(vault, options, pref) 
      }
      
   };

   twtOAuthServer.prototype.setUserParams = function(args, vault){

      for(var name in args){

         switch(name){
            case "request":
              this.request = args[name];    // set provided request stream
            break;
            case "responce":
              this.responce = args[name];   // set provided responce stream
            break;
            case "consumer_key":            // confidential app data
              vault.consumer_key = args[name];
            break;
            case "consumer_secret":
              vault.consumer_secret = args[name];
            break;
            case "key":
              vault.key = args[name];       // reference to private key used in https encription 
            break;
            case "cert":
              vault.cert = args[name];      // reference to certificate used in https encription
            break;
            default:
              console.log(name + " not supported")
         }
      }
      
      this.checkAllParams(vault); // checks that all important params are in place
     

   };
   twtOAuthServer.prototype.getOptions = function(reqHeaders){ // gets params from query portion of request url
      this.sentOptions = url.parse(this.request.url, true).query // parses options sent in client request url
      console.log('sentOptions: ', this.sentOptions);
      
      this.getRequestHeaders(reqHeaders); // gets headers from client request and puts them in reqHeaders
   };

   twtOAuthServer.prototype.getRequestHeaders = function(reqHeaders){ // takes headers from request if header
                                                                      // is supported ( is in reqHeaders)
      var sentHeaders = this.request.headers // headers from request stream
      for(var name in reqHeaders){           // omiting content-length, since it must be 0, for POST with no body
         if(sentHeaders.hasOwnProperty(name) && name !== 'content-length') reqHeaders[name] = sentHeaders[name];
      }
      console.log("reqHeaders: " , reqHeaders);
   };
 
   twtOAuthServer.prototype.setEncoding = function(str){
      this.request.setEncoding(str); // maybe you should rememeber what encoding whas, before you change it !
   };
 
   twtOAuthServer.prototype.setOptions = function(vault, reqHeaders, options){ // Uses params sent in url to set
                                                                               // options for request to twiter
                                                                               // and options that are used to 
                                                                               // calculate signature (like SBS)
      for(var name in options){
         if(this.sentOptions[name])
         options[name] = this.sentOptions[name];  // If sentOptions has that 
                                                  // property and it is not undefined
                                                  // Querystring object is not 
                                                  // connected to Object from node 6.0
                                                  // It doesnt have hasOwnProperty(..)
      }

      options.headers = reqHeaders // sets headers
      options.cert = vault.cert;   // sets certificate (https) 
      options.key = vault.key;     // sets private_key used for https encription
      
      console.log(" OPTIONS: ",options);
   };
   
   twtOAuthServer.prototype.sendRequest = function(vault, options, pref){  // inserts consumer key into
                                                                           // signatureBaseString and authorize
                                                                           // header string
       this.setEncoding('utf8');                // Sets encoding to client request stream 
       vault.body = "";
       this.request.on('data', function(data){  // Gets body from request and puts it into vault
           vault.body += data;                  // 
       });

       this.insertConsumerKey(vault, options, pref); // inserts consumer_key into SBS and AHS      
    //   if(pref === 'api') this.insertToken(options, pref)
       this.insertSignature(vault, options, pref);   // inserts signature into AHS
       this.setAuthorizationHeader(options,pref);    // sets AH with given prefix into request options
       
       this.request.on('end', function(){     
              this.send(options);
       }.bind(this)); // Async function loose "this" context, binding it in order not to lose it.
   };
  
   twtOAuthServer.prototype.insertConsumerKey = function(vault, options, pref){// insert missing consumer key in 
                                                                               // SBS and AHS

      var consumer_key = this.missingVal_SBS.consumer_key; // get consumer key name (as it stands in OAuth Specs)
      var value = vault.consumer_key;                   // Get value of consumer key from vault 

      options.SBS_AHS_insert(pref, consumer_key, value) // insert consumer key to SBS and AHS
   };

   twtOAuthServer.prototype.insertToken = function(tokenObj, options, pref){
      var tokename = this.missingVal_SBS.token;       // take the key name
      var value = tokenObj.oauth_token;               // take the key value

  
      options.SBS_AHS_insert(pref, token, value); // insert token in SBS and AHS  
   }
   
      
   twtOAuthServer.prototype.insertSignature = function(vault, options, pref){ // creates signature and 
                                                                         // inserts it
                                                                         // into Authorization Header string
      var HmacSha1 = new hmacSha1('base64');                             // Create new hmac function
      var signingKey = percentEncode(vault.consumer_secret) + "&";  // Prepare consumer_secret
      // var oauth_token_secret for when we accuire it
      var sbs = options[pref + 'SBS'];                              // get SBS
      var ahs = options[pref + 'AH'];                                // get ah
      var signature = HmacSha1.digest(signingKey, sbs);             // calculates oauth_signature

      var key = this.missingVal_AH.signature; // take key name 
      options[pref + 'AH'] = options.insertKey(ahs, options.missingVal_AH, key, signature, true); 
                                                                         // inserts signature into AHS
      console.log(" SIGNATURE: " + signature);
      console.log(" AHS: " + options[pref + 'AH']); 
   };
   
   twtOAuthServer.prototype.setAuthorizationHeader = function(options, pref){ // sets appropriate AH into request
                                                                              // options
      options.headers.authorization = options[pref + 'AH'];
   }

   twtOAuthServer.prototype.send = function(options){
        
        var proxyRequest = https.request(options, function(twtResponce){
 
              twtResponce.setEncoding('utf8');
              twtResponce.pipe(this.responce); // pipe the twitter responce to client responce;

              twtResponce.on('data', function(data){
                console.log(" twitter responded: ", data);
              })

              twtResponce.on('error', function(err){
                     console.log("twt responce error: ", err)
              })
        }.bind(this))
        proxyRequest.on('error', function(err){
            console.log("request to twtiter error: ", err);
        })
        proxyRequest.end(); // sends request to twtter
   };

   twtOAuthServer.prototype.checkAllParams = function (vault){
     
      for(var name in vault){
         
         switch(name){
            case "request":
               if(!this[name]) throw new Error(this.messages.requestNotSet);
            break;
            case "responce":
               if(!this[name]) throw new Error(this.messages.responceNotSet);
            break;
            case "key":
               if(!vault[name]) throw new Error(this.messages.keyNotSet);
            break;
            case "cert":
               if(!vault[name]) throw new Error(this.messages.certNotSet);
            break;
            case "consumer_key":
               if(!vault[name]) throw new Error(this.messages.consumerKeyNotSet);
            break;
            case "consumer_secret":
               if(!vault[name]) throw new Error(this.messages.consumerSecretNotSet);
            break;
         
         }
      }
   }

   twtOAuthServer.prototype.messages = {
       consumerKeyNotSet: "You must provide consumer_key which identifies your app",
       consumerSecretNotSet: "You must provide consumer_secret which identifies your app",
       certNotSet: "You must provide cert (certificate) used in https encription when connecting to twitter.",
       keyNotSet: "You must provide key (private key) used in https encription when connecting to twitter",
       requestNotSet: "You must provide request (read) stream",
       responceNotSet: "You must provide responce (write) stream"
   }
  
   twtOAuthServer.prototype.genHeaderString = function(vault){
      var a = [];
       
      for(var name in this.oauth){
          a.push(name);
      }
      console.log("a; "+ a);
      a.sort(); // aphabeticaly sort array of property names
      var headerString = this.leadPrefix; // Addign "OAuth " in front everthing
      var key;
      var value;
      var keyValue;
      for(var i = 0; i < a.length; i++){  // iterate oauth by sorted way 
         
          key = a[i];                                    // Take the key name

          if(key === "consumer_key") value = vault.consumer_key; // get value from vault
          else value = this.oauth[key];                         // get it from aouth object
      
          key = this.headerPrefix + percentEncode(key);  // addig prefix to every key;
          value = "\"" + percentEncode(value) + "\"";    // adding double quotes to value
          
          keyValue = key + "=" + value;                  // adding "=" between
          if(i !== (a.length - 1)) keyValue = keyValue + ", " // add trailing comma and space, until end

          headerString += keyValue;       
      } 
      console.log("header string: " + headerString); 
   }

   twtOAuthServer.prototype.setNonUserParams = function(){ // sets all "calculated" oauth params 
     // this.setSignatureMethod();
     // this.setNonce();
      this.setTimestamp();
     // this.setVersion();
   }
   
   twtOAuthServer.prototype.genSigningKey = function(csecret, usecret){// Generates signing keys used by hmacSha1 
                                                                  // function.
      var key = "";
      if(cs) key += percentEncode(cs) + "&";
      if(us) key += percentEncode(us) + "&";
        
      return key; 
   }
   
   twtOAuthServer.prototype.setTimestamp = function(){
      this.oauth.timestamp = Date.now() / 1000 | 0;// cuting off decimal part by converting it to 32 bit integer
                                                   // in bitwise OR operation. 
   }

   module.exports =  function(args){
      var r = new twtOAuthServer(args); 
      
      return phantomHead = {
          init : r.init.bind(r)
      } 
   }

