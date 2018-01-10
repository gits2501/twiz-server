var https        = require('https');
var hmacSha1     = require('hmac_sha1') // require('hmac_sha1');
var EventEmitter = require('events').EventEmitter;
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
      this.response; // responce stream 

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
        token: '',          // ONLY for testing
        token_secret:'',    // ONLY for testing

        missingVal_SBS:{
          consumer_key: 'consumer_key',// Name of consumer key as it stands in OAuth (for SBS), without 'oauth' 
                                       // prefix. Used of inserting consumer_key value
          token: 'token',              // Name of access token param for SBS string. Used for inserting token val
          marker: percentEncode("=&"), // "%3D%26" missing value marker for signature base string
          offset: 3                    // Esentialy length of percent encoded "&", we place missing between "="
                                       // and "&" 
        },

        missingVal_AHS: { 
          signature:'signature',            
          marker: "=\"\"",             // ="" - missing value marker for authorization header string (AHS) 
          offset: 1                   
        },

         SBS_AHS_insert: function(pref, key, value){
            var sbs = this[pref + 'SBS'];       // sbs (of some prefix)
            this[pref + 'SBS'] = this.insertKey(sbs, this.missingVal_SBS, key, value); // set key in SBS
          
            // key and value are like in those for SBS                                         
            var ahs = this[pref + 'AH'];        // ah (of some prefix)
            this[pref + 'AH'] = this.insertKey(ahs, this.missingVal_AHS, key , value, true);// set key in AHS

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
      api_options.apiSBS = '';                       // SBS for api calls
      api_options.apiAH = '';                        // Ah for api calls
      api_options.apiHost = '';
      api_options.apiPath = '';
      api_options.apiMethod = '';          
      

      var oauth_options = Object.create(api_options) // options for 3-leg oauth requests  
      oauth_options.legSBS = '';                     // signature base string 
      oauth_options.legAH = '';                       // authorization header string
      oauth_options.legHost = '';
      oauth_options.legPath = '';
      oauth_options.legMethod = '';
      
      var options = Object.create(oauth_options)     // HTTP server request options
      options.host = "";
      options.path = "";
      options.method = "";
      options.headers = "";
      options.key = "";
      options.cert = "";
     
      this.eventNames = {                            // Names of events that are emited
         insertUserToken: 'insertUserToken',
         tokenFound: 'tokenFound'   
      }
   
      this.init = function init(req, res, next){ 
         console.log("in INIT")
                                             // Encompases server logic
         args.request  = req;
         args.response = res;
         args.next     = next ;

         this.setUserParams(args, vault);    // Params needed for this lib to work
         if(this.isPreflight()) return;        // on preflighted requests stop here
         console.log('before getOptions');
         this.getOptions(reqHeaders);        // Options sent in query portion of client request url and headers
         this.setOptions(vault, reqHeaders, options);    // sets options used for twitter request

         this.setAppContext();
         this.currentLeg = this.getCurrentLeg(options); // gets an end string from current path name
         console.log('before onNewListeners')
         this.onNewListeners(this.currentLeg);// set action on listeners we emit              
      }

      this.oauth = function (tokenObj){         
          var pref = 'leg';                  // Prefix or preference var, picks 3-leg dance or twitter api call
          console.log('in oauth')
          if(tokenObj && this.hasUserToken(tokenObj)) { 
             vault.accessToken = tokenObj;    // Put token object in vault
             pref = 'api';                   // Since we have user token, we can go for twitter api call
          }                        

          this.sendRequest(vault, options, pref); // inserts needed tokens, signs the strings, sends request 
          
      }
      
   };
   
   twtOAuthServer.prototype = Object.create(EventEmitter.prototype) // link EE prototype

   twtOAuthServer.prototype.onNewListeners = function(currentLeg){
     console.log('newListeners')
     console.log('currentLeg: ', currentLeg)
      switch(currentLeg){
        case 'request_token': console.log('insertUserToken')
          this.app.emit(this.eventNames.insertUserToken, this.oauth.bind(this)) 
        break;
        case 'access_token':  console.log('tokenFound')
          this.oauth();   // just start access_token search since it wasnt passed on request_token leg   
        break;
      }
   }
  
  twtOAuthServer.prototype.getCurrentLeg = function(options){
     var leg = options.legPath;
     return leg.substr(leg.indexOf('/',1) + 1);// for exemple it gets 'request_token' from '/oauth/request_token' 
  } 
  twtOAuthServer.prototype.hasUserToken = function(tokenObj){
      var error;
      var generalInfo =  this.messages.twiz + this.currentLeg + ' leg: ';
 
      if(!tokenObj.oauth_token) {
         error = JSON.stringify({
            error: generalInfo + this.messages.oaTokenMissing 
         })
         this.next(new Error(error))
         return;
      }
      
      if(!tokenObj.oauth_token_secret) {
         error = JSON.stringify({ 
            error: generalInfo + this.messages.oaTokenSecretMissing 
         })
         this.next(new Error(error));
         return
      } 

      return true; // all tokens are present
   }
   twtOAuthServer.prototype.isPreflight = function() {
    var preflight; console.log('Preflight: method:', this.request.method);
      if (this.request.method == "OPTIONS"){  // Both needs to be plased for PREFLIGHT
        preflight = true;
        console.log("preflight request with OPTIONS");
        this.response.setHeader("Access-Control-Allow-Headers","content-type , authorization");
        this.response.setHeader("Access-Control-Allow-Origin", "https://gits2501.github.io");
      }
      else{
        this.response.setHeader("Access-Control-Allow-Origin","https://gits2501.github.io"); // Other (no preflight) can have just this.
        // this.response.setHeader("Content-Type", "application/json");
        return preflight;
      }

      console.log("URL source: " + this.request.url); console.log("url parsed:", url.parse(this.request.url, true).query)
      console.log("domain: " + this.request.domain)  
      var  body = "";

      this.request.on('end', function(){ console.log("REQ ended")
         console.log("Sent BODY: "+ body)
         console.log("resp headers: " + this.response.headers) 
      }.bind(this))
      
      this.request.on('error', function(err){
        console.log("Error: "+ err);
        this.next(err)
      }.bind(this)) 
      this.response.end();

   
    return preflight;
  
   }
   twtOAuthServer.prototype.setUserParams = function(args, vault){

      for(var name in args){

         switch(name){
            case "request":
              this.request = args[name];    // set provided request stream
            break;
            case "response":
              this.response = args[name];   // set provided responce stream
            break;
            case "next":
              this.next = args[name];
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
              console.log(name + " not supported");
         }
      }
      
      this.checkAllParams(vault); // checks that all important params are in place
     

   };

   twtOAuthServer.prototype.setAppContext = function(){ // check the framework
      this.app;       // Can be reference to 'this.req.app' when in Express, or 'this' when in Connect
       
      if(this.request.app){  // check express context
         this.app = this.request.app; 
         console.log('express confirmed');
      }
      else if(this.next){              // For connect context just check if there is 'next' function
         EventEmitter.init.call(this); // Call emitter constructor on this object
         this.app = this;              // app is 'this', since we are linked to EventEmitter 
                  
      }
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
                                                                               // them along options' prototype
                                                                               // chain if those
                                                                               // param names exists in prototype 
      for(var name in options){
         if(this.sentOptions[name])
         options[name] = this.sentOptions[name];  // If sentOptions has that 
                                                  // property and it is not undefined
                                                  // Querystring object is not 
                                                  // connected to Object from node 6.0
                                                  // It doesnt have hasOwnProperty(..)
      }

      options.headers = reqHeaders    // sets headers
      options.cert    = vault.cert;   // sets certificate (https) 
      options.key     = vault.key;    // sets private_key used for https encription
      
      console.log(" OPTIONS: ",options);
   };
   
   twtOAuthServer.prototype.sendRequest = function(vault, options, pref){  // inserts consumer key into
                                                                           // signatureBaseString and authorize
                                                                           // header string
      this.setEncoding('utf8');                  // Sets encoding to client request stream 
      
      this.receiveRequest(vault, options, pref); // receives client request body
      this.signRequest(vault, options, pref);    // inserts keys and signature
        
      this.transmitRequest(vault, options, pref); // sends request     
   };

   twtOAuthServer.prototype.transmitRequest = function(vault, options, pref){

     if(this.currentLeg === 'AccessProtectedResources'){
        console.log('in APR - sendingRequest');
        this.send(options,pref, vault);
        return;
     }
     
     this.request.on('end', function(){     
          this.send(options, pref, vault);     // Sends request to twitter
     }.bind(this)); // Async function loose "this" context, binding it in order not to lose it.
   }

   twtOAuthServer.prototype.receiveRequest = function(vault, options, pref){
      vault.body = "";
      this.request.on('data', function(data){  // Gets body from request and puts it into vault
          vault.body += data;                   
      });
 
   }
   
   twtOAuthServer.prototype.signRequest = function(vault, options, pref){
      this.insertConsumerKey(vault, options, pref);            // inserts consumer_key into SBS and AHS      

      if(pref === 'api') this.insertToken(vault, options, pref)// insert user access_token in api calls
       
      this.insertSignature(vault, options, pref);              // inserts signature into AHS
      this.finalizeOptions(options, pref);                     // picks final options which are used in request

   }

   twtOAuthServer.prototype.insertConsumerKey = function(vault, options, pref){// insert missing consumer key in 
                                                                               // SBS and AHS

      var consumer_key = options.missingVal_SBS.consumer_key;// get consumer key name (as it stands in OAuth Spec
      var value = vault.consumer_key;                        // Get value of consumer key from vault 
      
      if(this.currentLeg === 'AccessProtectedResources')
      console.log("["+pref+"SBS]", options[pref+ "SBS"]);     
      
      options.SBS_AHS_insert(pref, consumer_key, value)   // insert consumer key to SBS and AHS
   };

   twtOAuthServer.prototype.insertToken = function(vault, options, pref){
      var tokenName  = options.missingVal_SBS.token;       // take the key name
      var tokenValue = vault.accessToken.oauth_token;      // take the key value 

      console.log('missingVal_SBS.token: ', options.missingVal_SBS.token) 
      options.SBS_AHS_insert(pref, tokenName, tokenValue); // insert token in SBS and AHS  
   }
   
      
   twtOAuthServer.prototype.insertSignature = function(vault, options, pref){ // creates signature and 
      var accessToken = vault.accessToken;                                    // inserts it
                                                                         // into Authorization Header string
      var HmacSha1 = new hmacSha1('base64');                             // Create new hmac function
      var signingKey = percentEncode(vault.consumer_secret) + "&";       // Prepare consumer_secret

      if(pref === 'api') signingKey = signingKey + percentEncode(accessToken.oauth_token_secret); 
                                                                                              // on api calls
                                                                                              //, add token_secr 

      var sbs = options[pref + 'SBS'];                           // get SBS
      var signature = HmacSha1.digest(signingKey, sbs);          // calculates oauth_signature

      
      var ahs = options[pref + 'AH'];                            // get ah
      var key = options.missingVal_AHS.signature;                // take key name 
      options[pref + 'AH'] = options.insertKey(ahs, options.missingVal_AHS, key, signature, true); 
                                                                         // inserts signature into AHS
      console.log(" SIGNATURE: " + signature);
      console.log(" AHS: " + options[pref + 'AH']); 
   };
   
   twtOAuthServer.prototype.finalizeOptions = function(options, pref){// actual option are one from 'leg' or 'api'
      options.host    = options[pref + 'Host']; // when you start sending pref+ Host in  queryString
      options.path    = options[pref + 'Path'];
      options.method  = options[pref + 'Method'];

      options.headers.authorization = options[pref + 'AH']; // sets authorization header 
   }
   
   twtOAuthServer.prototype.send = function(options, pref, vault){
        vault.twitterData = ''; // twitter response data (should be Buffer)
        var proxyRequest = https.request(options, function(twtResponse){
 
              twtResponse.setEncoding('utf8');

             console.log('twtResponse content-type: ', twtResponse.headers['content-type']);
             console.log('twtResponse statusCode: ', twtResponse.statusCode);
             console.log('twtResponse statusMessage: ', twtResponse.statusMessage);
             console.log('twtResponse headers: ', twtResponse.headers);
              if(twtResponse.statusCode !== 200 ){ 
                 this.onFailure(twtResponse); return
              }

              this.setResponseHeaders(twtResponse);   

              if(this.currentLeg !== 'access_token')                                                // 
              twtResponse.pipe(this.response);            // pipe the twitter responce to client's responce;
              
              this.receiveBody(twtResponse, vault); 
              if(this.currentLeg === 'access_token')           // see if we are at the end of access_token leg
              twtResponse.on('end', this.accessTokenEnd.bind(this, vault))

              twtResponse.on('error', this.errorHandler.bind(this));

        }.bind(this))

        if(pref === 'api' && vault.body) prexyRequest.write(vault.body); // on api request send body if exists

        proxyRequest.on('error', function(err){
            console.log("request to twtiter error: ", err);
            // this.next(err)
        }.bind(this))

        proxyRequest.end(); // sends request to twtter
   };
   
   twtOAuthServer.prototype.onFailure = function(twtResponse){
      console.log('in onFailure')
      this.response.statusCode = twtResponse.statusCode;
      this.response.statusMessage  = twtResponse.statusMessage;
      twtResponse.pipe(this.response);              // pipe response to clent response
     console.log('before errorHandler');
      twtResponse.on('error', this.errorHandler.bind(this));  // on error, call next(err)
   }

   twtOAuthServer.prototype.errorHandler = function(err){
     console.log('twtResponse error:', err)
     this.next(err);
   }
   twtOAuthServer.prototype.receiveBody = function(twtResponse, vault){
      twtResponse.on('data', function(data){
         console.log(" twitter responded: ", data);
         vault.twitterData += data;                    // makes 
      })
   }
   twtOAuthServer.prototype.accessTokenEnd = function(vault){
     this.accessProtectedResources(vault)
     this.app.emit(this.eventNames.tokenFound, Promise.resolve(vault.twitterData))
   }
   twtOAuthServer.prototype.setResponseHeaders = function(twtResponse){
      // set status line 
      this.response.statusCode    = twtResponse.statusCode;
      this.response.statusMessage = twtResponse.statusMessage;
 
      // hack for twitter's incorect(?) content-type=text/html response in request token step
      if(this.currentLeg === 'request_token') this.response.setHeader('Content-Type','text/plain'); //application                                                                                                  // /x-www-url-e
      this.response.setHeader('Content-Type', twtResponse.headers['content-type']);
   }



   twtOAuthServer.prototype.accessProtectedResources = function(vault){
      this.prepareAccess(vault);
      console.log('in access protected resources')
      this.oauth(vault.accessToken);

   }

   twtOAuthServer.prototype.prepareAccess = function(vault){
      this.currentLeg = 'AccessProtectedResources'; // another api call (but has special name), bcz all 3 legs 
                                                    // were 'hit' up to this point
      var accessToken = vault.twitterData;
      try{                                    // try parsing access token
        accessToken = JSON.parse(accessToken);  
      }
      catch(er){ 
        accessToken = url.parse("?" + accessToken, true).query // simple hack for parsing twitter access token string
        console.log('url parsed accessToken:', accessToken);
      }
      
      vault.accessToken = accessToken;
      
   }
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
            //for now we dont check for this.next (for compatibility with other frameworks)
         }
      }
   }

   twtOAuthServer.prototype.messages = {
       twiz: '[twiz-server] ',
       consumerKeyNotSet: "You must provide consumer_key which identifies your app",
       consumerSecretNotSet: "You must provide consumer_secret which identifies your app",
       certNotSet: "You must provide cert (certificate) used in https encription when connecting to twitter.",
       keyNotSet: "You must provide key (private key) used in https encription when connecting to twitter",
       requestNotSet: "You must provide request (read) stream",
       responceNotSet: "You must provide responce (write) stream",
       oaTokenMissing: "oauth_token is missing",
       oaTokenSecretMissing: "oauth_token_secret is missing"
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
     return function(){
      
        phantomHead = {
           init :function(){
               var r = new twtOAuthServer(args); 
               r.init.apply(r, arguments);
           }
        }
         
        return phantomHead.init
     } 
   }

