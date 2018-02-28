var https        = require('https');
var hmacSha1     = require('hmac_sha1') // require('hmac_sha1');
var EventEmitter = require('events').EventEmitter;
var stream = require('stream');
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

   function CustomError(){
       
       this.messages = {}; // error messages place holder    
   
       
       this.addCustomErrors = function (errors){  // add custom error messages
 
          Object.getOwnPropertyNames(errors).map(function(name){
     
            this.messages[name] = errors[name];
          },this)
       }

       this.CustomError = function(name){// uses built-in Error func to make custom err info
          var err = Error(this.messages['name']);      // take message text
          err['name'] = name;                          // set error name
          return err; 
       }


   }

   function Options (options, vault, args){ // builds request options and confugures user supplied parameters

      vault.consumer_key =  "",    // app's consumer key
      vault.consumer_secret = "",
      vault.cert = "",            // certificate (can be selfsigned)
      vault.key = ""              // private key (used for https encription)
      
      
      var reqHeaders = {       // holds headers of a request
         'accept': "",
         'authorization': "",
         'accept-language': "",
         'content-length': '0' // must be zero when method is POST with no body
      }  
     
      function addUtils() {
         this.missingVal_SBS = {
            consumer_key: 'consumer_key',// Name of consumer key as it stands in OAuth (for SBS), without 'oauth'
                                         // prefix. Used when inserting consumer_key value 
            token: 'token',              // Name of access token param for SBS string. Used for inserting token
            marker: percentEncode("=&"), // "%3D%26" missing value marker for signature base string
            offset: 3                    // Esentialy length of percent encoded "&", we place missing between "="
                                       // and "&" 
        },

        this.missingVal_AHS = { 
           signature:'signature',            
           marker: "=\"\"",             // ="" - missing value marker for authorization header string (AHS) 
           offset: 1                   
        },

        this.SBS_AHS_insert = function(phase, key, value){
            var sbs = this[phase + 'SBS'];     console.log('sbs_ad insert:',phase,sbs)  // sbs of a phase)
            this[phase + 'SBS'] = this.insertKey(sbs, this.missingVal_SBS, key, value); // set key in SBS
          
            // key and value are like in those for SBS                                         
            var ahs = this[phase + 'AH'];        // ah of a phase
            this[phase + 'AH'] = this.insertKey(ahs, this.missingVal_AHS, key , value, true);// set key in AHS

        }, 
     
        this.insertKey = function(insertString, missingVal, keyName, keyValue, ah){
            var str = insertString; 
            var len = (keyName.length + missingVal.marker.length) - missingVal.offset;// calcualte idx from where                                                                                      // we insert the value
            var idx = str.indexOf(keyName);          // take index of the key we search  
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
     
      function addPhaseParams(){      // Adds parametars for each phase we support 
         addUtils.call(this);                  // add utility function that use phase params
         this.apiSBS = '';                     // SBS for api calls
         this.apiAH = '';                      // Ah for api calls
         this.apiHost = '';                    // host we hit for api calls
         this.apiPath = '';                    
         this.apiMethod = '';          
      

         this.legSBS = '';                     // Signature base string for OAuth legs (steps)
         this.legAH = '';                      // Authorization header string
         this.legHost = '';                    
         this.legPath = '';
         this.legMethod = '';
         
         this.verSBS = ''                      // SBS for verify credentials
         this.verAH = '';
         this.verHost = '';
         this.verPath = '';
         this.verMethod = '';
      }
     
     function addFinalParams(){                // Adds parameters that node.js uses when sending a request
        addPhaseParams.call(this)         
        this.host = "";
        this.path = "";
        this.method = "";
        this.headers = "";
        this.key = "";
        this.cert = "";
     }                                   

     addFinalParams.call(options); 
      
     CustomError.call(this);
     this.addCustomErrors({
       twiz: '[twiz-server] ',
       consumerKeyNotSet: "You must provide consumer_key which identifies your app",
       consumerSecretNotSet: "You must provide consumer_secret which identifies your app",
       certNotSet: "You must provide cert (certificate) used in https encription when connecting to twitter.",
       keyNotSet: "You must provide key (private key) used in https encription when connecting to twitter",
       requestNotSet: "You must provide request (read) stream",
       responseNotSet: "You must provide response (write) stream",
     })
     
     this.initOptions = function init(req, res, next){ 
         console.log("in INIT")
                                             // Encompases server logic 
         args.request  = req;
         args.response = res;
         args.next     = next;

         this.setUserParams(args, vault);    // Params needed for this lib to work
         if(this.isPreflight()) return;      // on preflighted requests stop here
         console.log('before getOptions');
         this.getOptions(reqHeaders);        // Options sent in query portion of client request url and headers
         this.setOptions(vault, reqHeaders, options);    // sets options used for twitter request

         this.setAppContext();
     }

   };
   
   Options.prototype = Object.create(EventEmitter.prototype) // link EE prototype
   
   Options.prototype.setUserParams = function(args, vault){
      for(var name in args){
         switch(name){
            case "request":
              this.request = args[name];    // set request stream
            break;
            case "response":
              this.response = args[name];   // set response stream
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

   Options.prototype.checkAllParams = function (vault){
     
      for(var name in vault){
         
         switch(name){
            
            case "key":
               if(!vault[name]) throw this.CustomError('keyNotSet');
            break;
            case "cert":
               if(!vault[name]) throw this.CustomError('certNotSet');
            break;
            case "consumer_key":
               if(!vault[name]) throw this.CustomError('consumerKeyNotSet');
            break;
            case "consumer_secret":
               if(!vault[name]) throw this.CustomError('consumerSecretNotSet');
            break;
            //for now we dont check for this.next (for compatibility with other frameworks)
         }
      }
         if(!this.request)  throw this.CustomError('requestNotSet');
         if(!this.response) throw this.CustomError('responseNotSet');
   }
   
   Options.prototype.getOptions = function(reqHeaders){ // gets params from query portion of request url
      this.sentOptions = url.parse(this.request.url, true).query // parses options sent in client request url
      console.log('sentOptions: ', this.sentOptions);
      
      this.getRequestHeaders(reqHeaders); // gets headers from client request and puts them in reqHeaders
   };

   Options.prototype.getRequestHeaders = function(reqHeaders){ // takes headers from request if header
                                                               // is supported ( is in reqHeaders)
      var sentHeaders = this.request.headers // headers from request stream
      for(var name in reqHeaders){           // omiting content-length, since it must be 0, for POST with no body
         if(sentHeaders.hasOwnProperty(name) && name !== 'content-length') reqHeaders[name] = sentHeaders[name];
      }
      console.log("reqHeaders: " , reqHeaders);
   };

   Options.prototype.setOptions = function(vault, reqHeaders, options){ // Uses params sent in url to set
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

     
  Options.prototype.setAppContext = function(){ // check the framework
      this.app;               // Can be reference to 'this.req.app' when in Express, or 'this' when in Connect
       
      if(this.request.app){            // check express context
         this.app = this.request.app; 
         console.log('express confirmed');
      }
      else if(this.next){              // For connect context just check if there is 'next' function
         EventEmitter.init.call(this); // Call emitter constructor on this object
         this.app = this;              // app is 'this', since we are linked to EventEmitter 
         console.log('Connect confirmed')         
      }
  };
    
  Options.prototype.isPreflight = function() { // has to go as saparate middleware
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

  function OAuth(){
     CustomError.call(OAuth);
     OAuth.addCustomErrors({
        oauthTokenMissing: "oauth_token is missing",
        oauthTokenSecretMissing: "oauth_token_secret is missing"
     })
    

  }

  OAuth.prototype = Object.create(Options.prototype);
  
  OAuth.safeKeepAccessToken = function(tokenObj, vault){ // if we have access token data , keep it in vault
      if(tokenObj){
         this.checkAccessToken(tokenObj);
         vault.accessToken = tokenObj;
      }
      else vault.accessToken = '';
  }
  OAuth.checkAccessToken = function(tokenObj){           // check token object for access token data
 
      if(!tokenObj.oauth_token) {
         throw this.CustomError('oauthTokenMissing')     
      }
      
      if(!tokenObj.oauth_token_secret) {
         throw this.CustomError('oauthTokenSecretMissing');
      } 
   }

   OAuth.prototype.insertConsumerKey = function(vault, options, phase){// insert missing consumer key in 
                                                                       // SBS and AHS

      var consumer_key = options.missingVal_SBS.consumer_key;// get consumer key name (as it stands in OAuth Spec
      var value = vault.consumer_key;                        // Get value of consumer key from vault 
      
      options.SBS_AHS_insert(phase, consumer_key, value)   // insert consumer key to SBS and AHS
   };

   OAuth.prototype.insertAccessToken = function(vault, options, phase){
      var tokenName  = options.missingVal_SBS.token;       // take the key name
      var tokenValue = vault.accessToken.oauth_token;      // take the key value 

      console.log('missingVal_SBS.token: ', options.missingVal_SBS.token) 
      options.SBS_AHS_insert(phase, tokenName, tokenValue); // insert token in SBS and AHS  
   }
   
      
   OAuth.prototype.insertSignature = function(vault, options, phase){ // creates signature and 
      var accessToken = vault.accessToken;                               // inserts it
                                                                         // into Authorization Header string
      var HmacSha1 = new hmacSha1('base64');                             // Create new hmac function
      var signingKey = percentEncode(vault.consumer_secret) + "&";       // Prepare consumer_secret

      if(phase === 'api') signingKey = signingKey + percentEncode(accessToken.oauth_token_secret); 
                                                                                              // on api calls
                                                                                              // add token_secret

      var sbs = options[phase + 'SBS'];                           // get SBS
      var signature = HmacSha1.digest(signingKey, sbs);          // calculates oauth_signature

      
      var ahs = options[phase + 'AH'];                            // get ah
      var key = options.missingVal_AHS.signature;                // take key name 
      options[phase + 'AH'] = options.insertKey(ahs, options.missingVal_AHS, key, signature, true); 
                                                                         // inserts signature into AHS
      console.log(" SIGNATURE: " + signature);
      console.log(" AHS: " + options[phase + 'AH']); 
   };

   OAuth.prototype.finalizeOptions = function(options, phase){ // sets final options that we send in twitter req 
      options.host    = options[phase + 'Host']; // when you start sending pref+ Host in  queryString
      options.path    = options[phase + 'Path'];
      options.method  = options[phase + 'Method'];
 
      options.headers.authorization = options[phase + 'AH']; // sets authorization header 
  }

   function TwitterProxy(req, res, next){ // req, res, options
     //  this.request  = req;
      this.response = res;
      this.next     = next;
     
      this.headerFix = {
        textHtml : 'application/x-www-url-formencoded;charset=utf-8'
      }

      this.twtRequest;
      this.twtResponse;

   }   

   TwitterProxy.prototype.createTwtRequest = function(options, twtResponseHandler){ // creates request we'll send
      this.twtRequest = https.request(options, function(res){                       // to Twitter
          this.twtResponse = res;
          twtResponseHandler();
      }.bind(this))
   }

  /* TwitterProxy.prototype.twtRequestSetBody = function(vault){ // 'api' requests
       if(vault.body){
          this.twtRequest.setHeader('TransferEncoding','chunked');
          this.twtRequest.write(vault.body);
       {  
   }
  */

   TwitterProxy.prototype.twtRequestOnError = function(){ // all

      this.twtRequest.on('error', function(err){ this.next(err) }.bind(this))
   }

   TwitterProxy.prototype.twtRequestSend = function(twtRequest){     // all

      this.twtRequest.end(function(){

            console.log('proxyRequest.headers:');
            console.log('pR.content-type:', this.twtRequest.getHeader('content-type'))
            console.log('pR.TE:', this.twtRequest.getHeader('TE'));
            
            console.log('pR.content-length:', this.twtRequest.getHeader('content-length'))
            console.log('pR.content-encoding', this.twtRequest.getHeader('content-encoding'))

            console.log('pR.transfer-encoding:', this.twtRequest.getHeader('transfer-encoding'))// shouldnt have one
            
      }.bind(this)); // sends request to twtter


   }

   TwitterProxy.prototype.twtResponseOnFailure = function(phase){ // all responce
       console.log('statusCode:', this.twtResponse.statusCode );
      if(this.twtResponse.statusCode === 200) return false;

      console.log('in onFailure')
      console.log('content-type (before) : ', this.twtResponse.headers['content-type'])
      
      if(phase ==='leg'){          // when error is some oauth
                                   // leg, twitter send content-type=application/json
                                   // but body is actually form encoded
        this.twtResponse.headers['content-type'] = this.headerFix.textHtml; // Fix for twitter's incorect content-type,
      }                                                               // on entitty-body that is actualy 
                                                                     // formencoded
      this.twtResponse.on('data', function(data){
        console.log('failure body:', data.toString('utf8'))  
      })

      console.log('content-type: ', this.twtResponse.headers['content-type'])

      this.response.writeHead(this.twtResponse.statusCode, this.twtResponse.statusMessage, this.twtResponse.headers)// redo with     write so it doesnt reset previously sett headers (from other middlewears)

      this.twtResponse.pipe(this.response);              // pipe response to clent response
        console.log('before errorHandler');
      this.twtResponse.on('error', function(err){console.log('twtResponse error:', err); this.next()}.bind(this));     return true
   }
   
   TwitterProxy.prototype.twtResponsePipeBack = function(action){  // all (not access token)
         
         //this.twtResponseReceiveBody(vault, enc); // receives body to vault in specified encoding
         //this.twtResponseOnEnd(handler);          // on response end invoke handler
      
         /* function handler(){
            this.twtResponseParseBody(vault);     // make it as json string
 
            this.setResponseHeaders();            //
            this.twtDataPipe(vault, enc);
         }.bind(this); 
         */
       console.log(' pipeBack action:', action)
         if(action === 'request_token') this.setRequestTokenHeaders(); // apply content-type fix
         
         this.setResponseHeaders();
         
         this.twtResponse.pipe(this.response); //  
   }
   TwitterProxy.prototype.setRequestTokenHeaders = function(){

      var headers = this.twtResponse.headers;
      headers['content-type'] = this.headerFix.textHtml; // aplly header fix for twitter's incorect content-type
      console.log('headers[content-type]: ', headers['content-type']);
   } 

   TwitterProxy.prototype.setResponseHeaders = function(){  // all responce (exept access_token) 
      
      this.response.writeHead(this.twtResponse.statusCode, 
                              this.twtResponse.statusMessage, 
                              this.twtResponse.headers);
      console.log('headers writen:', this.twtResponse.headers)
   }
 /*  TwitterProxy.prototype.twtDataPipe = function(vault, enc){
      
      var twtDataStream = stream.PassThrough();
      twtDataStream.end(Buffer.from(vault.twtData, enc)) // write to stream
      twtDataStream.pipe(this.response)                      // pipe back to client

      twtDataStream.on('error', function(err){
           this.response.end();                              // prevent memory leaks
           this.next(err);
      }.bind(this));
   }
 */
   TwitterProxy.prototype.twtResponseOnError = function(){ // all response
      this.twtResponse.on('err', function(err){
           console.log('twtResponse error: ', err);
           this.next(err)
      }.bind(this))
   }
   
   TwitterProxy.prototype.twtResponseReceiveBody = function(vault, encoding){ // all access_token
       console.log('twtResponseReceiveBody')
      vault.twtData = '';
      this.twtResponse.on('data', function(data){
         console.log(" twitter responded: ", data.toString('utf8'));
         vault.twtData += data.toString(encoding);                    // makes 
      })
   }

   TwitterProxy.prototype.twtResponseOnEnd = function(func){

       this.twtResponse.on('end', func);
   }

   TwitterProxy.prototype.twtResponseParseBody = function(vault){ // 

      var data = vault.twtData; console.log('vault.twtData:', vault.twtData)
      try{                                    // try parsing access token
        data = JSON.parse(data);  
      }
      catch(er){ 
        data = url.parse("?" + data, true).query // simple hack for parsing twitter's access token 
                                                               // string (that is form-encoded)
        console.log('url parsed => data:', data);
      }
      
      vault.twtData = data ; 
      
   }
   

   function PhaseBuilder(options, vault, args){
     
     Options.call(this, options, vault, args);

     this.leg = ['request_token', '', 'access_token'] // Oauth leg (step) names
     
     this.phases = {
       leg: {                                 
          toString: function(){ return 'leg' },
          requestToken: this.leg[0],
          accessToken : this.leg[2] 
       },
       
       api:{
          toString: function(){ return 'api' },
          plain: 'api',
          verifyCred: 'ver',
          accessProtectedResorces: 'APR'  
       }   
     }

     this.Phase = function Phase(){
       this.name   = '';
       this.action = '';
       this.signRequest = '';
       this.proxyRequest = '';
     }

     
     this.legPhase = new this.Phase();
     this.apiPhase = new this.Phase();

     this.initPhases = function (req, res, next){
     
        this.initOptions(req, res, next); // initOptions
        this.setPhases(options);
     }

   }

   PhaseBuilder.prototype = Object.create(Options.prototype); 
  
   PhaseBuilder.prototype.setPhases = function(options){ 
     
      this.setPhase(this.legPhase, this.phases.leg, this.getCurrentLegAction(options)) // set current phase
      this.setPhase(this.apiPhase, this.phases.api, this.phases.api.plain)         // set next phase
      
   }

   PhaseBuilder.prototype.setPhase = function(phase, name, action){ // setlegPhase(this.phases.leg,
                                                                         // this.phases.leg.requestToken
      phase.name   = name.toString();
      phase.action = action; 
      phase.signRequest = new OAuth();
      phase.proxyRequest = new TwitterProxy(this.request, this.response, this.next);
   }

   PhaseBuilder.prototype.getCurrentLegAction = function(options){
      console.log('legPath: ', options.legPath) 
      var path = options.legPath;
      var action;
  
      for(var i = path.length; i >= 0; i--){
        if(path.charAt(i) === '/'){
          action = path.substring(i+1);
          break;
        }
      }
  
      this.isLegActionValid(action);
      return action;
   }
   
   PhaseBuilder.prototype.isLegActionValid = function(action){ 
  
      var valid =  (action === this.leg[0] || action === this.leg[2]);
      if(!valid) throw new Error('OAuth leg sent by client not recoginized')
  
   } 

    //*/
   function PhaseConfigurator (args){

      var vault = {};
      var options = {};
      
      PhaseBuilder.call(this, options, vault, args)

      this.alternator = {
         run: function(tokenObj){

             OAuth.safeKeepAccessToken(tokenObj, vault); // safe keep token in vault
             this.switch_()
         },
         switch_: function(){

            if(vault.accessToken) this.apiPhase.run();
            else this.legPhase.run() ;
         },
         legPhase: this.legPhase,
         apiPhase: this.apiPhase
      }


      this.startAlternator  = function(req, res, next){ console.time('t')
         this.initPhases(req, res, next);
         this.configurePhases(this.alternator.legPhase.action, options, vault);        
         this.emitPhaseEvents(this.alternator);
      }

   }

   PhaseConfigurator.prototype = Object.create(PhaseBuilder.prototype)

   PhaseConfigurator.prototype.configurePhases = function (action, options, vault){
      

      if(action === this.leg[0]) // request_token 
       this.addRequestTokenRun(this.alternator, options, vault); 
 
      if(action === this.leg[2]){ // access_token
       this.promisifyAccessTokenRun(this.alternator, options, vault);
      }
   }      
      
   PhaseConfigurator.prototype.addRequestTokenRun = function(alternator, options, vault){

      var legPhase = alternator.legPhase;
      var apiPhase = alternator.apiPhase;

      legPhase.run = function(){
         console.log('leg.phase run: ', this.name, this.action)
         this.signRequest.run(this.name);
         this.proxyRequest.run(this.name, this.action);
      } 
      
      legPhase.signRequest.run = function(phase){
                                                    // new OAuth
  
         this.insertConsumerKey(vault, options, phase);
         this.insertSignature(vault, options, phase);
         this.finalizeOptions(options, phase);
      }
 
      legPhase.proxyRequest.run = function(phase, action){         
         
         this.sendRequest(this.handleResponse.bind(this, phase, action));
      }
   
      legPhase.proxyRequest.handleResponse =  function(phase, action){   // Handle response from twitter
             console.log('twtResponse content-type: ', this.twtResponse.headers['content-type']);
             console.log('twtResponse statusCode: ', this.twtResponse.statusCode);
             console.log('twtResponse statusMessage: ', this.twtResponse.statusMessage);
             console.log('twtResponse headers: ', this.twtResponse.headers);
             this.twtResponse.on('data',function(data){
                 console.log('in data Event (request_token)')
                 console.log(data.toString('utf8'))
             })
             
             this.twtResponseOnError();                            // Handle any response errors
             if(this.twtResponseOnFailure(phase)) return;          // if response didn't have desired outcome
         
             console.log('before PipeBack')
             this.twtResponsePipeBack(action);
             this.twtResponse.on('end', function(){console.log(action + ' ENDED'); console.timeEnd('t')}.bind(this))
      }
  
      legPhase.proxyRequest.sendRequest = function(twtResponseHandler){
        console.log('request sent with Options:' , options); 
         this.createTwtRequest(options, twtResponseHandler); // Create request we send to twitter
         this.twtRequestOnError();                                // Handle any request error
         this.twtRequestSend();                                   // Send request 
      }           
         
      apiPhase.run = legPhase.run; // same phase run
            
      apiPhase.signRequest.run = function(phase){
           
         this.insertConsumerKey(vault, options, phase);
         this.insertAccessToken(vault, options, phase);
         this.insertSignature(vault, options, phase);
         this.finalizeOptions(options, phase);
      }      
 
      apiPhase.proxyRequest.run = legPhase.proxyRequest.run
      apiPhase.proxyRequest.handleResponse = legPhase.proxyRequest.handleResponse // same response handler 
      apiPhase.proxyRequest.sendRequest = legPhase.proxyRequest.sendRequest // same response handler 
    
  }

  PhaseConfigurator.prototype.addAccessTokenRun = function(resolve, alternator, options, vault){

      this.addRequestTokenRun(alternator, options, vault);
     
      var legPhase = alternator.legPhase;
      var apiPhase = alternator.apiPhase;
      console.log('access_token run')
     legPhase.proxyRequest.handleResponse = function(phase, action){ // redefine handle response for legPhase
              console.log('phase: ', phase, 'action', action);
             console.log('twtResponse content-type: ', this.twtResponse.headers['content-type']);
             console.log('twtResponse statusCode: ', this.twtResponse.statusCode);
             console.log('twtResponse statusMessage: ', this.twtResponse.statusMessage);
             console.log('twtResponse headers: ', this.twtResponse.headers);
                       
         this.twtResponseOnError()
         if(this.twtResponseOnFailure(phase)) return;

         this.twtResponseReceiveBody(vault, 'utf8')
        console.log('before twtResponseOnEnd')
        this.finish = function(){
          
           this.twtResponseParseBody(vault); 
           alternator.run(vault.twtData); // makes alternator run again with possible access token
           resolve(vault.twtData);        // resolves a promise with access token = twtData
        }

        this.twtResponseOnEnd(this.finish.bind(this))
        
      }
   
  }
 
  PhaseConfigurator.prototype.promisifyAccessTokenRun = function(alternator, options, vault ){ //
     this.accessTokenPromise =  new Promise(function(resolve,reject){
        this.addAccessTokenRun(resolve, alternator, options, vault);
     }.bind(this))
  }

  PhaseBuilder.prototype.emitPhaseEvents =  function(alternator){ 
     console.log('this.alternator.legPhase.action: ', alternator.legPhase.action);
     
      switch(alternator.legPhase.action){
        case this.leg[0] : console.log('loadAccessToken')
          this.app.emit(this.eventNames.loadAccessToken, this.alternator.run.bind(this.alternator)) // this.verifyCredentials()
        break;
        case this.leg[2] :  console.log('tokenFound')
          this.app.emit(this.eventNames.tokenFound, this.accessTokenPromise) // pass promise to listener
          alternator.run(); // run the access token leg
        break;
      }
  }
  
  PhaseConfigurator.prototype.eventNames = {                            // Names of events that are emited
         loadAccessToken: 'loadAccessToken',
         tokenFound: 'tokenFound'   
  }


  
   module.exports =  function(args){
     return function twizServer(){
             console.log('NEW Phase Configurator')
        
        var pc = new PhaseConfigurator(args);
        return pc.startAlternator.bind(pc);
     } 
   }

