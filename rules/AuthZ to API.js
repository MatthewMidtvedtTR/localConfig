function (user, context, callback) {
    /* This rule does an authorization check to verify if the Client is allowed to access the requested API.
       This is based on proposals as outlined in https://thehub.thomsonreuters.com/docs/DOC-2975103#jive_content_id_Managing_Access_to_an_Application.
     */

    const apiRequested         = context.request.query && context.request.query.audience;
    const clientAuthorizedAPIs = (context.clientMetadata.allowed_APIs && context.clientMetadata.allowed_APIs.split(",")) || (context.clientMetadata.allow_resource_servers && context.clientMetadata.allow_resource_servers.split(","));
    const clientName           = context.clientName;
    
    debug("clientAuthorizedAPIs: "+clientAuthorizedAPIs);
    debug("apiRequested: "+apiRequested);
    /*
    if audience parameter is not present
    then this rule will not be executed
     */
    if(! apiRequested){
        return callback(null, user, context);
    }

    verifyClientAPIAuthZ().then(successCallback).catch(errorCallBack);

    function errorCallBack(err) {
        callback (new UnauthorizedError(err));
    }
    function successCallback(_) {
        callback(null, user, context);
        return _;
    }

    function verifyClientAPIAuthZ() {
        /*
          Check if Client is allowed to access the corresponding API. Note that
            a. If Client is whitelisted, allow access.
            b. If not, API being requested should be allowed on Client Metadata.
         */
        return new Promise(function(resolve, reject) {
            if( configuration.WHITELIST_API_ACCESS_CLIENT_LIST &&
                configuration.WHITELIST_API_ACCESS_CLIENT_LIST.split(",").includes(clientName)) {
                debug("Client is whitelisted from API AuthZ check");
                return resolve("Client is whitelisted");
            } else if (! (clientAuthorizedAPIs && clientAuthorizedAPIs.includes(apiRequested))) {
                debug("Client is not authorized to access the requested API");
                return reject("You're not authorized to access this API");
            } else {
                return resolve("Client is allowed to access requested API");
            }
        });
    }

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[CGA rule for API access: ' + clientName + ', API requested: '+apiRequested+']: ' + statement);
        }
    }
}