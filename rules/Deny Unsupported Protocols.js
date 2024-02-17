/*
 This rule will deny unsupported protocols like WSFed, SAML for all OIDC clients
 SAML will be supported only for clients having a metadata allow_saml_protocol=true. 
 This should be the first rule to get executed always.
*/
function (user, context, callback) {
    //Protocol values are available in https://auth0.com/docs/rules/context-object
    //Deny all wsfed requests
    //Deny SAML requests for all OIDC clients. SAML clients will have a client metadata allow_saml_protocol=true
    if ((context.protocol === 'wsfed') || (context.protocol === 'samlp' && !context.clientMetadata.allow_saml_protocol)) {
        debug("WSFed / SAML protocol is not supported for this client.");
        return callback(
          new UnauthorizedError('Unsupported operation'));
     }
    callback(null, user, context);

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[SAML Mapping Rule for Client: ' + context.clientName + ',and user: ' + user.user_id + ']: ' + statement);
        }
    }
}
