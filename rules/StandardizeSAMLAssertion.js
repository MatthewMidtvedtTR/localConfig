/*
 This rule is to configure SAML attribute mapping as mentioned in https://thehub.thomsonreuters.com/docs/DOC-3005231
 This rule will get executed only for SAML requests
*/
function (user, context, callback) {
    const ruleName = 'StandardizeSAMLAssertion';
    if (context.protocol === "samlp") {
        debug("Updating the saml configuration mappings");
        context.samlConfiguration.mappings = {
            "https://tr.com/euid": "app_metadata.euid",
            "given_name": "given_name",
            "family_name": "family_name",
            "email": "email",
            "https://tr.com/federated_user_id": "federated_user_id",
            "https://tr.com/federated_provider_id": "federated_provider_id",
            //Set SAML Subject NameID to euid
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "app_metadata.euid",
            //Add first_name and last_name attributes for Aha
            "first_name": "given_name",
            "last_name": "family_name"
        };
    }
    callback(null, user, context);

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[SAML Mapping Rule for Client: ' + context.clientName + ',and user: ' + user.user_id + ']: ' + statement);
        }
    }
}