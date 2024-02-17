/*
  This rule adds additional data to user profiles, provided the account doesn't have the corresponding details already.
  Currently this rule checks for euid and ownership [for federated profiles only], as specified in
  https://thehub.thomsonreuters.com/docs/DOC-2993440#jive_content_id_User_Identifier_userId and
  https://thehub.thomsonreuters.com/docs/DOC-2977259#jive_content_id_Application_Metadata_app_metadata.
*/
function (user, context, callback) {
    let ManagementClient = require('auth0@2.23.0').ManagementClient;
    const management = new ManagementClient({
        domain: auth0.domain,
        clientId: configuration.CLIENT_ID,
        clientSecret: configuration.CLIENT_SECRET
    });

    let uuid = require("uuid");
    const isAccountLinkingBypass = (context.isAccountLinkingRedirect === true);

    user.app_metadata = user.app_metadata || {};
    const pingConn = configuration.PING_CONNECTION;

    let needsUpdate = false;
    var user_data = user_data || {};
    let profileNeedsUpdate = false;

    //Checking if the account is linked or not

    const hasMultipleIdentities = user.identities && user.identities.length > 1;
    if (context.connection === pingConn && hasMultipleIdentities) {
        if ((user.identities[1].profileData.name) && (!user.name || user.name !== user.identities[1].profileData.name)){
            profileNeedsUpdate = true;
            user_data.name = user.identities[1].profileData.name;
        }
        if ((user.identities[1].profileData.given_name) && (!user.given_name || user.given_name !== user.identities[1].profileData.given_name)) {
            profileNeedsUpdate = true;
            user_data.given_name = user.identities[1].profileData.given_name;
        }
        if ((user.identities[1].profileData.family_name) && (!user.family_name  || user.family_name !== user.identities[1].profileData.family_name)) {
            profileNeedsUpdate = true;
            user_data.family_name = user.identities[1].profileData.family_name;
        }

    }

    // The following if block(s) checks if details are missing from the user profile, and populates "user" object correspondingly.
    if(shouldVerifyMetadataInCurrentContext()) {
        if (!user.app_metadata.euid) {
            user.app_metadata.euid = uuid();
            needsUpdate = true;
            debug("EUID is missing");
        }
        if (!user.app_metadata.owning_entity && context.connection === pingConn) {
            user.app_metadata.owning_entity = {};
            user.app_metadata.owning_entity.entity_type = 'customer';
            user.app_metadata.owning_entity.customer_id = user.federated_provider_id;
            needsUpdate = true;
            debug("Ownership is missing");
        }
    }

    // If details were found to be missing from the user profile, the following block calls management api to update/enrich  user profile
    // with missing data.
    if (needsUpdate) {
        debug("Calling management api to update profile");
        return auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
            .then(() => {
                debug("Management api call completed successfully");
                callback(null, user, context);
            })
            .catch((err) => {
                console.error("unexpected error while calling management api for enriching profile with id " + user.user_id + ": " + err);
                callback(err, user, context);
            });
    }

    //if ther are any mismatch of attributes between local account federated account, make a mgmt api call to update the local account
    if (profileNeedsUpdate) {
        debug("Calling management api to update local profile");
        var params = { id: user.user_id };
        management.updateUser(params, user_data).then(() => {
            debug("Management api call completed successfully");
            callback(null, user, context);
        })
            .catch((err) => {
                console.error("unexpected error while calling management api for enriching profile with id " + user.user_id + ": " + err);
                callback(err, user, context);
            });

    }
    callback(null, user, context);

    /**
     * We want to update app_metadata wherever necessary for all local accounts, and to federated accounts only if not in account linking context.
     * Refer CIAM-1329 for more details.
     * @returns {boolean}
     */
    function shouldVerifyMetadataInCurrentContext() {
        const isFederatedAccount =  (user.connection !== "Username-Password-Authentication" &&
            user.federated_provider_id !== undefined &&
            user.federated_user_id !== undefined) === true;
        debug("Is the account " + user.user_id + " federated? :" + isFederatedAccount);
        const shouldVerifyMetadata = (!isFederatedAccount  || (isFederatedAccount && !isAccountLinkingBypass));
        debug("Should verify metadata? " + shouldVerifyMetadata);

        return shouldVerifyMetadata;
    }

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[Enrich profile rule for user: ' + user.user_id + ']: ' + statement);
        }
    }

}
