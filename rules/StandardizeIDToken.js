/*
 This rule is to create the ID token as outlined in the CIAM User Profile document: https://thehub.thomsonreuters.com/docs/DOC-2977259
 Any attributes that aren't required to be put in the ID Token is 'deleted' from the user json object.
*/
function (user, context, callback) {

    const namespace = configuration.NAMESPACE;
    const pingConn = configuration.PING_CONNECTION;
    const hasMultipleIdentities = user.identities && user.identities.length > 1;
    const productAssetID = context.clientMetadata.assetID;

    let currentUser = {};

    if (context.connection === pingConn) {
        if (user.federated_provider_id) { // If the federated profile isn't linked, federated details will be available at root level
            currentUser = user;
        } else {
            if (hasMultipleIdentities && user.identities[1].profileData) {
                currentUser = user.identities[1].profileData;
            }
        }
        if (currentUser.federated_provider_id) {
            context.idToken[namespace + 'federated_user_id'] = currentUser.federated_user_id;
            context.idToken[namespace + 'federated_provider_id'] = currentUser.federated_provider_id;
            context.accessToken[namespace + 'federated_user_id'] = currentUser.federated_user_id;
            context.accessToken[namespace + 'federated_provider_id'] = currentUser.federated_provider_id;
        }
    } else {
        // Only set password updated at for non federated connection
        const password_updated_at = user.last_password_reset || user.created_at;  
        context.idToken[namespace + 'password_updated_at'] = password_updated_at; 
        debug(namespace + 'password_updated_at=' + context.idToken[namespace + 'password_updated_at']);
    }

    if (hasMultipleIdentities) {
        context.idToken[namespace + 'linked_data'] = user.app_metadata.linked_data;
        context.accessToken[namespace + 'linked_data'] = user.app_metadata.linked_data;
    }

    //If using OOTB registration page, "given_name" & "family_name" attributes aren't populated by default, but default "assumed" values are put for "name" and "nickname" attributes.
    //The following block removes "name" and "nickname" attributes, if "given_name" & "family_name" attributes are known.
    if (user.family_name && user.given_name) {
        delete user.name;
        delete user.nickname;
    }

    //Legacy data, if present for a migrated profile, is only added to the ID Token if "profile" scope was present in the authorization request.
    if ((user.app_metadata && user.app_metadata.legacy_data) && (context.request.query && context.request.query.scope && context.request.query.scope.indexOf('profile') !== -1)) {
        context.idToken[namespace + 'legacy_data'] = user.app_metadata.legacy_data;
    }

    //euid is put by default to the access tokens and id tokens.
    if (user.app_metadata && user.app_metadata.euid) {
        context.idToken[namespace + 'euid'] = user.app_metadata.euid;
        context.accessToken[namespace + 'euid'] = user.app_metadata.euid;
    }

    //assetID added to the token as custom claim.If the value is present then put the original else put 000000
    if (productAssetID) {
        context.idToken[namespace + 'assetID'] = productAssetID;
        context.accessToken[namespace + 'assetID'] = productAssetID;
    } else {
        context.idToken[namespace + 'assetID'] = "000000";
        context.accessToken[namespace + 'assetID'] = "000000";
    }

    callback(null, user, context);
  
    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[StandardizeIDToken rule : ' + context.clientName + ',and user: ' + user.user_id + ']: ' + statement);
        }
    }
}
