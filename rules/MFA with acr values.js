function (user, context, callback) {

    /* This rule invokes MFA if authorization request specified it using acr_values, and MFA wasn't already done in one of the
     preceding rules. As such, this rule should be triggered as low in the pipeline as possible amongst rules that trigger MFA.
      We're only running this rule for certain protocols.
      Note that there is a provision on password grants to use MFA, the following logic is under the assumption that Products using
      ROP grants wouldn't call for MFA using use acr_values specifically  and expect mfa-required error.
     */

      if(context.request!==undefined && context.request.query!==undefined && context.request.query.prompt === 'none'){
        return callback(null, user, context);
    }

    const clientMFA = context.clientMetadata.require_mfa;
    const userRoles = context.authorization.roles;
    const requiredMFARole = configuration.MFA_ROLE_NAME;
    const user_Multifactor = new Array(user.multifactor);
    const acr_Values = context.request.query && context.request.query.acr_values;
    const completedMfa = context.authentication && !!context.authentication.methods.find(
        (method) => method.name === 'mfa'
    );

    let mfa_enrollment = false;

    //Bypassing MFA if the user has completed MFA and there is no acr_values and the user is not a part of MFArequied role
    if (completedMfa && acr_Values !== 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' && userRoles.indexOf(requiredMFARole) === -1) {
        return callback(null, user, context);
    }

    //checking MFA factors for user, if the user has only email as a factor, then it should not be considered as a MFA factor
    if (user_Multifactor) {
        if (user_Multifactor.length === 1) {
            if (user_Multifactor.toString() === "email" || user_Multifactor.toString() === "") {
                mfa_enrollment = false;
            } else { mfa_enrollment = true; }
        } else {
            mfa_enrollment = true;
        }
    }




    //if a connection is a federated connection MFA will not trigger
    if ((context.connection === configuration.PING_CONNECTION)) {
        return callback(null, user, context);
    }

    /*MFA will trigger if the protocol is either 'oidc-basic-profile' or 'oidc-hybrid-profile' or 'oidc-implicit-profile' AND clientMFA is true or user has MFA role 
    or user has mfa factor other than email or acr values in the authz request
    **/

    if (((context.protocol === 'oidc-basic-profile') || (context.protocol === 'oidc-hybrid-profile') || (context.protocol === 'oidc-implicit-profile')) &&
        ((clientMFA === 'true') || (userRoles.indexOf(requiredMFARole) !== -1) || (mfa_enrollment) || (context.request.query.acr_values && context.request.query.acr_values === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'))) {
        console.log("Triggering MFA as requested in the authorization request, current protocol is: " + context.protocol);
        context.multifactor = {
            provider: 'any',
            allowRememberBrowser: false
        };
    }
    return callback(null, user, context);

}