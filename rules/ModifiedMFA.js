function (user, context, callback) {

    /* This rule invokes MFA if authorization request specified it using acr_values, and MFA wasn't already done in one of the
     preceding rules. As such, this rule should be triggered as low in the pipeline as possible amongst rules that trigger MFA.
      We're only running this rule for certain protocols.
      Note that there is a provision on password grants to use MFA, the following logic is under the assumption that Products using
      ROP grants wouldn't call for MFA using use acr_values specifically  and expect mfa-required error.
     */
    if (context.completedMfa && context.acrValues !== 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' || context.connection === configuration.PING_CONNECTION) {
        return callback(null, user, context);
    }

    const ruleName = 'MFA with acr values';
    const clientMFA = context.clientMetadata.require_mfa;
    const userRoles = context.authorization.roles;
    const requiredMFARole = configuration.MFA_ROLE_NAME;
    const user_Multifactor = new Array(user.multifactor);
    const alwaysUse = user.app_metadata.alwaysUseMFA;
    const userNeedsMFA = context.acrValues !== 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' || userRoles.indexOf(requiredMFARole) === 1 || clientMFA;
    const adaptiveMFAResult = AdaptiveMFA();
    let mfa_enrollment = false;
    //user is enrolled or not
    if (user_Multifactor) {
        if (user_Multifactor.length === 1) {
            if (user_Multifactor.toString() === "email" || user_Multifactor.toString() === "") {
                mfa_enrollment = false;
            } else { mfa_enrollment = true; }
        } else {
            mfa_enrollment = true;
        }
    }

    //to stop the user from being forced to enroll in Adaptive MFA when risky. This is only on for clients that have an MFA object configuredf. This should be considered to be turned on for all application
    if(!mfa_enrollment){
        return callback(new UnauthorizedError('...'));
    }
    //if we are passed this block we know that we don't have to worry avbout MFA being enabled for a user who is not enrolled or something along those lines.


    /*MFA will trigger if the protocol is either 'oidc-basic-profile' or 'oidc-hybrid-profile' or 'oidc-implicit-profile' AND clientMFA is true or user has MFA role
    or user has mfa factor other than email or acr values in the authz request
    **/

    if (((context.protocol === 'oidc-basic-profile') || (context.protocol === 'oidc-hybrid-profile') || (context.protocol === 'oidc-implicit-profile')) &&
        ((clientMFA === 'true') || (userRoles.indexOf(requiredMFARole) !== -1) || (mfa_enrollment && adaptiveMFAResult) || alwaysUse || (context.acrValues === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'))) {
        //context.log("Triggering MFA as requested in the authorization request, current protocol is: " + context.protocol, ruleName);
        context.multifactor = {
            provider: 'any',
            allowRememberBrowser: false //THIS MUST BE CHANGED BACK TO TRUE
        };
    }
    return callback(null, user, context);

    function AdaptiveMFA() {
        if (context.clientMetadata.MFA === undefined) {
            return false;
        }
        const MFA = JSON.parse(context.clientMetadata.MFA);
        const authenticationCodes = [context.riskAssessment.assessments.UntrustedIP.code, context.riskAssessment.assessments.NewDevice.code, context.riskAssessment.assessments.ImpossibleTravel.code];
        const foundMatchOfCodes = MFA.codes !== undefined ? MFA.codes.some( e => authenticationCodes.includes(e)) : false;
        const confidenceOfAuthentication = (() => {
            switch (context.riskAssessment.confidence) {
                case 'low': //high risk
                    return 1;
                case 'medium':
                    return 2;
                case 'high': //low risk
                    return 3;
                default:
                    return 1; //neutral
            }
        })();
        //think about the conversion that is happening here if it is empty. Think about this now.
        const confidenceOfAuthenticationPolicy = MFA.riskTolerance;
        const thresholdMet = MFA.riskTolerance !== undefined ? confidenceOfAuthenticationPolicy >= confidenceOfAuthentication : false;
        if(foundMatchOfCodes || thresholdMet){
            return true;
        }
        return false;
    }
}


//START LOGGING
// user.app_metadata = {};
// user.app_metadata.authenticationCodes = authenticationCodes;
// user.app_metadata.confidenceOfAuthentication = confidenceOfAuthentication;
// user.app_metadata.confidenceOfAuthenticationPolicy = context.clientMetadata.MFA;
// auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
//END LOGGING
