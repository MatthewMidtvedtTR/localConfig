function (user, context, callback) {
const isAcceptedProtocol = context.protocol === 'oidc-basic-profile' || context.protocol === 'oidc-hybrid-profile' || context.protocol === 'oidc-implicit-profile';
    const clientMFA = context.clientMetadata.require_mfa;
    const userRoles = context.authorization.roles;
    const requiredMFARole = configuration.MFA_ROLE_NAME;
    const user_Multifactor = new Array(user.multifactor);
    const alwaysUse = user.app_metadata.alwaysUseMFA;
    const clientAdaptiveMFAEnrollment = context.clientMetadata.MFA ? JSON.parse(context.clientMetadata.MFA) : false;
    const adaptiveMFAResult = (() => {
        if (context.clientMetadata.MFA === undefined) {
            return false;
        }
        const authenticationCodes = [context.riskAssessment.assessments.UntrustedIP.code, context.riskAssessment.assessments.NewDevice.code, context.riskAssessment.assessments.ImpossibleTravel.code];
        const foundMatchOfCodes = clientAdaptiveMFAEnrollment.codes !== undefined ? clientAdaptiveMFAEnrollment.codes.some( e => authenticationCodes.includes(e)) : false;
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
        const confidenceOfAuthenticationPolicy = clientAdaptiveMFAEnrollment.riskTolerance;
        const thresholdMet = clientAdaptiveMFAEnrollment.riskTolerance !== undefined ? confidenceOfAuthenticationPolicy >= confidenceOfAuthentication : false;
        if(foundMatchOfCodes || thresholdMet){
            return true;
        }
        return false;
    })();
    let mfa_enrollment = false;
    if (user_Multifactor) {
        if (user_Multifactor.length === 1) {
            if (user_Multifactor.toString() === "email" || user_Multifactor.toString() === "") {
                mfa_enrollment = false;
            } else { mfa_enrollment = true; }
        } else {
            mfa_enrollment = true;
        }
    }

    if (isAcceptedProtocol && clientMFA === 'true' || userRoles.indexOf(requiredMFARole) !== -1 || mfa_enrollment && adaptiveMFAResult || mfa_enrollment && !clientAdaptiveMFAEnrollment || alwaysUse === 'true' || context.acrValues === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor') {
        context.multifactor = {
            provider: 'any',
            allowRememberBrowser: !adaptiveMFAResult
        };
    }
    return callback(null, user, context);
}