function (user, context, callback) {

    if (context.completedMfa && context.acrValues !== 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' || context.connection === configuration.PING_CONNECTION) {
        //condensing code
        //this is also for silent auth calls.
        return callback(null, user, context);
    }

    if(context.protocol === 'redirect-callback' && user.app_metadata.mfa_verification_code !== undefined) {
        return callback(new UnauthorizedError("Failed to complete second factor authentication on risky authentication"));
        //this means that someone called the continue button without actually completing the flow.
        //this will only happen if the user did not complete this flow because THIS IS THE ONLY TIME MFA VERIFICATION CODE IS SET
    }

  	const axiosHttpClient = require('axios@0.19.2');
    const ManagementClient = require('auth0@2.23.0').ManagementClient;
    const management = new ManagementClient({
        domain: auth0.domain,
        clientId: configuration.CLIENT_ID,
        clientSecret: configuration.CLIENT_SECRET
    });
    const isAcceptedProtocol = context.protocol === 'oidc-basic-profile' || context.protocol === 'oidc-hybrid-profile' || context.protocol === 'oidc-implicit-profile';
    const clientMFA = context.clientMetadata.require_mfa;
    const userRoles = context.authorization.roles;
    const requiredMFARole = configuration.MFA_ROLE_NAME;
    const user_Multifactor = new Array(user.multifactor);
    const alwaysUse = user.app_metadata.alwaysUseMFA;
    const userNeedsMFA = context.acrValues === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' || userRoles.indexOf(requiredMFARole) === 1 || clientMFA;
    const adaptiveMFAResult = (() => {
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
        const confidenceOfAuthenticationPolicy = MFA.riskTolerance;
        const thresholdMet = MFA.riskTolerance !== undefined ? confidenceOfAuthenticationPolicy >= confidenceOfAuthentication : false;
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

    if(!mfa_enrollment && adaptiveMFAResult && isAcceptedProtocol) {
        sendVerificationEmail(updateVerificationCode());
        const redirectUrl = new URL('https://google.com'); //This will be a place on the profile app for the OTP code
        context.redirect = {
            url: redirectUrl
        };
    }

    if (isAcceptedProtocol && clientMFA === 'true' || userRoles.indexOf(requiredMFARole) !== -1 || mfa_enrollment && adaptiveMFAResult || alwaysUse === 'true' || context.acrValues === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor') {
        // context.log("Triggering MFA as requested in the authorization request, current protocol is: " + context.protocol, 'MFA with acr values');  //THIS MUST BE CHANGED BACK
        context.multifactor = {
            provider: 'any',
            allowRememberBrowser: false //THIS MUST BE CHANGED BACK TO TRUE
        };
    }

    function updateVerificationCode() {
        // debug('Updating verification code');

        const verificationCode = generateVerificationCode();
        const metadata = {
            mfa_verification_code: verificationCode,
            mfa_verification_code_issued_time: new Date().getTime()
        };

        management.updateUser({ id: user.user_id }, { app_metadata: metadata })
            .then(() => {
                // debug("Management API call completed successfully");
            })
            .catch((err) => {
                // logError(`Unexpected error while calling Management API to update verification code for profile with id ${user.user_id}: ${err}`);
                callback(err, user, context);
            });

        return verificationCode;
    }

    function generateVerificationCode() {
        return (Math.floor(Math.random() * 90000) + 10000).toString();
    }

    function sendVerificationEmail(verificationCode) {
        // debug('Sending verification email');

        const body = {
            recipients: [
                {
                    address: user.email,
                    substitution_data: {
                        verification_code: verificationCode
                    }
                }
            ],
            content: {
                template_id: `verifyYourAccountReturnVisit.${resolveLocale()}`,
                use_draft_template: configuration.ENVIRONMENT === 'ciam-sandbox'
            }
        };

        const options = {
            method: 'POST',
            url: `${configuration.SPARKPOST_API}/v1/transmissions`,
            headers: {
                'Authorization': `${configuration.SPARKPOST_API_KEY}`,
                'X-MSYS-SUBACCOUNT': 29,
                'content-type': 'application/json'
            },
            data: JSON.stringify(body)
        };
        axiosHttpClient(options)
            .then(resp => {
                // debug(resp.data);
            })
            .catch(err => {
                // logError(`Calling Sparkpost to send a verification email for profile: ${err}`);
                callback(err, user, context);
            });
    }

    function resolveLocale() {
        let resultLocale = 'en';

        let userLocale;
        if (user.locale) {
            userLocale = user.locale;
        } else if (user.app_metadata && user.app_metadata.locale) {
            userLocale = user.app_metadata.locale;
        }

        if (userLocale && userLocale.length >= 2) {
            resultLocale = userLocale.substring(0, 2);
        }

        return resultLocale;
    }
  return callback(null, user, context);
}