/*
This rule blocks local accounts if they have been linked to federated accounts and the email domain is in reserved domains 
if and only if they do not have the allow_local_account role or hint_login = "account-linking-bypass"
 */
function (user, context, callback) {

	const reserved_domains = configuration.RESERVED_DOMAINS;

	let isReservedDomain = false; 
	let isLocalAccount = context.hasOwnProperty("connectionStrategy") && context.connectionStrategy.toLowerCase() === "auth0";
	let localBypass = context.hasOwnProperty("authorization") && context.authorization.hasOwnProperty("roles") && context.authorization.roles.includes("allow_local_account");
	let silentAuthForAccountLinking = context.request && context.request.query !== undefined && (context.request.query.hint === 'account-linking-bypass' || context.request.query.hint === 'email-verification-bypass');

    if (!isLocalAccount) {
        return callback(null, user, context);
    }

	/* Do not block users who are athenticate via ROPG */
	if (!((context.protocol === 'oidc-basic-profile') || (context.protocol === 'oidc-hybrid-profile') || (context.protocol === 'oidc-implicit-profile'))) {
		return callback(null, user, context);
	}
	

    /* Below code will be executed only for local accounts */
	/* Check if user email domain is reserved domain */
	var [user_name, domain] = user.email.split('@');
	var user_domain = domain.toLowerCase();
	if(reserved_domains.includes(user_domain)) {
	   isReservedDomain = true;
    }
  

	if (isReservedDomain && !(localBypass || silentAuthForAccountLinking)) {
		debug("local account blocked");
	    return callback(new UnauthorizedError('Please use SSO to log in.'));
	}
  

   callback(null, user, context);

    function debug(statement) {
        if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
            console.log('[Block local account rule for Client: ' + context.clientName + ',and user: ' + user.user_id + ']: ' + statement);
        }
    }
}
