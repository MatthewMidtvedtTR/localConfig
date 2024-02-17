/*
   This rule verifies if a user's email is verified. Login with unverified account is only allowed in the following cases:
   a. "isEmailVerificationSkipped" attribute is set on the current connection.
   b. Client has the metadata 'allow_unverified_accounts' set to true AND the account was created in the last 30 minutes.
 */
function (user, context, callback) {
  const allowedMillisSinceCreated = configuration.UNVERIFIED_EMAIL_ALLOWED_SINCE_CREATED_MILLIS;
  const ruleName = 'Force Email Verification';

  var redirectURL = new URL(configuration.EMAIL_VERIFICATION_REDIRECT_URL);
  redirectURL.searchParams.append('client_id', context.clientID);

  /**
   * Returns true if current request is ROPG, and email verification is skipped on the Client => Temporarily developed
   * for Onvio
   * @returns {boolean}
   */
  function bypassROPGRequest() {
    return (context.protocol === 'oauth2-password' || context.protocol === 'oauth2-resource-owner') &&
        context.clientMetadata.allow_unverified_accounts === 'true';
  }

  if((context.connectionMetadata && context.connectionMetadata.isEmailVerificationSkipped === 'true') || bypassROPGRequest()) {
    debug("Skipping email verification rule for the current connection, or ROPG request");
    return callback(null, user, context);
  }

  let allowUnverifiedAccounts = context.clientMetadata && context.clientMetadata.allow_unverified_accounts &&
      context.clientMetadata.allow_unverified_accounts === 'true';

  let scopes = [];

  let allowVerificationBypassForSelfScopes = context.clientMetadata && context.clientMetadata.allow_unverified_accounts_for_self_scopes &&
      context.clientMetadata.allow_unverified_accounts_for_self_scopes.toLowerCase() === 'true' &&
      context.request && context.request.query && context.request.query.hint && context.request.query.hint === 'email-verification-bypass';
  let selfScopesOnly = false;
  let isContinueFlow = context.protocol && context.protocol === "redirect-callback";
  if (allowVerificationBypassForSelfScopes) {
    if (context.request && context.request.query && context.request.query.scope) {
      context.request.query.scope.split(' ').forEach(function (scope) {
        scopes.push(scope.trim());
      });
    }
    selfScopesOnly = scopes.every(function (scope) {
      return scope.includes("write.self") || scope.includes("read.self") || scope === "openid" || scope === "profile" || scope === "email";
    });
  }

  if (!user.email_verified && allowUnverifiedAccounts && !isContinueFlow) {

    const createdTimeMillis =  new Date(user.created_at).getTime();
    const currTimeMillis = new Date().getTime();
    const millisSinceCreated = currTimeMillis - createdTimeMillis;
    if (millisSinceCreated >= allowedMillisSinceCreated) {
      debug("email is not verified redirecting to digital for verifying email");
      context.redirect = {
        url: redirectURL
      };
      return callback(null, user, context);
    } else {
      debug("User hasn't verified their email, allowing access since account was created within the last 30 mins");
      return callback(null, user, context);
    }

  } else if (!user.email_verified && allowVerificationBypassForSelfScopes && selfScopesOnly && !isContinueFlow) {
    context.isSilentAuthCall = true;
    return callback(null, user, context);
  }
  else if(user.email_verified){
    return callback(null, user, context);
  } else if (!isContinueFlow) {
    debug("email is not verified redirecting to digital for verifying email");
    context.redirect = {
      url: redirectURL
    };
    return callback(null, user, context);
  } else {
    return callback(new UnauthorizedError("Email is not verified."));
  }
  function debug(statement) {
    if (configuration.CONSOLE_LOGS_ENABLED === 'true') {
      console.log('[Email verification rule : ' + context.clientName + ',and user: ' + user.user_id + ']: ' + statement);
    }
  }
}
