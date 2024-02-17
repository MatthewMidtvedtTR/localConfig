function (user, context, callback) {
  // assume that the user is enrolled in MFA
  // check if the user has already done MFA for the current authentication
	  // if so, callback
	  // if not, trigger MFA
    const completedMfa = context.authentication && !!context.authentication.methods.find(
      (method) => method.name === 'mfa');
  
  if(completedMfa){
	  return callback(null, user, context);
  } else {
           context.multifactor = {
            provider: 'any',
            allowRememberBrowser: false
        };
  }
  return callback(null, user, context);
}