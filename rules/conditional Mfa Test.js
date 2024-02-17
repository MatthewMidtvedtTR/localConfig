function (user, context, callback) {
        context.multifactor = {
            provider: 'any',
            allowRememberBrowser: false
        };
  const mfaDone = context.authentication && !!context.authentication.methods.find(
      (method) => method.name === 'mfa');
  if(mfaDone){
    console.log('true!!!');
     context.idToken['https://tr.com/' + 'mfa_completed_at'] = mfaDone.timestamp;
    context.idToken['https://tr.com/' + 'mfa_completed_at'] = context.completedMfa.timestamp;
  } else {
    console.log('false');
  }
  return callback(null, user, context);
}