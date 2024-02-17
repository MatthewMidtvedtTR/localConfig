function (user, context, callback) {
  context.idToken['customClaim'] = 'shouldWork';
  context.idToken['amr'] = 'shouldntWorkkkk';
  
  context.accessToken['https://tr.com/'+'amr'] = 'shouldntWork';
  context.accessToken['https://tr.com/'+'authtime'] = 'someValue';
  return callback(null, user, context);
}