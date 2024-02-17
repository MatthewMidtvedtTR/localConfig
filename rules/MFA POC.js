function (user, context, callback) {
  if(user.multifactor.length > 0 && context.clientMetadata.bypassMFA === 'true'){
    context.multifactor = {
    	provider: 'none'
  	};
  } else {
  	context.multifactor = {
    	provider: 'any'
  	};
  }
  return callback(null, user, context);
}