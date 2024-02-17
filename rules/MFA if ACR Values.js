function (user, context, callback) {
		if(context.request.query.acr_values === 'http://schemas.openid.net/pape/policies/2007/06/multi-factor') {
      context.multifactor = {
        provider: 'any'
      };
	  }
  return callback(null, user, context);
}