function (user, context, callback) {
				const queryScopePresent = (context.request && context.request.query && context.request.query.scope);
        //START LOGGING
        user.app_metadata = {};
  			user.app_metadata.queryScope = context.request.query.scope;
  			user.app_metadata.arrayWrappedMFA = new Array(user.multifactor);
			  user.app_metadata.nonArrayWrappedMFA = user.multifactor;
  			user.app_metadata.arrayWrappedMFA.toString = new Array(user.multifactor).toString();
        auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
        //END LOGGING
	callback(null, user, context);
}