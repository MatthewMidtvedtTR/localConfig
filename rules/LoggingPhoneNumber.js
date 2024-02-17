function (user, context, callback) {
  if(user.user_id === 'auth0|63fcd2b2227ed196ff881a82'){
    callback(new UnauthorizedError('test'));
        //START LOGGING
        user.app_metadata = {};
			  user.app_metadata.phoneNumberFactor = user.multifactor;
        auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
        //END LOGGING
  }
	callback(null, user, context);
}