function (user, context, callback) {
  const authenticationCodes = [context.riskAssessment.assessments.UntrustedIP.code, context.riskAssessment.assessments.NewDevice.code, context.riskAssessment.assessments.ImpossibleTravel.code];
        //START LOGGING
        user.app_metadata = {};
        // user.app_metadata.confidenceOfAuthenticationPolicy = context.clientMetadata.MFA;
  			// user.app_metadata.parsed = JSON.parse(context.clientMetadata.MFA).riskTolerance;
  			user.app_metadata.multifactorObject = context.multifactor;
			  user.app_metadata.overallConfidence = context.riskAssessment.confidence;
  			user.app_metadata.authenticationCodes = authenticationCodes;
  			user.app_metadata.ENROLLEDIN = user.multifactor;
        auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
        //END LOGGING
	callback(null, user, context);
}