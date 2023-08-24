function (user, context, callback) {
    const namespace = configuration.NAMESPACE;
    //above this line is to be removed
//    const includeAuthenticationInformationClaims = context.request.query['max_age'] !== undefined || context.request.query['prompt'] === 'login';
    //we need to test that this boolean works, so I should start by testing that this works by an unauthorized error. If I worked on testing this would be much easier.

        //code to add the information to the token.
        const milliseconds = context.authentication.methods.find((method) => method.name === 'pwd').timestamp;
  			const seconds = milliseconds/1000;
        context.accessToken[namespace + 'auth_time'] = seconds;
        //return callback(new UnauthorizedError("testing"));
    return callback(null, user, context);
}