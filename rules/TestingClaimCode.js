function (user, context, callback) {
    const namespace = configuration.NAMESPACE;
    //above this line is to be removed
    const includeAuthenticationInformationClaims = context.request.query && context.request.query.max_age !== undefined || context.request.query.prompt === 'login' || context.request.query.scope && context.request.query.scope.indexOf(namespace + 'auth_time') !== -1;
    //we need to test that this boolean works, so I should start by testing that this works by an unauthorized error. If I worked on testing this would be much easier.

    if(includeAuthenticationInformationClaims){
        //code to add the information to the token.
        context.accessToken[namespace + 'auth_time'] = context.authentication.methods.find(e => e.name === 'pwd').timestamp;
        //return callback(new UnauthorizedError("testing"));
    }
    return callback(null, user, context);
}
