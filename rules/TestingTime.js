function (user, context, callback) {
  const namespace = configuration.NAMESPACE;
	const authenticationObject = context.authentication.methods.find(e => e.name === 'pwd');
  context.accessToken[namespace + 'auth_time'] = Math.trunc(authenticationObject.timestamp/1000);
  return callback(null, user, context);
}