function (user, context, callback) {
	const namespace = configuration.NAMESPACE;
  context.accessToken[namespace + 'pwd_auth_time'] = context.authentication.methods.find(e => e.name === 'pwd').timestamp;
  return callback(null, user, context);
}