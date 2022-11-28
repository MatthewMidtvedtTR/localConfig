function (user, context, callback) {
	context.multifactor = {
    provider: 'any'
  };
  return callback(null, user, context);
}