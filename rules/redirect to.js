function (user, context, callback) {
	var a = 'https://google.com';
  context.redirect = {
    url: a
  };
  return callback(null, user, context);
}