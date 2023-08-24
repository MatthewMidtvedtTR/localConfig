function (user, context, callback) {
	let redirectURL = new URL('https://google.com/');
  context.redirect = {
    url: redirectURL
   };
  return callback(null, user, context);
}