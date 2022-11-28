function (user, context, callback) {
	global.info=true;
  return callback(null, user, context);
}