function test(user, context, callback) {
  user.testing='word';
  return callback(null, user, context);
}