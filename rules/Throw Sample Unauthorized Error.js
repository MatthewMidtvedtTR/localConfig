function (user, context, callback) {
  return callback(new UnauthorizedError('Sample error'));
}