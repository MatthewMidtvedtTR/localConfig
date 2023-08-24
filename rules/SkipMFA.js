function (user, context, callback) {
  context.multifactor = {
    provider: 'none'
  };
  return callback(null, user, context);
}