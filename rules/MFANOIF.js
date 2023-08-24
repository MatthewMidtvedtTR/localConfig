function (user, context, callback) {
  context.multifactor = {
    provider: 'any',
    allowRememberBrowser: true
  };
  return callback(null, user, context);
}