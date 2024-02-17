function (user, context, callback) {
    context.multifactor = {
    provider: 'email',
    allowRememberBrowser: false
  };
  callback(null, user, context);
}