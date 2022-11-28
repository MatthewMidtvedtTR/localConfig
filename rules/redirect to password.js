function (user, context, callback) {
	var reset = new URL('https://matthew.ciam-sandbox.thomsonreuters.com/lo/reset?ticket=hOdio98IVxudX7lo5aWRdSxpgpaUiup8#');
  context.redirect = {
    url: reset
  };
  return callback(null, user, context);
}