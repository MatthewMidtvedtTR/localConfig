function (user, context, callback) {
  let keys = Object.keys(context.request.query);
  let boo = true;
  if(context.request.query['max_age'] !== undefined){
    boo=false;
  }
	context.multifactor = {
    provider: 'any',
    allowRememberBrowser: boo
  };
  return callback(null, user, context);
}