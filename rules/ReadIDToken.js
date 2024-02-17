function (user, context, callback) {
  if(context.idToken['sub'] !== undefined){
   return callback(new UnauthorizedError("shouldReturn"));
  }
  return callback(null, user, context);
}