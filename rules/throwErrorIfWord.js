function (user, context, callback) {
  if(user.testing==='word'){
    return callback(new UnauthorizedError("error passed"));
  }
  return callback(null, user, context);
}