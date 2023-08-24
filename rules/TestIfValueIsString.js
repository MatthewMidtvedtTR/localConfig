function (user, context, callback) {
    const clientMFAConfiguration = context.clientMetadata.MFA ? JSON.parse(context.clientMetadata.MFA) : false;
  const adaptiveMFAResult = (() => {
    if (clientMFAConfiguration) return callback(new UnauthorizedError("stored as a string"));
  })();
  return callback(null, user, context);
}