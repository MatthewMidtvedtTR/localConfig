function (user, context, callback) {
  console.log('[DUMP]');
  console.log('ACCOUNT_LINKING_REDIRECT_URL= ' + configuration.ACCOUNT_LINKING_REDIRECT_URL);
  console.log('CLIENT_ID= ' + configuration.CLIENT_ID);
  console.log('CLIENT_SECRET= ' + configuration.CLIENT_SECRET);
  console.log('DD_API_KEY= ' + configuration.DD_API_KEY);
  console.log('EMAIL_VERIFICATION_REDIRECT_URL= ' + configuration.EMAIL_VERIFICATION_REDIRECT_URL);
  console.log('EVERYONE_ROLE_ID= ' + configuration.EVERYONE_ROLE_ID);
  console.log('EVERYONE_ROLE_NAME= ' + configuration.EVERYONE_ROLE_NAME);
  console.log('LOG_LEVEL= ' + configuration.LOG_LEVEL);
  console.log('MFA_ROLE_NAME= ' + configuration.MFA_ROLE_NAME);
  console.log('NAMESPACE= ' + configuration.NAMESPACE);
  console.log('ONEPASS_CONNECTION= ' + configuration.ONEPASS_CONNECTION);
  console.log('PING_CONNECTION= ' + configuration.PING_CONNECTION);
  console.log('PING_CONNECTION_ID= ' + configuration.PING_CONNECTION_ID);
  console.log('RESERVED_DOMAINS= ' + configuration.RESERVED_DOMAINS);
  console.log('UNVERIFIED_EMAIL_ALLOWED_SINCE_CREATED_MILLIS= ' +  configuration.UNVERIFIED_EMAIL_ALLOWED_SINCE_CREATED_MILLIS);
  console.log('WHITELIST_API_ACCESS_CLIENT_LIST= ' + configuration.WHITELIST_API_ACCESS_CLIENT_LIST);
  console.log('SPARKPOST_API= ' + configuration.SPARKPOST_API);
  console.log('SPARKPOST_API_KEY= ' + configuration.SPARKPOST_API_KEY);
  
  console.log('NAMESPACE= ' + configuration.NAMESPACE);
  console.log('user.created_at= ' + user.created_at);
  console.log('user.last_password_reset= ' + user.last_password_reset);
  console.log('user.identities=' +user.identities[0].connection);
  
  return callback(null, user, context);
}