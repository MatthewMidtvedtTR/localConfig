function (user, context, callback) {
	const password = require('secure-random-password@0.2.1');
  const thePassword = password.randomPassword({ length: 20, characters: [password.lower, password.upper, password.digits] });
  console.log('The password is : ' + thePassword);
  return callback(null, user, context);
}