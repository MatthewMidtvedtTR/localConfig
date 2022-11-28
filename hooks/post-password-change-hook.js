/**
 @param {object} user - The affected user
 @param {string} user.id - user id
 @param {string} user.username - user name
 @param {string} user.email - email
 @param {string} user.last_password_reset - exact date/time the user's password was changed
 @param {object} context - Auth0 connection and other context info
 @param {object} context.connection - information about the Auth0 connection
 @param {object} context.connection.id - connection id
 @param {object} context.connection.name - connection name
 @param {object} context.connection.tenant - connection tenant
 @param {object} context.webtask - webtask context
 @param {function} cb - function (error)
 */
module.exports = function (user, context, cb) {
  const https = require('https');

  const postData = JSON.stringify({
    "content": {
      "template_id": "yourpasswordisupdated.en",
      "use_draft_template": context.webtask.secrets.ENVIRONMENT === "ciam-sandbox"
    },
    "substitution_data": {
    "fname": "Seattle"
    },
    "recipients": [
      {
        "address": {
          "email": user.email,
        }
      }
    ]
  });

  const postDataLength = Buffer.byteLength(postData);

  const options = {
    hostname: 'api.sparkpost.com',
    path: '/api/v1/transmissions',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': postDataLength,
      'Authorization': context.webtask.secrets.SPARKPOST_API_KEY,
      'X-MSYS-SUBACCOUNT': 29
    }
  };

  const req = https.request(options, (res) => {
    console.log('STATUSCODE:', res.statusCode);
    console.log('HEADERS:', res.headers);

    res.on('DATA', (d) => {
      process.stdout.write(d);
    });
  });

  req.on('ERROR', (e) => {
    console.error(e);
  });

  req.write(postData);
  req.end();
  cb();
};
