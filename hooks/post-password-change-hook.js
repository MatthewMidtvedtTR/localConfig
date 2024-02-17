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
  const domain = `${context.connection.tenant}.${context.webtask.secrets.ENVIRONMENT}.thomsonreuters.com`;
  const hostname = (() => {
    switch (domain) {
      case 'main.ciam-sandbox.thomsonreuters.com':
        return 'auth-sandbox.thomsonreuters.com';
      case 'main.ciam-nonprod.thomsonreuters.com':
        return 'auth-nonprod.thomsonreuters.com';
      case 'main.ciam-prod.thomsonreuters.com':
        return 'auth.thomsonreuters.com';
      default:
        return domain;
    }
  })();

  getAccessToken().then(accessToken=> getUser(accessToken.access_token)).then(fullUser=> sendEmail(fullUser)).catch(error=> captureError(error));

  cb();

  function sendEmail(fullUser){

    function determineTemplateToSend(locale){
      switch(locale){
        case 'es-AR':
        case 'fr-CA':
        case 'pt-BR':
          return locale.substring(0,2);
        default:
          return 'en';
      }
    }

    const postData = JSON.stringify({
      'content': {
        'template_id': 'yourpasswordisupdated.'+determineTemplateToSend(fullUser.app_metadata.locale),
        'use_draft_template': context.webtask.secrets.ENVIRONMENT === 'ciam-sandbox'
      },
      'substitution_data': {
        'DIGITAL_HOST': context.webtask.secrets.DIGITAL_HOST,
        'fname': fullUser.given_name ? fullUser.given_name : ''
      },
      'recipients': [
        {
          'address': {
            'email': user.email,
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

    return httpRequest(options, postData);
  }

  function getUser(accessToken){
    const optionsForUser = {
      hostname: domain,
      path: '/api/v2/users/'+user.id,
      method: 'GET',
      headers:{
        'Authorization': 'Bearer '+ accessToken
      }
    };
    return httpRequest(optionsForUser);
  }

  function getAccessToken(){
    const postDataForAT = JSON.stringify({
      'client_id': context.webtask.secrets.CLIENT_ID,
      'client_secret': context.webtask.secrets.CLIENT_SECRET,
      'audience': 'https://'+domain+'/api/v2/',
      'grant_type': 'client_credentials'
    });

    const postDataLengthForAT = Buffer.byteLength(postDataForAT);

    const optionsForAT = {
      hostname: domain,
      path: '/oauth/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': postDataLengthForAT
      }
    }
    return httpRequest(optionsForAT, postDataForAT);
  }

  function captureError(errorObj){
    console.error(`ERROR: user=${user.id}: ${errorObj.message}`);
    forwardLogToDatadog(errorObj.toString(), 'ERROR');
  }

  function forwardLogToDatadog(message, status){
    if (context.webtask.secrets.DATADOG_LOGS_ENABLED !== 'true') {
      return;
    }

    const postData = JSON.stringify({
      'ddsource': 'auth0',
      'ddtags': `tenant:${context.connection.tenant}`,
      'environment': context.webtask.secrets.ENVIRONMENT.replace('ciam-', ''),
      'hostname': hostname,
      'data': {
        'hostname': hostname,
        'session_connection': context.connection.name,
        'user_id': user.id
      },
      'service': 'Post Password Change Hook',
      status,
      message,
    });

    const postDataLength = Buffer.byteLength(postData);

    const options = {
      method: 'POST',
      hostname: new URL('https://http-intake.logs.datadoghq.com/api').hostname,
      path: '/api/v2/logs',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': postDataLength,
        'DD-API-KEY': context.webtask.secrets.DATADOG_API_KEY,
        'DD-APPLICATION-KEY': context.webtask.secrets.DATADOG_APPLICATION_KEY
      },
      data: postData
    };

    httpRequest(options, postData).catch(error=> console.error('Error writing to Datadog: ' + error.message)); //this should handle the situation that our error message to DataDog fails for some reason. 
  }

  function httpRequest(params, postData) {
    return new Promise(function(resolve, reject) {
      var req = https.request(params, function(res) {
        var body = [];
        res.on('data', function(chunk) {
          body.push(chunk);
        });
        res.on('end', function() {
          const jsonContent = res.headers['content-type'] && res.headers['content-type'].includes('application/json');
          if(jsonContent) {
            body = JSON.parse(Buffer.concat(body).toString());
          } else {
            body = Buffer.concat(body).toString();
          }
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`statusCode=${res.statusCode} responseBody=${JSON.stringify(body)}`));
          }
          resolve(body);
        });
      });
      req.on('error', function(err) {
        console.error(err);
        reject(err);
      });
      if (postData) {
        req.write(postData);
      }
      req.end();
    });
  }
};
