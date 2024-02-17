function(user, context, callback){
  
  const policy = context.clientMetadata.password_reset_policy;
  if(policy === undefined || context.protocol === "redirect-callback"){
    //if the client doesn't have the policy, the whole flow and Rule is irrelevant, so we can just continue normally by exiting the Rule.
    //OR 
    //This is in the case that we have a warning period like OP with a skip button.
    callback(null, user, context);
  }
  
  let keys = Object.keys(context.request.query);
  //make a ticket to bump this because of vulnerabilities
  const moment = require('moment@2.19.3');
  user.app_metadata = context.request;
  user.app_metadata.listOfKeys = keys;
  user.app_metadata.THE_POLICY = policy; 
  //we will just assume seconds for now on the policy but can allow a different format for this in the future.
  const now = moment();
  let timeResetIsDue = moment(user.last_password_reset).add(policy, 's');
  // persist the app_metadata update
  auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
    .then(function(){
    if(timeResetIsDue.isSameOrBefore(now)){
      let initialRequest = new URL('/authorize', 'https://'+context.request.hostname);
      let queryKeys = Object.keys(context.request.query);
      queryKeys.forEach(element => initialRequest.searchParams.append(element, context.request.query[element]));
      let redirectURL = new URL('https://www-tr-com-qa-ams.ewp.thomsonreuters.com/en-us/profile');
      redirectURL.searchParams.append('originalURL', initialRequest.toString());
      context.redirect = {
        url: redirectURL
      };
  }
      callback(null, user, context);
    })
    .catch(function(err){
      callback(err);
    });
}