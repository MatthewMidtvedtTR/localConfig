function (user, context, callback) {
  const namespace = 'someSpace';
  //set claim for nonfederated users.
        const userMultifactor = new Array(user.multifactor);
        let mfaEnrollment = false;
        if (userMultifactor) {
            if (userMultifactor.length === 1) {
                if (userMultifactor.toString() === 'email' || userMultifactor.toString() === '') {
                    mfaEnrollment = false;
                } else { mfaEnrollment = true; }
            } else {
                mfaEnrollment = true;
            }
        }
        if(mfaEnrollment){
            context.idToken[namespace + 'mfa_methods'] = user.multifactor;
        }
  return callback(null, user, context);
}