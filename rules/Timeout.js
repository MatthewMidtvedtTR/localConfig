function (user, context, callback) {
	console.log("testing");
  
	new Promise(function(resolve, reject) {
    //setTimeout(resolve, 0);
    resolve();
  }).then(function() {
    console.log("testing2");
  });  
  
  return callback(null, user, context);
}