function (user, context, callback) {
	context.riskAssessment.confidence = 'low';
  return callback(null, user, context);
}