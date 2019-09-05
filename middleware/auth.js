const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
  // Get token from header
  const token = req.header('x-auth-token');

  // Check if token exists
  if (!token) {
    return res.status(401).json({ msg: 'No Token, authorization denied ' });
  }

  try {
    // Verify the token and take out the payload
    const decoded = jwt.verify(token, config.get('jwtSecret'));

    // Set the user that is in the payload so we have access to it in that route
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};
