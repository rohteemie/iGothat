// middleware/auth.middleware.js
const { verifyToken } = require('../helper/auth.util');

// Middleware function to check for a valid JWT
/**
 * Middleware to authenticate a token from the Authorization header.
 *
 * @param {Object} req - The request object.
 * @param {Object} req.headers - The headers of the request.
 * @param {string} req.headers.authorization - The Authorization header containing the token.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 *
 * @returns {Object|void} - Returns a 401 status with a message if the token is not provided,
 *                          a 403 status with a message if the token verification fails,
 *                          or proceeds to the next middleware if the token is valid.
 */
function authenticateToken(req, res, next) {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token not provided' });
    }

    const decodedUserId = verifyToken(token);
    req.user = { id: decodedUserId.sub, username: decodedUserId.username };
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired, use refresh token' });
    }
    return res.status(403).json({ message: error.message });
  }
}

function validateUserOwnership(req, res, next) {
  const { username } = req.params;

  if (req.user.username !== username) {
    return res.status(403).json({ message: 'You do not have access to this resource' });
  }
  next();
}

function authorizeRoles(...allowedRoles) {
	return (req, res, next) => {
	  if (!allowedRoles.includes(req.user.role)) {
		return res.status(403).json({ message: 'Access Denied' });
	  }
	  next();
	};
}

function checkTokenExpiry(req, res, next) {
	const tokenExpiry = req.user.exp;  // Assuming the expiry time is part of the token payload
	const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds

	if (tokenExpiry < currentTime) {
	  return res.status(401).json({ message: 'Session expired, please log in again' });
	}
	next();
  }


const allowedIPs = ['123.456.789.000'];  // Example whitelist
function checkIP(req, res, next) {
  const userIP = req.ip || req.connection.remoteAddress;
  if (!allowedIPs.includes(userIP)) {
    return res.status(403).json({ message: 'Unauthorized IP address' });
  }
  next();
}


module.exports = {
	authenticateToken,
	authorizeRoles,
	checkTokenExpiry,
	checkIP,
  validateUserOwnership
 };
