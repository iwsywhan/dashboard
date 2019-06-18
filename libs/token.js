const jwt = require('jsonwebtoken');
const config = require('../config/config');

// exports.createToken = (payload, secret, expiredTokenTime) => {
//     return jwt.sign(payload, secret, { expiresIn: expiredTokenTime });
// };

exports.decodeToken = (token, callback) => {
    return jwt.verify(token, config.secret, callback);
};