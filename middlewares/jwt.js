var jwt = require('jsonwebtoken');
var tokenConfig = require('../config/token');

module.exports = function (req, res, next) {
    if (req.url === '/logout') {
        next();
    }
    // var authrizationHeader = req.headers['authorization'];
    const token = req.headers['x-access-token'];

    if (!token) {
        res.sendStatus(401);
    }

    if (token) {
        jwt.verify(token, tokenConfig, function (err, decodedToken) {
            // if (ip === decodedToken.ip) {
                next();
            // }
        });
    }
};
