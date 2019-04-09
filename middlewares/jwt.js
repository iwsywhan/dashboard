var jwt = require('jsonwebtoken');
var tokenConfig = require('../config/token');

module.exports = function (req, res, next) {
    if (req.url === '/logout') {
        next();
    }
    var authrizationHeader = req.headers['authorization'];

    // var ip = req.headers['x-forwarded-for'] ||
    // req.connection.remoteAddress ||
    // req.socket.remoteAddress ||
    // req.connection.socket.remoteAddress;
    var token = authrizationHeader.split(' ')[1];
    
    if (!authrizationHeader) {
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
