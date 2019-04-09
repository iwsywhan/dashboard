var jwt = require('jsonwebtoken');
var tokenConfig = require('../config/token');

module.exports = function (req, res, callback) {
    if (typeof req.session.userid !== "undefined" && req.headers['user-agent'].indexOf('Electron') < 0) {

        var decodedToken = {};
        decodedToken.ip = req.session.ip;
        decodedToken.id = req.session.userid;
        decodedToken.userlv = req.session.userlv;
        decodedToken.code_03 = req.session.code_03;
        decodedToken.code_02 = req.session.code_02;
        decodedToken.code_01 = req.session.code_01;
        decodedToken.drone = 'Y';
        callback(true, decodedToken);
        return;
    }

    var authrizationHeader = req.headers['authorization'] !== undefined ? req.headers['authorization'] : req.params.tken;

    if (authrizationHeader == undefined) {
        // callback(false, null)
        // res.send('인증 실패')
        res.redirect('/');
        return;
    }

    var array = authrizationHeader.split(' ');
    var token = array.length > 1 ? authrizationHeader.split(' ')[1] : authrizationHeader;
    var dtoken;
    jwt.verify(token.replace('"', ''), tokenConfig, function (err, decodedToken) {
        if (err) {
            callback(false, null)
        } else {
            callback(true, decodedToken);
        }
    });    
};
