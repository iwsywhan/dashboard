var jwt = require('jsonwebtoken');
const { decodeToken } = require('./token');
var tokenConfig = require('../config/token');


exports.auth = async (req, res, next) => {
    
    const token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (token) {
        decodeToken(token, (err, decoded) => {
            if (err) {
                // const error = new ClientError("0008", 403);
                // return res.status(error.statusCode).json({ message: error.message });
            } else {
                req.session = decoded;
                next();
            }
        });
    } else {
        // const error = new ClientError("0009", 403);
        // return res.status(error.statusCode).send({ error: error.message });
    }
}

/*
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

    // var authrizationHeader = req.headers['authorization'] !== undefined ? req.headers['authorization'] : req.params.tken;
    const token = req.headers['x-access-token'];
    console.log(token)        

    if (!token) {
        // callback(false, null)
        // res.send('인증 실패')
        res.redirect('/');
        return;
    }

    jwt.verify(token, tokenConfig, function (err, decoded) {
        if (err) {
            callback(false, null)
        } else {
            req.session = decoded;
            callback(true, decoded);
        }
    });    
};
*/