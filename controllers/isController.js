var dbConn = require('../db');
var logger = require('../libs/logger');
var util = require('util');
var pushServiceAPI = require('../pushServiceAPI.js');
var decodeJWT = require('../libs/decodeJWT');

var mVoIP = function(req, res) {
    logger.info('Path change : /ismVoIP');

    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var mVoIP;
            var query = util.format('SELECT SV_OP_SV_V FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', token.code_03);    
            
            dbConn.query(query, function (error, results) {
                logger.info('Query:', query);
                if (error) {
                    logger.error('DB Error:', error);
                    mVoIP = '';
                    res.status(500).send('DB ' + error);
                } else {

                    if (results.length > 0) {
                        mVoIP = results[0].SV_OP_SV_V != 'Y' ? 'N' : results[0].SV_OP_SV_V
                    } else {
                        mVoIP = 'N'
                    }                    
                }
                res.send(mVoIP);
            });
        }

    });

};

var existRegid = function(req, res) {
    logger.info('Path change : /IsExistRegid');
    pushServiceAPI.IsExistRegid(dbConn, req.params.dev_key, req.params.dev_type, function(results) {
        logger.info('IsExistRegid result : ', results);
        res.send(results[0]);
    });
};

module.exports = {
    mVoIP: mVoIP,
    existRegid: existRegid
};
