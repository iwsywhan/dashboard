var logger = require('../libs/logger');
var util = require('util');
var dbConn = require('../db');

var callStatus = function(req, res) {
    logger.info('Path change : /voiceCallStatus');
    var query = util.format('SELECT SVC_TYPE FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = \'%s\' and INSERT_DATE = \'%s\' and STATUS < 3', req.param('CUSTCNT'), req.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
};

module.exports = {
    callStatus: callStatus
};
