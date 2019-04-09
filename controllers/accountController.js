var logger = require('../libs/logger');
var util = require('util');
var dbConn = require('../db');

var getLanguage = function(req, res) {
    logger.info('Path change : /getLanguage');
    var query = util.format("SELECT LOCALE FROM TB_ADMIN WHERE ADMIN_ID = '%s'", req.session.userid);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results[0]);
        }
    });
};

var setLanguage = function(req, res) {
    logger.info('Path change : /setLanguage');
    var query = util.format("UPDATE TB_ADMIN SET LOCALE = '%s' WHERE ADMIN_ID = '%s'"
    ,req.body.locale, req.session.userid);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send({result: true});
        }
    });
};

module.exports = {
    getLanguage,
    setLanguage
};
