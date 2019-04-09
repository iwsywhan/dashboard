var logger = require('../libs/logger');
var util = require('util');
var dbConn = require('../db');

var countServcing = function(req, res) {
    logger.info('Path change : /getCountServcing');
    var query = 'SELECT count(P_CUST_CTN) as COUNT FROM TB_STB_SERVICE WHERE STATUS = \'2\'';
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

module.exports = {
    countServcing: countServcing
};
