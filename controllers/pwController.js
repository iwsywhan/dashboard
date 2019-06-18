var logger = require('../libs/logger');
var dbConn = require('../db');
var util = require('util');

var reset = function(req, res) {
    logger.info('Path change : /pwReset');

    var id = req.param('id');
    var type = req.param('type');

    if (error) {
        logger.error('Error:', error);
    } else {
        if (id !== 'undefined') {
            res.send({ 'id': id, 'type': type });
        }
    }
};

var getchange = function(req, res) {
    logger.info('Path change : /pwChange');
    
    if (error) {
        logger.error('Error:', error);
    } else {
        res.send({ pass_change: req.session.pass_change });
    }
}

var putchange = function(req, res) {
    var key_id = req.param('key_id');
    logger.info('Path change : /pwChange');
    
    if (error) {
        logger.error('Error:', error);
    } else {
        res.send({ pass_change: key_id });
    }
};

var get = function(req, res) {
    logger.info('Path change : /password/get');

    var query = util.format("SELECT admin_pw from TB_ADMIN WHERE admin_id = '%s'", req.session.userid);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.info('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results[0]);
        }
    });
};

module.exports = {
    reset: reset,
    putchange: putchange,
    get: get
};
