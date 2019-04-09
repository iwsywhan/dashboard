var dbConn = require('../db');
var logger = require('../libs/logger');
var util = require('util');

var pcCheck = function(req, res) {
    var query = 'SELECT (SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'IPADDR\')';
    query += ' AS IPADDR, ';
    query += '(SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'RTSP_URL\')';
    query += ' AS RTSP_URL, ';
    query += '(SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'CTL_PORT\')';
    query += ' AS CTL_PORT ';

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.info('DB Error:', error);
        } else {
            res.send(results[0]);
        }
    });
};

var pclist = function(req, res) {
    logger.info('Path change : /viewService');

    var query = util.format('select b.DEV_NM,b.DEV_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,b.MODEL,b.VERSION,IFNULL(b.SVC_IP, \'\') as SVC_IP,IFNULL(b.DEV_KEY,\'\') as DEV_KEY,b.STATUS,b.VSTATUS,b.INSERT_DATE' +
        ' from ( select P_CUST_CTN, P_INSERT_DATE, DEV_KEY, max(INSERT_DATE) as INSERT_DATE from TB_VIEW_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, DEV_KEY) a' +
        ' left join TB_VIEW_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.DEV_KEY = b.DEV_KEY' +
        ' WHERE DEV_TYPE = \'%s\'' +
        ' order by b.INSERT_DATE', req.param('CUSTCNT'), req.param('INSERTDATE'), req.param('view_type'));

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
    pcCheck: pcCheck,
    pclist: pclist
};
