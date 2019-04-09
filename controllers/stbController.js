var dbConn = require('../db');
var logger = require('../libs/logger');
var util = require('util');
var pushServiceAPI = require('../pushServiceAPI.js');
var decodeJWT = require('../libs/decodeJWT');

var service = function(req, res) {
    logger.info('Path change : /stbService');

    var query = util.format('select b.STB_NM,b.STB_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,IFNULL(b.SVC_STB_IP, \'\') as SVC_STB_IP,IFNULL(b.STB_MAC_ADDR,\'\') as STB_MAC_ADDR,b.STATUS,b.INSERT_DATE,' +
        'IFNULL(b.STB_MODEL,\'\') as STB_MODEL, IFNULL(b.STB_OS,\'\') as STB_OS' +
        ' from ( select P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR, max(INSERT_DATE) as INSERT_DATE from TB_STB_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR) a' +
        ' left join TB_STB_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.STB_MAC_ADDR = b.STB_MAC_ADDR' +
        ' order by b.INSERT_DATE', req.param('CUSTCNT'), req.param('INSERTDATE'));

    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
};

module.exports = {
    service: service
};
