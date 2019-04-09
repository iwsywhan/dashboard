var dbConn = require('../db');
var logger = require('../libs/logger');
var decodeJWT = require('../libs/decodeJWT');

var check = function(req, res) {
    logger.info('/manage/check');

    var JWT = decodeJWT(req, res, function(result, token) {
        
        if (result) {
            var id = token.id;
            var code3 = token.code_03;
            var query = 'select ADMIN_LV,ADMIN_ID,a.CODE_01,a.CODE_02,a.CODE_03,ADMIN_NM,CUST_ADMIN, '
            query += '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ';
            query += '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ';
            query += '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3 '
            query += 'from TB_ADMIN a where ADMIN_ID = \'' + id + '\'';
        
            dbConn.query(query, function(error, results) {
        
                logger.info('Query:', query);
                if (error) {
                    logger.error('DB Error:', error);
                    res.status(500).send('DB ' + error);
                } else {
                    res.send(results[0]);
                }
            });
        }
    });

};

var check2 = function(req, res) {
    logger.info('/manage/check2');
    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var id = token.id;

            var query;
            query = 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'STB\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'MOBILE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'VOICE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'PC\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'TOSS\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'SMS\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'ANY\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'SECURITY\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'CONFERENCE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'ORG_SIZE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'CONTROL_SIZE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'STB_SIZE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'ADMIN_SIZE\'';
            query += ' UNION ALL ';
            query += 'SELECT C_NAME, C_VALUE FROM TB_COMMON WHERE C_NAME = \'SECURITY_VIDEO\'';
            query += ' UNION ALL ';
            query += 'SELECT ADMIN_ID, ADMIN_LV FROM TB_ADMIN WHERE ADMIN_ID = \'' + id + '\'';
        
            dbConn.query(query, function(error, results) {
                logger.info('Query:', query);
                if (error) {
                    logger.info('DB Error:', error);
                    res.status(500).send('DB ' + error);
                } else {
                    res.send(results);
                }
            });
        }
    });

};

module.exports = {
    check: check,
    check2: check2
};