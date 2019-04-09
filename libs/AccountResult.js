var logger = require('./logger');
var util = require('util');
var Result = require('./Result');
var crypto = require('crypto');

module.exports = AccountResult;


function AccountResult() {
}

AccountResult.prototype = new Result();

AccountResult.prototype.isEntry = function (dbConn, req, res, callback) {
    var admin_id = typeof req.body.CHECK_ID === 'undefined' ? req.body.LC_ID : req.body.CHECK_ID;

    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_ADMIN WHERE ADMIN_ID = '%s'", admin_id);

    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        var status = false;
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            logger.info('DB Success: ', req.body.ID);
            if (results[0].CNT > 0) {                
                res.status(500).send({RESULT_CODE:"0001", RESULT_MESSAGE:"서비스 등록된 계정"});
            } else {
                if (typeof callback === "function") {
                    status = true;
                } else {
                    res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상 처리"});
                }
            }
        }

        if (typeof callback === "function") {
            callback(status);
        }
    });
}

AccountResult.prototype.insertAccount = function (dbConn, req, res) {
    var hash_pw = crypto.createHash('sha256').update(req.body.LC_PASS).digest('hex');
    var query = util.format("INSERT INTO TB_ADMIN (" +
        "ADMIN_ID,ADMIN_PW,ADMIN_LV,ADMIN_NM,ADMIN_MOBILE_NUM,ADMIN_DEPT_NM,ADMIN_ARANK,INSERT_DATE," +
        "CODE_01,CODE_02,CODE_03,CODE_ID,STATUS,UPDATE_DATE,UTM_ID)" +
        "VALUES(" +
        "'%s','%s','%s','%s','%s','%s','%s',%s" +
        ",'%s','%s','%s',%d,'%s',%s,'%s')"
        ,req.body.LC_ID, hash_pw, '2', req.body.LC_U_NAME, req.body.LC_U_PHONE, '기본 관제센터', req.body.LC_U_CLASS, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
        ,'900', '999', req.body.LC_CUST_CODE, Number('900999'+req.body.LC_CUST_CODE), 'Y', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', req.body.UTM_ID);
    
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            return false;
        } else {
            res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상 처리"});
            return true;
        }
    });    
}

