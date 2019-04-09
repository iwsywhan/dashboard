var logger = require('../libs/logger');
var util = require('util');
var dbConn = require('../db');

var detailSave = function(req, res) {// 작업내용 등록
    logger.info('Path change : /workDatailSave');

    // var s_userid = req.param('userid');
    var s_userid = req.session.userid;
    var checkVar = req.param('checkVar');
    var subject = req.param('subject');
    var content = req.param('content');
    var checkVarList = checkVar.split('`'); //선택체크박스
    var queryS = '';

    for (var i = 1; i < checkVarList.length; i++) {
        var checkVarColumn = checkVarList[i].split(',');
        if (i > 1) {
            queryS += ', ';
        }
        queryS += "( '" + checkVarColumn[0] + "', '" + checkVarColumn[1] + "', '" + checkVarColumn[2] + "', '" + subject + "', '" + content + "', '" + s_userid + "', DATE_FORMAT(now(),'%Y%m%d%H%i%s')  ) ";
    }

    var query = " insert into TB_TERMINAL_IMAGE_TRANS_MEMO( P_CUST_CTN,P_CTN_DEVICE,P_INSERT_DATE,SUBJECT,CONTENT,ADMIN_ID, INSERT_DATE ) ";
    query += ' values  ';
    query += queryS;

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

var list = function(req, res) {// 작업내용 등록
    logger.info('Path change : /workDatailList : ');

    var checkVar = req.param('checkVar');
    var checkVarList = checkVar.split("`"); //선택체크박스

    var queryS = "   P_CUST_CTN = 'xxx' ";
    for (var i = 1; i < checkVarList.length; i++) {
        var checkVarColumn = checkVarList[i].split(",");
        if (i == 1) queryS = "    ";
        if (i > 1) queryS += "  or  ";
        //queryS += " ( P_CUST_CTN='"+checkVarColumn[0]+"' and P_CTN_DEVICE='"+checkVarColumn[1]+"' and P_INSERT_DATE='"+checkVarColumn[2]+"' ) ";
        queryS += " ( P_CUST_CTN='" + checkVarColumn[0] + "' and P_INSERT_DATE='" + checkVarColumn[2] + "' ) ";
    }

    var query = "select P_CUST_CTN,P_CTN_DEVICE,P_INSERT_DATE,SUBJECT,CONTENT,ADMIN_ID,INSERT_DATE  from TB_TERMINAL_IMAGE_TRANS_MEMO ";
    query += "  where   ";
    query += queryS;
    query += " order by   INSERT_DATE DESC ";


    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            res.send(results);
        }
    });
};

module.exports = { 
    detailSave: detailSave,
    list: list
};
