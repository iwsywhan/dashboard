var util = require('util');
const logger = require('./libs/logger')

exports.getCountNewNoticeOnChannel = function (dbConn, request, response) {

    var now_date = new Date().formatDate("yyyyMMddhhmmss");
    var query =  "SELECT " +
        "   SUM(COUNT) NOTICE_COUNT " +
        "FROM " +
        "(" +
        "   SELECT count(if((N_READ_FLAG = '0' or N_READ_FLAG is null), 1, null)) COUNT " +
        "   FROM ( " +
        "       SELECT N_READ_FLAG " +
        "        FROM TB_NOTICE_POPUP a LEFT JOIN TB_TN_SERVICE b " +
        "        ON a.SEQ = b.P_CUST_CTN and b.DEV_KEY = '" + request.session.userid + "' " +
        "    WHERE N_F_DATE <= '" + now_date + "' AND N_T_DATE > '" + now_date + "' AND N_SENDDATE != '' " +
        "    ORDER BY a.N_SENDDATE DESC " +
        "    LIMIT 2 " +
        "    ) c " +
        "    UNION ALL " +
        "    SELECT " +
        "        if (COUNT(*) > 5,5,COUNT(*)) COUNT " +
        "    FROM TB_TN_SERVICE " +
        "    WHERE P_CUST_CTN = '" + request.param("P_CUST_CTN") + "' AND P_INSERT_DATE = '" + request.param("P_INSERT_DATE") + 
        "       ' AND DEV_KEY = '" + request.session.userid + "' AND N_READ_FLAG = '0' " +
        ") d ";


    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            //callback(null);
        } else {
            logger.info('DB Success:');
            response.send(results[0]);
        }
    });
}

var SelectMaxSequenceNumOnChannel = function (dbConn, request, callback) {
    
    if (request.param("N_SEQ") != "create") {
        callback("0");
    } else {
        logger.info('Path change: /SelectMaxSequenceNumOnChannel');
        var query = util.format('SELECT ifnull(MAX(CAST(N_SEQ as integer)),0) MAX_SEQ FROM TB_TN_SERVICE WHERE P_CUST_CTN = \'%s\' AND P_INSERT_DATE = \'%s\''
                                ,request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'));
        dbConn.query(query, function (error, results) {
            
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
                callback(null);
            } else {
                logger.info('DB Success:');
                var n_seq = Number(results[0].MAX_SEQ)+1;
                callback(n_seq);
                console.log('MAX N_SEQ : ', n_seq);
            }
        });   
    }
}


exports.InsertNoticeDataOnChannel = function (dbConn, request, response) {
    
    SelectMaxSequenceNumOnChannel(dbConn, request, function(MAX_SEQ) {
        
        if (MAX_SEQ == null) {
            response.send("seq num을 얻어오는데 실패하였습니다.");
            return;
        }

        // 산업용 Iot 서버에서 SEQ를 가져올 때 이상한 동작이 발생되어 SEQ를 DB를 통해 가져오는 것으로 수정
        if (request.param('N_TYPE') == '1') {   // 시스템 공지사항 읽기 Set up
            var query1 = 'SELECT SEQ FROM TB_NOTICE_POPUP WHERE N_INSERTDATE = \'' + request.param('P_INSERT_DATE') + '\'';
            dbConn.query(query1, function (error, results) {                    
                logger.info('Query:', query1);
                if (error) {
                    logger.error('DB Error:', error);
                    response.send("query error");
                } else {
                    logger.info('DB Success:');
                    if (Object.keys(results).length > 0) {
                        logger.info('SEQ => P_CUST_CTN :', results[0].SEQ);                        
                        InsertNotice(dbConn, request, response, results[0].SEQ, MAX_SEQ);
                    } else {
                        response.send("시스템 공지사항 SEQ를 찾을 수가 없습니다. 관리자에게 문의하세요.")
                    }
                }
            });
        } else {    // 서비스 공지사항 추가
            InsertNotice(dbConn, request, response, request.param('P_CUST_CTN'), MAX_SEQ)
        }

        // var query = 'INSERT INTO TB_TN_SERVICE ' +
        //             '(P_CUST_CTN, P_INSERT_DATE, DEV_TYPE, DEV_KEY, DEV_INDEX, DEV_NM, DEV_DEPT_NM, ' +
        //             'OWNER_TYPE, N_SEQ, N_TITLE, N_CONTENT, WRITE_TIME, STATUS, INSERT_DATE, UPDATE_DATE, N_READ_FLAG, N_TYPE) ' +
        //             'VALUES ' +
        //             '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,\'1\',?) ON DUPLICATE KEY UPDATE N_READ_FLAG = \'1\'';

        // var now = new Date();
        // var insert_time = now.formatDate("yyyyMMddhhmmss");
        // var write_time = now.formatDate("yyyy-MM-dd hh:mm:ss");
        // var sql = dbConn.query(query, [request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'), request.param('DEV_TYPE'), 
        //                             request.param('DEV_KEY'), request.param('DEV_INDEX'), request.param('DEV_NM'), request.param('DEV_DEPT_NM'),
        //                             "1", MAX_SEQ, request.param('N_TITLE'), request.param('N_CONTENT'), write_time, 
        //                             "1",insert_time, insert_time, request.param("N_TYPE")], function (error, result) {
        //     logger.info('Query: ', 	query);
        //     if (error){
        //         logger.error('DB Error:', error);
        //         response.send("query error");
        //     }else {
        //         logger.info("DB Insert Success");
        //         response.send(MAX_SEQ.toString());
        //     }
        // });
    });
};

InsertNotice = function (dbConn, request, response, key ,MAX_SEQ) {

    var query = 'INSERT INTO TB_TN_SERVICE ' +
                '(P_CUST_CTN, P_INSERT_DATE, DEV_TYPE, DEV_KEY, DEV_INDEX, DEV_NM, DEV_DEPT_NM, ' +
                'OWNER_TYPE, N_SEQ, N_TITLE, N_CONTENT, WRITE_TIME, STATUS, INSERT_DATE, UPDATE_DATE, N_READ_FLAG, N_TYPE) ' +
                'VALUES ' +
                '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,\'1\',?) ON DUPLICATE KEY UPDATE N_READ_FLAG = \'1\'';

    var now = new Date();
    var insert_time = now.formatDate("yyyyMMddhhmmss");
    var write_time = now.formatDate("yyyy-MM-dd hh:mm:ss");
    var sql = dbConn.query(query, [key, request.param('P_INSERT_DATE'), request.param('DEV_TYPE'), 
                                request.param('DEV_KEY'), request.param('DEV_INDEX'), request.param('DEV_NM'), request.param('DEV_DEPT_NM'),
                                "1", MAX_SEQ, request.param('N_TITLE'), request.param('N_CONTENT'), write_time, 
                                "1",insert_time, insert_time, request.param("N_TYPE")], function (error, result) {
        logger.info('Query: ', 	query);
        if (error){
            logger.error('DB Error:', error);
            response.send("query error");
        }else {
            logger.info("DB Insert Success");
            response.send(MAX_SEQ.toString());
        }
    });
}

exports.SelectNoticeDataOnChannel = function (dbConn, request, response) {
    
    var now = new Date();            
    var now_date = now.formatDate("yyyyMMddhhmmss");    

    var cust_ctn = request.param('P_CUST_CTN');
    var insert_date = request.param('P_INSERT_DATE');

    var query;
    query = 
    'SELECT * ' +
    'FROM ' +
        '(SELECT * ' +
        'FROM  ' +
            '(SELECT ifnull(b.ADMIN_NM,a.N_ADMIN) DEV_NM ' +
             ',ifnull(ADMIN_DEPT_NM,"") DEV_DEPT_NM ' +
             ',a.N_TITLE, a.N_CONTENT,SEQ N_SEQ, a.N_INSERTDATE INSERT_DATE ' +
             ',DATE_FORMAT(N_SENDDATE,"%Y-%m-%d %T") WRITE_TIME ' +
             ',1 N_TYPE ' +
             ',ifnull(c.N_READ_FLAG, 0) N_READ_FLAG ' +
            'FROM TB_NOTICE_POPUP a LEFT JOIN TB_ADMIN b ON a.N_ADMIN = b.ADMIN_ID ' +
            'LEFT JOIN TB_TN_SERVICE c ON a.SEQ = c.P_CUST_CTN AND c.DEV_KEY = \'' + request.session.userid + '\' ' +
            'WHERE N_F_DATE <= \'' + now_date + '\' AND N_T_DATE > \'' + now_date + '\' ' +
            'AND N_SENDDATE != \'\' ' +
            'ORDER BY N_SENDDATE DESC ' +
            'LIMIT 2 ' +
        ') a1 ' +
        'UNION ALL ' +
            'SELECT * ' +
            'FROM ' +
                '(SELECT distinct ifnull(c.ADMIN_NM, b.DEV_NM) ADMIN_NM, a.DEV_DEPT_NM, a.N_TITLE, a.N_CONTENT, a.N_SEQ, a.INSERT_DATE, a.WRITE_TIME, 2 N_TYPE, a.N_READ_FLAG ' +
                'FROM TB_TN_SERVICE a ' +
                'LEFT JOIN TB_TN_SERVICE b ON a.P_CUST_CTN = b.P_CUST_CTN AND a.P_INSERT_DATE = b.P_INSERT_DATE AND b.OWNER_TYPE = \'1\' ' +
                'LEFT JOIN TB_ADMIN c ON b.DEV_KEY = c.ADMIN_ID ' +
                'WHERE a.P_CUST_CTN = \'' + request.param('P_CUST_CTN') + '\' and a.P_INSERT_DATE = \'' + request.param('P_INSERT_DATE') + '\' ' +
                'and a.DEV_KEY = \''+ request.session.userid + '\' AND a.N_TYPE = \'2\' ' +
                'ORDER BY WRITE_TIME DESC LIMIT 5 ' +
        ') a2 ' +
    ') a3 ';
                                
    logger.info('Query:', query);                        
    dbConn.query(query, function (error, results) {        
        if (error) {
            logger.error('DB Error:', error);
            response.send("query error");
        } else {
            logger.info('DB Success:');            
            response.send(results);
        }
    });
}

exports.UpdateNoticeDataOnChannel = function (dbConn, request, response) {

    var query = 'UPDATE TB_TN_SERVICE SET N_TITLE = ?, N_CONTENT = ?, WRITE_TIME = ?, UPDATE_DATE = ?, STATUS = ? ' +
                'WHERE P_CUST_CTN = ? AND P_INSERT_DATE = ? AND OWNER_TYPE = ? AND N_SEQ = ?';

    var now = new Date();            
    var update_time = now.formatDate("yyyyMMddhhmmss");
    var write_time = now.formatDate("yyyy-MM-dd hh:mm:ss");
    var sql = dbConn.query(query, [request.param('N_TITLE'), request.param('N_CONTENT'), write_time, update_time, "2",
                                   request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'), "1", request.param('N_SEQ')], function (error, result) {
    	
    	if(error) {
    		logger.error('DB Error: ',error);
            response.send("query error");
    	}else {
            logger.info("DB Update Success");
            response.send(request.param('N_SEQ'));
    	}
    });

    logger.info('Query:', sql.sql); 
}

exports.UpdateSystemNoticeChangeStatus = function (dbConn, request, response) {
    var query = "UPDATE TB_TN_SERVICE " +
    "SET N_READ_FLAG = '1' " +
    "WHERE P_CUST_CTN = '" + request.param("P_CUST_CTN") + "' AND P_INSERT_DATE = '" + request.param("P_INSERT_DATE") + 
    "' AND DEV_KEY = '" + request.session.userid + "' AND N_SEQ = " + request.param("N_SEQ");

    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
        }
    });
}

exports.UpdateSystemNoticeResend = function (dbConn, request, response) {
    var query = "UPDATE TB_TN_SERVICE " +
    "SET N_READ_FLAG = '0' " +
    "WHERE P_CUST_CTN = '" + request.param("P_CUST_CTN") + "'";

    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
        }
    });    
}

exports.getSystemNoticeContent = function (dbConn, request, response) {
    var query = "SELECT N_CONTENT FROM TB_NOTICE_POPUP WHERE SEQ = '" + request.param("P_CUST_CTN") + "'";
    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
            response.send(results[0]);
        }
    });    
}

exports.getServiceNoticeContent = function (dbConn, request, response) {
    var query = "SELECT N_CONTENT FROM TB_TN_SERVICE " +
                "WHERE P_CUST_CTN = '" + request.param("P_CUST_CTN") +"' AND WRITE_TIME = '" + request.param("WRITE_TIME") + 
                "' AND OWNER_TYPE = '1' AND N_SEQ = '" + request.param("N_SEQ") + "'";

    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
            response.send(results[0]);
        }
    });    
}