var util = require('util');
var winston = require('winston');
var moment = require('moment');

var LOGGER_FOLDER_PATH = '/LCS/APP/LOG/WEBAPP/daily-w';
var logger = new (winston.Logger)({
    transports: [
        new winston.transports.DailyRotateFile({
            name: 'dailyInfoLog',
            level: 'info',
            filename: LOGGER_FOLDER_PATH,
            timestamp: function () { return moment().format("YYYY-MM-DD HH:mm:ss.SSS"); },
            datePattern : 'yyyyMMdd.log',
            json: false
        })
    ]
});

exports.GetPCViewerList = function (dbConn, devKey, devType, callback) {
	
	var query;
	query = util.format(
        'SELECT a.CUST_CTN ,a.CUST_NM ,a.CUST_DEPT_NM ,min(b.STATUS) LAST_STATUS, max(SVC_TIME_ST) LAST_SVC_TIME_ST ' +
        ',b.*,ifnull(NOTICE_COUNT, 0) NOTICE_COUNT, ifnull(AR_COUNT,0) AR_COUNT, e.FEATURE_KEY ' +
		' FROM' +
		    ' ( SELECT * FROM TB_TERMINAL_IMAGE_TRANS WHERE STATUS < \'3\') a' +
		    ' LEFT JOIN' + 
		    ' (' +
		        ' SELECT ' +
					    'x.P_CUST_CTN, x.P_INSERT_DATE, DEV_TYPE, DEV_KEY, DEV_INDEX, DEV_NM, DEV_DEPT_NM, SVC_TIME_ST, SVC_TIME_ED' +
          				', SVC_IP, STATUS, VSTATUS, x.INSERT_DATE, UPDATE_DATE, SVC_TYPE, LOC_IP, CONT_PORT, DATA_PORT, RTSP_PORT' + 
			            ', MODEL, VERSION, S_WIDTH, S_HEIGTH, U_WIDTH, U_HEIGTH, M_WIDTH, M_HEIGTH, POPUP_F, LOW_QUALITY_F, BROKEN_PIPE_F' +
   	    			    ', LAST_SND_CODE, LAST_SND_TIME, LAST_RCV_CODE, LAST_RCV_TIME, DEFECT_CODE, FRAME_CNT, PLAY_INDEX, CPU_INFO, MEM_INFO' +				
		        ' FROM (  SELECT P_CUST_CTN ,P_INSERT_DATE ,MAX(INSERT_DATE) INSERT_DATE' +
		                ' FROM TB_VIEW_SERVICE' +
		                ' WHERE DEV_TYPE = \'3\' AND DEV_KEY = \'%s\'' +
		                ' GROUP BY P_CUST_CTN ,P_INSERT_DATE' +
		                ' ORDER BY INSERT_DATE DESC' +
		        ' ) y' +
		        ' LEFT JOIN TB_VIEW_SERVICE x' +
		        ' ON x.P_CUST_CTN = y.P_CUST_CTN AND x.P_INSERT_DATE = y.P_INSERT_DATE AND x.INSERT_DATE = y.INSERT_DATE' +
		        ' ORDER BY y.INSERT_DATE DESC' +
		    ' ) b' +
		    ' ON a.CUST_CTN = b.P_CUST_CTN AND a.INSERT_DATE = b.P_INSERT_DATE' +
            ' LEFT JOIN (' +
            '   SELECT P_CUST_CTN, P_INSERT_DATE, COUNT(P_CUST_CTN) AR_COUNT FROM TB_AR_SERVICE' +
            '   WHERE OWNER_TYPE = \'1\'' +
            '   GROUP BY P_CUST_CTN, P_INSERT_DATE' +
            ' ) c' +
            ' ON a.CUST_CTN = c.P_CUST_CTN and a.INSERT_DATE = c.P_INSERT_DATE' +		    	
            ' LEFT JOIN (' +
            '   SELECT P_CUST_CTN, P_INSERT_DATE, COUNT(P_CUST_CTN) NOTICE_COUNT' +
            '   FROM TB_TN_SERVICE' +
            '   WHERE OWNER_TYPE = \'1\'' +
            '   GROUP BY P_CUST_CTN, P_INSERT_DATE' +
            ') d' +
            ' ON a.CUST_CTN = d.P_CUST_CTN AND a.INSERT_DATE = d.P_INSERT_DATE' +
            ' LEFT JOIN (' +
            '   SELECT P_CUST_CTN, P_INSERT_DATE, FEATURE_KEY FROM TB_AR_SERVICE' +
            '   WHERE OWNER_TYPE = \'1\'  AND A_STATUS < \'3\' ' +
            '   GROUP BY P_CUST_CTN, P_INSERT_DATE' +
            ' ) e' +
            ' ON a.CUST_CTN = e.P_CUST_CTN and a.INSERT_DATE = e.P_INSERT_DATE' +		    	
        ' WHERE b.DEV_TYPE = \'3\' AND b.DEV_KEY = \'%s\'' +
		' GROUP BY a.CUST_CTN ,a.INSERT_DATE' +
		' HAVING DEFECT_CODE <> \'0001\'' +
		' ORDER BY a.INSERT_DATE ASC'
	, devKey, devKey);
        
    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            callback(results);
        }
    });
};

exports.GetViewerIndex = function (dbConn, DEV_KEY, DEV_TYPE, callback) {
	
	var query = util.format('SELECT' +
		    	' (COUNT(STATUS) % 9999) + 1  VIEW_INDEX' +
				' FROM TB_VIEW_SERVICE' + 
				' WHERE' +
                ' DEV_KEY = \'%s\' AND DEV_TYPE = \'%s\'', DEV_KEY, DEV_TYPE);
                
    logger.info('Query:', query);
	
    dbConn.query(query, function (error, results) {
        
        
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results); 
            callback(results);
        }
    });    
};

exports.GetViewerIndex2 = function (dbConn, viewInfo, DEV_TYPE, callback) {
	
	var query = util.format('SELECT' +
		    	' (COUNT(STATUS) % 9999) + 1  VIEW_INDEX' +
				' FROM TB_VIEW_SERVICE' + 
				' WHERE' +
		    	' DEV_KEY = \'%s\' AND DEV_TYPE = \'%s\'', viewInfo.DEV_KEY, DEV_TYPE);
	
    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results); 
            callback(results, viewInfo);
        }
    });    
};

// H.265 미지원 PC의 경우 실행 시 오류를 표시하고 종료하므로 DB 세션이 정리됨
// 따라서 종료된 거 포함하여 가장 마지막 DEV_INDEX 검색으로 변경
exports.GetViewerIndex3 = function (dbConn, P_CUST_CTN, P_INSERT_DATE, DEV_KEY, DEV_TYPE, callback) {
	logger.info('GetViewerIndex3', P_CUST_CTN, P_INSERT_DATE, DEV_KEY, DEV_TYPE)
	var query = util.format('SELECT DEV_INDEX FROM TB_VIEW_SERVICE' +
                // ' WHERE P_CUST_CTN = \'%s\' AND P_INSERT_DATE = \'%s\' AND DEV_KEY = \'%s\' and DEV_TYPE = \'%s\' AND STATUS < \'3\'' +
                ' WHERE P_CUST_CTN = \'%s\' AND P_INSERT_DATE = \'%s\' AND DEV_KEY = \'%s\' and DEV_TYPE = \'%s\' ' +
                ' ORDER BY INSERT_DATE DESC LIMIT 1', P_CUST_CTN, P_INSERT_DATE, DEV_KEY, DEV_TYPE);
    
    logger.info('Query:', query);
    dbConn.query(query, function (error, results) {
        
        
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results); 
            callback(results);
        }
    });    
};

exports.GetServiceClassPCViewer = function (dbConn, code03, callback) {
	
	var query = util.format('SELECT * FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', code03);
	
    dbConn.query(query, function (error, results) {     
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results); 
            callback(results);
        }
    });    
};

exports.playCountPCViewerOfAccount = function (dbConn, devKey, devType, callback) {
	
	var query = util.format('SELECT count(*) as CNT FROM TB_VIEW_SERVICE WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'%s\' and STATUS = \'2\'', devKey, devType);
	
	
    dbConn.query(query, function (error, results) {     
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results); 
            callback(results);
        }
    });    
};

var getCodeConnectedControl = function (dbConn, request, callback) {
    
    var query = "SELECT b.CODE_01, b.CODE_02, b.CODE_03 " +
                "FROM TB_VIEW_SERVICE a LEFT JOIN TB_TERMINAL_IMAGE_TRANS b " +
                "ON a.P_CUST_CTN = b.CUST_CTN AND a.P_INSERT_DATE = b.INSERT_DATE " +
                "WHERE a.P_CUST_CTN = '" + request.param("P_CUST_CTN") + "' AND a.P_INSERT_DATE = '" + request.param("P_INSERT_DATE") + 
                "' AND a.DEV_KEY = '" + request.session.userid + "'";
    
    logger.info('Query:', query);                
    dbConn.query(query, function (error, results) {        
        
        if (error) {
            logger.error('DB Error:', error);
            callback(null);
        } else {
            logger.info('DB Success:', results[0]);
            callback(results[0]);
        }
    });
};

exports.isAuthorityWriteNotice = function (dbConn, request, response) {

    getCodeConnectedControl(dbConn, request, function(conControl) {

        if (conControl == null) {
            response.send("실시간 공지 작성 권한을 얻오는데 오류가 발생되었습니다.");
            return;
        }

        var query = "SELECT DEV_KEY " +
                    "FROM TB_DEFAULT_CONNECT_INFO " +
                    "WHERE CODE_01 = '" + conControl.CODE_01 + "' AND CODE_02 = '" + conControl.CODE_02 + "' AND CODE_03 = '" + conControl.CODE_03 + "' " +
                    "AND DEV_TYPE = (SELECT DEFAULT_DEVICE FROM TB_CONTROL WHERE CODE_01 = '" + conControl.CODE_01 + 
                    "' and CODE_02 = '" + conControl.CODE_02 + "' and CODE_03 = '" + conControl.CODE_03 + "')";

        logger.info('Query: ', 	query);
        dbConn.query(query, function (error, results) {
            if (error){
                logger.error('DB Error:', error);
                response.send("query error");
            }else {
                logger.info("DB Success");
                // if (request.session.userlv == 1)
                //     response.send({"DEV_KEY" : request.session.userid});
                // else
                response.send(results[0]);
            }
        });        
    });
}