/**
 * @author iwsywhan
 */

var util = require('util');
const logger = require('./libs/logger')

/*
	함수 설명 : 서비스 현황에서 PUSH 메세지를 전송한 내역을 볼 수 있는 함수
			단, 하나의 단말에 대해서는 최종 결과만 보여준다.  
*/
exports.pushService = function (dbConn, pCustCtn, pInsertDate, callback){
	
	var query = util.format(' SELECT max(b.REQUEST_TIME) REQUEST_TIME ,max(b.RESPONSE_TIME) RESPONSE_TIME ,max(b.GCM_RESULT) GCM_RESULT' +
    							',max(b.GCM_ERROR) GCM_ERROR ,max(b.PUSH_STATUS) PUSH_STATUS ,max(b.RECEIVE_TIME) RECEIVE_TIME' +
    							',b.CTN, a.INSERT_DATE, c.NM, c.DEPT_NM' +
							' FROM (' +
    							' SELECT P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, PUSH_TYPE, max(INSERT_DATE) as INSERT_DATE' +
        						' FROM TB_PUSH_HISTORY' +
        						' WHERE P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'' +
        						' GROUP BY P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, PUSH_TYPE' +
    							' ) a left join TB_PUSH_HISTORY b' +
        						' on a.P_CUST_CTN = b.P_CUST_CTN' +
        						' and a.P_INSERT_DATE = b.P_INSERT_DATE' +
        						' and a.CTN = b.CTN' +
        						' and a.CUST_KEY = b.CUST_KEY' +
        						' and a.PUSH_TYPE = b.PUSH_TYPE' +
    							' left join TB_ORGANOGRAM c on a.CTN = c.CTN' +
							' GROUP BY a.P_CUST_CTN, a.P_INSERT_DATE, a.CTN, a.CUST_KEY, a.PUSH_TYPE'
							,pCustCtn, pInsertDate);
	
    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB Success:');
        			        	
        	callback(results);
        }        
    }); 	
};

/*
	함수 설명 : 서비스 현황에서 PUSH 메세지를 전송한 내역을 볼 수 있는 함수
			단, 하나의 단말에 대해서는 최종 결과만 보여준다.  
*/
exports.fullPushService = function (dbConn, pCustCtn, pInsertDate, callback){
	
	var query = util.format(' SELECT a.*, b.NM, b.DEPT_NM FROM' +
							' TB_PUSH_HISTORY a' +
							' left join TB_ORGANOGRAM b' +
							' on a.CTN = b.CTN' +
							' WHERE P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'' +
							' ORDER BY a.INSERT_DATE'
							,pCustCtn, pInsertDate);
	
    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB Success:');
        			        	
        	callback(results);
        }        
    }); 	
};

/*
	함수 설명 : 관제탑의 대표 전화를 가져오는 함수 
*/
exports.getPhoneNumberOfControl = function (dbConn, code01, code02, code03, callback){
	
	logger.info('Path change: /getPhoneNumberOfControl');
	var query = util.format('SELECT * FROM TB_CONTROL WHERE CODE_01 = \'%s\' AND CODE_02 = \'%s\' AND CODE_03 = \'%s\''
							,code01, code02, code03);
	
    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB Success:');
        			        	
        	callback(results);
        }        
    }); 	
};

/*
	함수 설명 : 관제탑의 대표 전화를 가져오는 함수 
*/
exports.getBookMarkList = function (dbConn, fav_key, callback){
	
	logger.info('Path change: /getBookMarkList');
	var query = util.format('SELECT * FROM TB_BOOKMARK_CONNECT_INFO WHERE FAV_TYPE = \'2\' AND FAV_KEY = \'%s\' ORDER BY DEV_TYPE DESC'
							,fav_key);
	
    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB Success:');
        			        	
        	callback(results);
        }        
    });
};