/**
 * @author iwsywhan
 */

var util = require('util');
var winston = require('winston');
var moment = require('moment');

var logger = new (winston.Logger)({ 
	transports: [
     new winston.transports.DailyRotateFile({
         name: 'dailyInfoLog',
         level:'info',
         filename: '/LCS/daily-',
         timestamp: function(){return moment().format("YYYY-MM-DD HH:mm:ss.SSS");},
         datePattern : 'yyyyMMdd.log',
         json:false
       })
   ]
});
/*
	함수 설명 : GCM 서버로 PUSH 하기전에 Reg ID를 얻어오는 함수  
*/
exports.GetRegIds = function (dbConn, pushTargetInfo, callback){
	logger.info('GetRegIds start');
	
	var arr = [];
	
	var mobileInfo = pushTargetInfo;
	
	var resultCnt = 0;
    if (typeof mobileInfo.mobileList != 'undefined') {
	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {
	    	
			var query = util.format('SELECT REG_ID FROM TB_PUSH_REG_INFO WHERE DEV_KEY = \'%s\' AND DEV_TYPE = \'1\'', mobileInfo.mobileList[i].ctn);
			
		    dbConn.query(query, function (error, results) {
		
				resultCnt++;
				
		        logger.info('Query:', query);
		        if (error) {
		            logger.error('DB Error:', error);
		        } else {
		        			        	
			    	if (Object.keys(results).length > 0){
			    		arr.push(results[0].REG_ID);
			    	}
			    	else{ // reg id 가 존재하지 않을 경우
			    		arr.push('');
			    	}
		        			        	
		        	logger.info('get regid arr : ', arr);
		        }
		        
		        logger.info(mobileInfo.mobileList.length + '-' + resultCnt);
		        
		        if (mobileInfo.mobileList.length == resultCnt){
					logger.info('registrationIds:', arr);
		        	callback(pushTargetInfo, arr);
		        }	        
		    });
		}    	
	}
	
	logger.info('GetRegIds end');	
};

/*
	함수 설명 : GCM 서버로 PUSH 메세지를 요청한 이력을 남기는 함수  
*/
exports.insertResult = function (dbConn, info, redIdGrp, response)
{
	var mobileInfo = info;

	// http statusCode == 200 이면 undefined 임. 이유는 200 이면 header를 제외하고 body만 넘겨줌
	//if (typeof response.statusCode == 'undefined'){
	//	response.statusCode = 200;
	//}

    if (typeof mobileInfo.mobileList != 'undefined') {

	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {

			var query;

			var insert_date = new Date().formatDate("yyyyMMddhhmmss") + '' +  new Date().getMilliseconds().toString();

			if (response == null){

				var statusCode = 408;

				query = util.format('INSERT INTO TB_PUSH_HISTORY' +
					'(P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, PUSH_TYPE, TITLE, MESSAGE, REQUEST_TIME, RESPONSE_TIME, MESSAGE_ID, HTTP_CODE, GCM_RESULT, GCM_ERROR, REG_ID, CANONICAL_ID, PUSH_STATUS, RECEIVE_TIME, INSERT_DATE) ' +
					'VALUES (\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\',\'%s\',concat(to_char(sysdate,\'yyyymmddhh24miss\'),substr(to_char(systimestamp,\'ff\'), 0, 3)))'
					,mobileInfo.MOBILE_NUM, mobileInfo.INSERT_DATE, mobileInfo.mobileList[i].ctn, mobileInfo.CUST_KEY, mobileInfo.PUSH_TYPE, mobileInfo.title, mobileInfo.content
					,mobileInfo.REQUEST_TIME, '', '', statusCode, '2', '', redIdGrp[i], '0', '0',  '');
			}else if (typeof response.statusCode == 'undefined'){

				response.statusCode = 200;

		    	var messageid = typeof response.results[i].message_id == 'undefined' ? '' : response.results[i].message_id;
		    	var gcmResult = messageid == '' ? '2' : '1';
		    	var gcmErroReason = gcmResult == 2 ? response.results[i].error : '';
		    	var canonicalid = typeof response.results[i].registration_id == 'undefined' ? '0' : '1';

				query = util.format('INSERT INTO TB_PUSH_HISTORY' +
					'(P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, PUSH_TYPE, TITLE, MESSAGE, REQUEST_TIME, RESPONSE_TIME, MESSAGE_ID, HTTP_CODE, GCM_RESULT, GCM_ERROR, REG_ID, CANONICAL_ID, PUSH_STATUS, RECEIVE_TIME, INSERT_DATE) ' +
					'VALUES (\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\',\'%s\',\'%s\')'
					,mobileInfo.MOBILE_NUM, mobileInfo.INSERT_DATE, mobileInfo.mobileList[i].ctn, mobileInfo.CUST_KEY, mobileInfo.PUSH_TYPE, mobileInfo.title, mobileInfo.content
					,mobileInfo.REQUEST_TIME, mobileInfo.responseTime, messageid, response.statusCode, gcmResult, gcmErroReason, redIdGrp[i], canonicalid, '0',  '', insert_date);
			}else {

				query = util.format('INSERT INTO TB_PUSH_HISTORY' +
					'(P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, PUSH_TYPE, TITLE, MESSAGE, REQUEST_TIME, RESPONSE_TIME, MESSAGE_ID, HTTP_CODE, GCM_RESULT, GCM_ERROR, REG_ID, CANONICAL_ID, PUSH_STATUS, RECEIVE_TIME, INSERT_DATE)' +
					'VALUES (\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\',\'%s\',\'%s\')'
					,mobileInfo.MOBILE_NUM, mobileInfo.INSERT_DATE, mobileInfo.mobileList[i].ctn, mobileInfo.CUST_KEY, mobileInfo.PUSH_TYPE, mobileInfo.title, mobileInfo.content
					,mobileInfo.REQUEST_TIME, mobileInfo.responseTime, '', response.statusCode, '2', '', '', '0', '0',  '', insert_date);
			}

			dbConn.query(query, function (error, result) {

	        	logger.info('Query:', query);

				if (error){
					logger.error('DB Error:', error);
				}else {
					logger.info('DB success');
				}
			});
	    }
	}
};

/*
	함수 설명 : GCM 서버로 PUSH 메세지를 요창하고 받은 응답에 대한 결과로 Reg id를 관리하는 함수  
*/
exports.manageRegID = function (dbConn, info, response, callback){
	logger.info('manageRegID start');
	
	if (response == null){
		callback(null);
		return;
	}
	
	var mobileInfo = info;
	
	if (response.failure > 0){
		
		logger.info('failure exists : ', response.failure);
		
		for(var i = 0; i < Object.keys(response.results).length; i++){
			if (typeof response.results[i].error != 'undefined'){
				
				if(response.results[i].error == 'Unavailable'){
					logger.info('redo push message : ', mobileInfo.mobileList[i].ctn);
													
					var obj = new Object();
					obj.name = mobileInfo.mobileList[i].name;
					obj.ctn = mobileInfo.mobileList[i].ctn;
					obj.dept = mobileInfo.mobileList[i].dept;
					
					var mobileArray = new Array();
					mobileArray.push(obj);
					
					var retransInfo = new Object();					
					retransInfo.INSERT_DATE = mobileInfo.INSERT_DATE;
					retransInfo.CTN_DEVICE  = mobileInfo.CTN_DEVICE;
					retransInfo.MOBILE_NUM  = mobileInfo.MOBILE_NUM;
					retransInfo.VIEW_TYPE   = mobileInfo.VIEW_TYPE;
					retransInfo.mobileList  = mobileArray;
										
					callback(retransInfo);
											
				} else if(response.results[i].error == 'InvalidRegistration' || response.results[i].error == 'NotRegistered'){
					logger.info('error => ' + response.results[i].error + ' : ' + mobileInfo.mobileList[i].ctn);
					
					var query = util.format('DELETE FROM TB_PUSH_REG_INFO WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'1\'', mobileInfo.mobileList[i].ctn);
									
					dbConn.query(query, function (error, result) {
					
				        logger.info('Query:', query);
				        
						if (error){
							logger.error('DB Error:', error);
						}else {
							logger.info('DB success');
						}
					});					
				}
			}
		}
	}
	
	if (response.canonical_ids > 0){
		
		logger.info('canonical_ids exists : ', response.canonical_ids);
		
		var updateCnt = 0;
		for(var i = 0; i < Object.keys(response.results).length; i++){
			if (typeof response.results[i].registration_id != 'undefined'){
				logger.info('canonical_ids => ' + response.results[i].registration_id + ' : ' + mobileInfo.mobileList[i].ctn);
				
				var query = util.format('UPDATE TB_PUSH_REG_INFO SET REG_ID = \'%s\' WHERE DEV_KEY = \'%s\' AND DEV_TYPE = \'1\''
				,response.results[i].registration_id, mobileInfo.mobileList[i].ctn);
								
				dbConn.query(query, function (error, result) {
				
			        logger.info('Query:', query);
			        
					if (error){
						logger.error('DB Error:', error);
					}else {
						logger.info('DB success');
					}
				});				
			}
		}	
	}
	
	callback(null);
};


/*
	함수 설명 : 단말로부터 받은 Reg id가 유효한지를 검사하는 함수  
*/
exports.checkValidRegID = function (dbConn, info, callback){
	
	var query = util.format('SELECT REG_ID FROM TB_PUSH_REG_INFO WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'%s\''
	,info.MOBILE_NUM, '1');
					
	dbConn.query(query, function (error, result) {
	
        logger.info('Query:', query);
        
		if (error){
			logger.error('DB Error:', error);
		}else {
			logger.info('DB success');
			
			callback(error, result);
		}
	});				
};


/*
	함수 설명 : PUSH 메세지를 받은 단말에 대한 정보를 이력으로 남기는 함수   
*/
exports.insertPushResponseHistory = function (dbConn, info, callback){
		
	var PUSH_STATUS = info.SERVICE == 'Y' ? '1' : '2';
		
	var insert_date = new Date().formatDate("yyyyMMddhhmmss") + '' +  new Date().getMilliseconds().toString();	  
	var query = util.format('INSERT INTO TB_PUSH_HISTORY(P_CUST_CTN,P_INSERT_DATE,CTN,CUST_KEY,PUSH_TYPE,TITLE,MESSAGE,REQUEST_TIME,RESPONSE_TIME,MESSAGE_ID,HTTP_CODE,GCM_RESULT,GCM_ERROR,REG_ID,CANONICAL_ID,PUSH_STATUS,RECEIVE_TIME,INSERT_DATE)' +
							'VALUES(\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'\', \'\', \'%s\', \'\', \'\', \'\', \'\', \'\', \'\', \'\', \'%s\',\'%s\',\'%s\')'
							,info.P_CUST_CTN, info.P_INSERT_DATE, info.MOBILE_NUM, info.CUST_KEY, info.PUSH_TYPE, info.REQUEST_TIME, PUSH_STATUS, info.RECV_TIME, insert_date);
 
	dbConn.query(query, function (error, result) {
	
        logger.info('Query:', query);
        
		if (error){
			logger.error('DB Error:', error);
		}else {
			logger.info('DB success');
			
			callback();			
		}
	});
};

/*
	함수 설명 : 단말에 대한 Reg id가 존재하는지 판단하는 함수   
*/
exports.IsExistRegid = function (dbConn, dev_key, dev_type, callback) {
	var query = util.format('SELECT count(*) COUNT FROM TB_PUSH_REG_INFO WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'%s\'' 
							,dev_key ,dev_type);
 
	dbConn.query(query, function (error, result) {
        logger.info('Query:', query);
		if (error) {
			logger.error('DB Error:', error);
			res.status(500).send('DB ' + error);
		} else {
			logger.info('DB success');		
			callback(result);
		}
	});	
};
