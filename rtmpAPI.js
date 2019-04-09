var util = require('util');
var winston = require('winston');
var moment = require('moment');
var utilLib = require('./public/javascripts/utilLib');

var logger = new (winston.Logger)({
    transports: [
        new winston.transports.DailyRotateFile({
            name: 'dailyInfoLog',
            level: 'info',
            filename: '/LCS/daily-',
            timestamp: function () { return moment().format("YYYY-MM-DD HH:mm:ss.SSS"); },
            datePattern : 'yyyyMMdd.log',
            json: false
        })
    ]
});

exports.GetRtmpCount = function (dbConn, dept_code_03, callback) {
	var query = 'select count(*) as cnt from TB_RTMP_SETUP_INFO ';
	query += 'where DEPT_CODE_03 = \''+dept_code_03+'\' ';
        
    dbConn.query(query, function (error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            callback(results[0]);
        }
    });
};

exports.GetRtmpsearchCount = function (dbConn, rtmp_id, rtmp_nm, ctl_nm, dept_code_03, callback) {
	
    var query = 'select count(*) as cnt ';
	    query += 'from TB_RTMP_SETUP_INFO a ';
		query += 'left join( ';
		query += 'select SEQ, CTL_NM from TB_CONTROL) b '	
		query += 'on a.CTL_SEQ = b.SEQ '
		query += 'where 1=1 ';
		query += 'and a.DEPT_CODE_03 = \''+dept_code_03+'\' '

	if (rtmp_id !== '') {
		query += 'and REG_ID like \"%' +rtmp_id+ '%\" ';
	}
	if (rtmp_nm !== 'all') {
		query += 'and DEVICE_NM like \"%' +rtmp_nm+ '%\" ';
	}    	
	if (ctl_nm !== '') {
		query += 'and b.CTL_NM like \"%' + ctl_nm + '%\" ';
	}
        
    dbConn.query(query, function (error, results) {
        
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            callback(results[0]);
        }
    });
};


exports.GetRtmpControlList = function (dbConn, code3, callback) {
	var query = 'select * from TB_CONTROL where CODE_03 =  \''+code3+'\' ';

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

exports.GetRtmpAdd = function (dbConn, rtmp_id, rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_code_03, dept_nm, ctn, arank, callback) {
	
	var query = 'INSERT INTO TB_RTMP_SETUP_INFO (REG_ID, DEVICE_NM, CTL_SEQ, CONN_URL, NM, DEPT_CODE_01, DEPT_CODE_02, DEPT_CODE_03, DEPT_NM, ARANK, CTN) ';
		query += 'VALUES (?, ?, ?, CONCAT((select C_VALUE from TB_COMMON where C_NAME = "RTMP_URL"),\''+rtmp_id+'\'), ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [rtmp_id, rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_code_03, dept_nm, arank, ctn], function (error, results) {
        
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            callback(rtmp_id);
        }
    });
};

exports.GetRtmpModify = function (dbConn, rtmp_id, rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_nm, ctn, arank, callback) {
	var query = 'UPDATE TB_RTMP_SETUP_INFO SET DEVICE_NM=?, CTL_SEQ=?, NM=?, DEPT_CODE_01=?, DEPT_CODE_02=?, DEPT_NM=?, ARANK=?, CTN=? WHERE REG_ID=?';
    dbConn.query(query, [rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_nm, arank, ctn, rtmp_id], function (error, result) {
    	callback(rtmp_id);
    });
};


exports.GetRtmpPaging = function (dbConn, start, pageSize, rtmp_id, rtmp_nm, ctl_nm, type, dept_code_03, response, request, callback) {
	var query = 'select a.*, ';
	query += 'b.CTL_NM ';
	query += 'from TB_RTMP_SETUP_INFO a ';
	query += 'left join( ';
	query += 'select SEQ, CTL_NM from TB_CONTROL) b '	
	query += 'on a.CTL_SEQ = b.SEQ '	
	query += 'where 1=1 ';
	query += 'and a.DEPT_CODE_03 = \''+dept_code_03+'\' '
	
	if (rtmp_id !== '') {
		query += 'and REG_ID like \"%' +rtmp_id+ '%\" ';
	}
	if (rtmp_nm !== 'all') {
		query += 'and DEVICE_NM like \"%' +rtmp_nm+ '%\" ';
	}    	
	if (ctl_nm !== '') {
		query += 'and CTL_NM like \"%' + ctl_nm + '%\" ';
	}
	
	query += 'order by REG_ID ';
	
	if (type !== 'excel') {
		query += 'limit '+start+','+pageSize+' ';
	}
	
	dbConn.query(query, function (error, results, fields) {
	    logger.info('Query: ',query);
		
		if (error) {
			logger.error('DB Error: ', error);
		} else {	
			if (type == 'excel') {
	    		var filename = "RTMP_INFO.xlsx";
	    		 var excepts = [];
	    		
	    		utilLib.excelExport(request, response, results, fields, filename, excepts);
			} else {
	    		response.send(results);
			}
		}
	});
};