var logger = require('./logger');
var util = require('util');
var EventEmitter   = require('events').EventEmitter;
var Result = require('./Result');
var fs = require('fs');
var querystring = require('querystring');
// var entries = require('object.entries');
// var utilLib = require('./utilLib.js');

module.exports = CloudHistory;

function CloudHistory () {
}

CloudHistory.prototype.reqUploadHistory = function (dbConn, key, input, callback) {
    var query = util.format("" +
    "UPDATE TB_FILE_REQ_UPLOAD_HISTORY " +
    "    SET ACCESS_TOKEN= '%s', UCLOUD_SERVER_INFO= '%s', FOLDER_ID= '%s', UPLOAD_NAME= '%s', TRACE_ID= '%s', UPLOAD_ID= '%s' " +
    "    ,OFFSET= '%s', UPLOAD_FIN= '%s', UPLOAD_MODE= '%s', FILE_ID= '%s', ENCODING_YN= '%s', OVER_FLAG= '%s', UPDATE_DATE= %s  " +
    "WHERE  " +
    "    SYS_TYPE = '%s' AND REQ_TYPE = '%s' AND DEV_KEY = '%s' AND IDENTIFICATION = '%s'"
    , input.ACCESS_TOKEN, input.UCLOUD_SERVER_INFO, input.FOLDER_ID, input.UPLOAD_NAME, input.TRACE_ID, input.UPLOAD_ID
    , input.OFFSET, input.UPLOAD_FIN, input.UPLOAD_MODE, input.FILE_ID, input.ENCODING_YN, input.OVER_FLAG, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
    , key.SYS_TYPE, key.REQ_TYPE, key.DEV_KEY, key.IDENTIFICATION);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {        
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}

CloudHistory.prototype.reqDownloadHistory = function (dbConn, key, input, callback) {
    var query = util.format("" +
    "INSERT INTO TB_FILE_REQ_DOWNLOAD_HISTORY " +
    "    (SYS_TYPE, REQ_TYPE, USER_ID, IDENTIFICATION, FILE_TYPE, FILE_NAME, FILE_SIZE, ACCESS_TOKEN, UCLOUD_SERVER_INFO  " +
    "    ,NONCE, FILE_ID, ADJUSTABLE_YN, SHARE_IMORY_ID, ENC_TYPE, STATUS, INSERT_DATE, UPDATE_DATE, CUSTOMER_CODE)  " +
    "VALUES  " +
    "    ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, %s, '%s') "
    ,key.SYS_TYPE, key.REQ_TYPE, key.USER_ID, input.IDENTIFICATION, input.FILE_TYPE, input.FILE_NAME, input.FILE_SIZE, input.ACCESS_TOKEN, input.UCLOUD_SERVER_INFO
    ,input.NONCE, key.FILE_ID, input.ADJUSTABLE_YN, input.SHARE_IMORY_ID, input.ENC_TYPE, input.STATUS
    ,'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', input.CUSTOMER_CODE);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}

CloudHistory.prototype.resDownloadHistory = function (dbConn, key, result, callback) {
    var query = util.format("" +
    "UPDATE TB_FILE_REQ_DOWNLOAD_HISTORY " +
    "    SET STATUS= '%s', RESULT_CODE= '%s', REASON= '%s', UPDATE_DATE= %s  " +
    "WHERE  " +
    "    SYS_TYPE = '%s' AND REQ_TYPE = '%s' AND USER_ID = '%s' AND FILE_ID = '%s' AND INSERT_DATE = '%s' "
    , result.STATUS, result.RESULT_CODE, result.REASON, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
    , key.SYS_TYPE, key.REQ_TYPE, key.USER_ID, key.FILE_ID, key.INSERT_DATE);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}

// CloudHistory.prototype.updateUploadReq = function (dbConn, key, input, result, callback) {
CloudHistory.prototype.updateUploadReq = function (dbConn, key, item, callback) {
    // var query = util.format("" +
    // "UPDATE TB_FILE_MNG_HISTORY " +
    // "    SET ACCESS_TOKEN= '%s', UCLOUD_SERVER_INFO= '%s', PARENT_FOLDER_ID= '%s', FOLDER_NAME= '%s', TRACE_ID= '%s', " +
    // "    UPLOAD_ID= '%s', FOLDER_ID= '%s', FILE_ID= '%s', UCLOUD_STATUS= '%s', " +
    // "    UCLOUD_DELETE_STATUS= '%s', UCLOUD_REQ_USERID= '%s', UCLOUD_UPLOAD_REQ_DATE= '%s', " +
    // "    UPLOAD_CONTINUE_STATUS= '%s', CUSTOMER_CODE= (SELECT CODE_03 FROM TB_ADMIN WHERE ADMIN_ID = '%s'), UPDATE_DATE = %s " +
    // "WHERE  " +
    // "    SYS_TYPE = '%s' AND REQ_TYPE = '%s' AND DEV_KEY = '%s' AND IDENTIFICATION = '%s' AND FILE_NAME = '%s'"
    // , input.ACCESS_TOKEN, input.UCLOUD_SERVER_INFO, input.PARENT_FOLDER_ID, input.FOLDER_NAME, input.TRACE_ID
    // , input.UPLOAD_ID, input.FOLDER_ID, result.FILE_ID, result.UCLOUD_STATUS
    // , result.UCLOUD_DELETE_STATUS, result.USER_ID, input.UCLOUD_UPLOAD_REQ_DATE
    // , result.UPLOAD_CONTINUE_STATUS, result.USER_ID, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
    // , key.SYS_TYPE, key.REQ_TYPE, key.DEV_KEY, key.IDENTIFICATION, key.FILE_NAME);
    var query = createUpdateSql('TB_FILE_MNG_HISTORY', key, item);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}
// CloudHistory.prototype.updateUploadRes = function (dbConn, key, result, callback) {
CloudHistory.prototype.updateUploadRes = function (dbConn, key, item, callback) {
    // var query = util.format("" +
    // "UPDATE TB_FILE_MNG_HISTORY " +
    // "SET " +
    // "    UCLOUD_STATUS = '%s' " +
    // "    ,UCLOUD_RESULT_CODE = '%s' " +
    // "    ,UCLOUD_REASON = '%s' " +
    // "    ,UCLOUD_DELETE_STATUS = '%s' " +
    // "    ,UCLOUD_UPLOAD_RES_DATE = %s " +
    // "    ,UPDATE_DATE = %s " +
    // "WHERE " +
    // "    SYS_TYPE = '%s' " +
    // "    AND REQ_TYPE = '%s' " +
    // "    AND DEV_KEY = '%s' " +
    // "    AND IDENTIFICATION = '%s' " +
    // "    AND FILE_NAME = '%s'"
    // , result.UCLOUD_STATUS, result.UCLOUD_RESULT_CODE, result.UCLOUD_REASON, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
    // , key.SYS_TYPE, key.REQ_TYPE, key.DEV_KEY, key.IDENTIFICATION, key.FILE_NAME);
    var query = createUpdateSql('TB_FILE_MNG_HISTORY', key, item);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}
CloudHistory.prototype.updateCreateFolderRes = function (dbConn, key, item, callback) {
    logger.info('updateCreateFolderRes', key, item);
    var query = createUpdateSql('TB_FILE_REQ_UPLOAD_HISTORY', key, item);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(false);
        } else {
            logger.info('DB Success: ');
            callback(true);
        }
    });
}


CloudHistory.prototype.updateStatusFolderDelete = function (dbConn, identification, callback) {
    var query = util.format("" +
    "UPDATE TB_FILE_MNG_HISTORY " +
    "SET UCLOUD_DELETE_STATUS = '1' " +
    "WHERE IDENTIFICATION = '%s'", identification);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            logger.info('DB Success: ');
            callback(null, true);
        }
    });
}

CloudHistory.prototype.updateStatusFileDelete = function (dbConn, file_id, callback) {
    var query = util.format("" +
    "UPDATE TB_FILE_MNG_HISTORY " +
    "SET UCLOUD_DELETE_STATUS = '1' " +
    "WHERE FILE_ID = '%s'", file_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            logger.info('DB Success: ');
            callback(null, true);
        }
    });
}

// CloudHistory.prototype.isRetryUploadFile = function (dbConn, folder_id, file_id, callback) {
CloudHistory.prototype.isRetryUploadFile = function (dbConn, fileName, callback) {
    var query = util.format("" +
    "SELECT UCLOUD_STATUS FROM TB_FILE_MNG_HISTORY " +
    "WHERE FILE_NAME = '%s'", fileName);
    // "WHERE FOLDER_ID = '%s' AND FILE_ID = '%s'", folder_id, file_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            logger.info('DB Success: ');
            if (results.length == 0) {      // 폴더 내에 같은 파일 없음
                callback(null, false);
            } else {
                if (results[0].UCLOUD_STATUS == '9') {      // 전송 이력 있음
                    callback(null, true);
                } else {                                    // 요청중 || 업로드중 || 업로드 완료 상태
                    callback(error, false);
                }
            }
        }
    });
}

// 고객사 별 유요한 토큰 존재 확인 및 토큰 값 가져오기
CloudHistory.prototype.getAvailableToken = function (dbConn, admin_id, callback) {
    var query = util.format("" +
    // "SELECT ACCESS_TOKEN, F_KEY, EXPIRE_DATE " +
    // "FROM TB_CUSTOMER " +
    // "WHERE ADMIN_ID = '%s'", admin_id);
    // "WHERE ADMIN_ID = '%s' AND EXPIRE_DATE > CAST(UNIX_TIMESTAMP(NOW(3))*1000 as CHAR(13))", admin_id);
    "SELECT b.ACCESS_TOKEN, b.EXPIRE_DATE, b.F_KEY, b.ADMIN_ID " +
    "FROM TB_ADMIN a LEFT JOIN TB_CUSTOMER b " +
    "ON a.CODE_03 = b.CUSTOMER_CODE " +
    "WHERE a.ADMIN_ID = '%s'", admin_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            logger.info('DB Success: ', results);
            // if (results[0].ACCESS_TOKEN == '' || Number(results[0].EXPIRE_DATE) < Number(new Date().getTime())) {      // 유효한 토큰 존재하지 않다면 토큰 발급을 위한 f_key 리턴            
            if (results.length > 0) {
                if (Number(results[0].EXPIRE_DATE) < Number(new Date().getTime())) {      // 유효한 토큰 존재하지 않다면 토큰 발급을 위한 f_key 리턴
                    // callback(null, false, results[0].F_KEY);
                    callback(null, false, results[0]);
                } else {                        // 유효한 토큰 존재한다면 토큰 리턴
                    callback(null, true, results[0]);
                    // callback(null, true, results[0].ACCESS_TOKEN);
                }    
            } else {
                logger.info('유효한 f_key 존재하지 않음')
                // callback(null, false, results[0]);
            }
        }
    });
}

// 고객사 별 유요한 토큰 존재 확인 및 토큰 값 가져오기
// CloudHistory.prototype.getAvailableTokenfromCode = function (dbConn, customer_code, callback) {
//     var query = util.format("" +
//     "SELECT ACCESS_TOKEN, EXPIRE_DATE, F_KEY " +
//     "FROM TB_CUSTOMER WHERE CUSTOMER_CODE = '%s' ", customer_code);
//     logger.info('Query: ', query);
//     dbConn.query(query, function(error, results) {
//         if (error) {        // 쿼리 오류
//             logger.error('DB Error: ', error);
//             callback(error, false);
//         } else {
//             logger.info('DB Success: ', results);
//             if (Number(results[0].EXPIRE_DATE) < Number(new Date().getTime())) {      // 유효한 토큰 존재하지 않다면 토큰 발급을 위한 f_key 리턴
//                 callback(null, false, results[0]);
//             } else {                        // 유효한 토큰 존재한다면 토큰 리턴
//                 callback(null, true, results[0]);
//             }
//         }
//     });
// }

// 고객사 별 토큰 및 유효기간 DB에 저장
CloudHistory.prototype.updateToken = function (dbConn, admin_id, API_TOKEN, callback) {
    var query = util.format("" +
    "UPDATE TB_CUSTOMER " +
	"SET ACCESS_TOKEN = '%s', EXPIRE_DATE = '%s' " +
    "WHERE ADMIN_ID = '%s'", API_TOKEN.accessToken, API_TOKEN.expireDate, admin_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            callback(null, true, API_TOKEN.accessToken);
        }
    });
}

// 생성된 F_key가 존재하는지 여부
CloudHistory.prototype.isCreatedFKey = function (dbConn, admin_id, callback) {
    var query = util.format("" +
    "SELECT F_KEY FROM TB_CUSTOMER WHERE ADMIN_ID = '%s'", admin_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false, null);
        } else {
            if (results[0].F_KEY == "" || results[0].F_KEY == "undefined" || results[0].F_KEY == null) {
                callback(null, false, null);
            } else {
                callback(null, true, results[0].F_KEY);
            }
        }
    });
}

// 생성된 계정으로 클라우드 f_key 발급하여 DB에 저장
CloudHistory.prototype.insertFKey = function (dbConn, admin_id, f_key, callback) {
    var query = util.format("" +
    "UPDATE TB_CUSTOMER " +
	"SET F_KEY= '%s' " +
    "WHERE ADMIN_ID = '%s'", f_key, admin_id);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            callback(null, true);
        }
    });
}

CloudHistory.prototype.insertFolderId = function (dbConn, type, dev_key, folder_id, callback) {
    var updateSet = '';
    if (type == 'ROOT') {
        updateSet = util.format("SET ROOT_FOLDER_ID = '%s' ", folder_id);
    } else if (type == 'UPLOAD') {
        updateSet = util.format("SET UPLOAD_FOLDER_ID = '%s' ", folder_id);
    } else if (type == 'RT_SNAPSHOT') {
        updateSet = util.format("SET RTSNAPSHOT_FOLDER_ID = '%s' ", folder_id);
    } else if (type == 'RT_VIDEO') {
        updateSet = util.format("SET RTVIDEO_FOLDER_ID = '%s' ", folder_id);
    }

    var query = util.format("" +
    "UPDATE TB_DRON_SETUP_INFO " + updateSet + " WHERE DEV_KEY = '%s'", dev_key);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false);
        } else {
            callback(null, true);
        }
    });
};

CloudHistory.prototype.getParentFolderId = function (dbConn, dev_key, folderTypeName, callback) {

    var select = "";
    if (folderTypeName == 'UPLOAD') {
        select = "SELECT UPLOAD_FOLDER_ID folderId ";
    } else if (folderTypeName == 'RT_SNAPSHOT') {
        select = "SELECT RTSNAPSHOT_FOLDER_ID folderId ";
    } else {        // 'RT_VIDEO'
        select = "SELECT RTVIDEO_FOLDER_ID folderId ";
    }

    var query = util.format(select +
    "FROM TB_DRON_SETUP_INFO WHERE DEV_KEY = '%s'", dev_key);    
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false, null);
        } else {
            callback(null, true, results[0]);
        }
    });
}

CloudHistory.prototype.isCreatedFolderId = function (dbConn, folder_name, folderType, callback) {

    var query = util.format("" +
    "SELECT COUNT(IFNULL(FOLDER_ID, NULL)) CNT, FOLDER_ID, PARENT_FOLDER_ID, FOLDER_NAME FROM TB_FILE_REQ_UPLOAD_HISTORY " +
    " WHERE IDENTIFICATION = '%s' AND REQ_TYPE = '%s'", folder_name, folderType);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {        // 쿼리 오류
            logger.error('DB Error: ', error);
            callback(error, false, null);
        } else {
            if (results[0].CNT > 0) {
                callback(null, true, results[0]);
            } else {
                callback(null, false, null);
            }
        }
    });
}

function createUpdateSql(table, key, item) {
    // table문 구성
    var sqlquery = "UPDATE " + table

    // set문 구성
    entries(item).forEach(function (key, index) {
        if (index == 0) {
            sqlquery += " SET ";
        } else if (index > 0) {
            sqlquery += ", "
        }
        if (typeof key[1] === "string") {
            sqlquery += key[0] + " = '" + key[1] + "' ";
        } else if (typeof key[1] === "number") {
            sqlquery += key[0] + " = " + key[1] + ' ';
        } else if (typeof key[1] === "object") {
            if (key[1] instanceof Date) {
                sqlquery += key[0] + " = '" + key[1].formatDate("yyyyMMddhhmmss") + "' ";
            } else {
                new Error("object type is not used");
            }
        }
    })

    // where문 구성
    entries(key).forEach(function (key, index) {
        if (index == 0) {
            sqlquery += "WHERE ";
        } else if (index > 0) {
            sqlquery += " AND "
        }
        if (typeof key[1] === "string") {
            sqlquery += key[0] + " = '" + key[1] + "'";
        } else if (typeof key[1] === "number") {
            sqlquery += key[0] + " = " + key[1];
        } else {
            new Error("object type is not used");
        }    
    })

    return sqlquery;
}