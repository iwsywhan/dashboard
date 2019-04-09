var logger = require('./logger');
var util = require('util');
var EventEmitter   = require('events').EventEmitter;
var Result = require('./Result');
var app = require('../app.js')
var ObjectAPI = require('./AnalysisObjectLib');
var fs = require('fs')

var objectAPI = new ObjectAPI;

util.inherits(DroneResult, EventEmitter);
// util.inherits(DroneResult, Result);
function DroneResult() {
    this._res = null;

    this.on('startRecording', function(resData) {
        this.sendResult(resData);
        // if (resData.header.resultCode == "0000") {
        //     objectAPI.serviceNotification('1', resData.body, function(err, bResult, result) {
        //         logger.info('serviceNotification(1)', err, bResult, result);
        //     });
        // }
    });

    this.on('stopRecording', function(resData) {
        this.sendResult(resData);
        // if (resData.header.resultCode == "0000") {
        //     objectAPI.serviceNotification('2', resData.body, function(err, bResult, result) {
        //         logger.info('serviceNotification(2)', err, bResult, result);
        //     });
        // }
    });

    this.on('startSnapshot', function(resData) {
        this.sendResult(resData);
    });

    this.on('upload', function(resData) {
        this.sendResult(resData);
    });

    this.on('startStreaming', function(resData) {
        // this.sendResult(resData);
        logger.info('startStreaming', resData);
        this.getMetaData(app.dbConn, resData.body.MOBILE_NUM, resData.body.VIEW_INDEX, this._res);
    });
    
    this.on('encrypt', function(resData) {
        logger.info('encrypt', resData);
        this.sendResult(resData);
    })    
}

DroneResult.prototype = new Result();

DroneResult.prototype.setResponse = function (res) {
    this._res = res;
}

DroneResult.prototype.sendResult = function (resData) {
    logger.info('EventEmitter', JSON.stringify(resData));
    if (resData.header.resultCode == "0000") {
        this._res.send({ RESULT_CODE: resData.header.resultCode, RESULT_MESSAGE: resData.body });
    } else {
        if (resData.header.command == 'B904') {
            app._io.sockets.emit('B904', '드론 사용 불가.');
            return ;
        }

        if (resData.header.command == 'B171' && resData.header.resultCode == "5121") {
            this._res.send({ RESULT_CODE: resData.header.resultCode, RESULT_MESSAGE: resData.body.REASON });
        } else {
            this._res.status(500).send({ RESULT_CODE: resData.header.resultCode, RESULT_MESSAGE: resData.body.REASON });
        }
    }
}

DroneResult.prototype.authorization = function (dbConn, ID, LC_CUST_CODE, res, callback) {
    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_ADMIN WHERE ADMIN_ID = '%s' AND CODE_03 = '%s'", ID, LC_CUST_CODE);
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ');
            if (results[0].CNT > 0) {
                callback(true);
            } else {
                res.status(401).send({RESULT_CODE:"1004", RESULT_MESSAGE:"미 인증 요청"});
                callback(false);
            }
        }
    });
}

DroneResult.prototype.isDuplicate = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_SETUP_INFO WHERE DEV_KEY = '%s'", req.body.D_ID);

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ', req.body.CHECK_ID);
            if (results[0].CNT > 0) {                
                res.status(500).send({RESULT_CODE:"1021", RESULT_MESSAGE:"생성 디바이스 존재"});
                callback(false);
            } else {
                callback(true);
            }
        }
    });
}

DroneResult.prototype.isEntry = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_SETUP_INFO WHERE DEV_KEY = '%s' AND DEPT_CODE_03 = '%s'"
    , req.body.D_ID, req.body.LC_CUST_CODE);

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ', req.body.CHECK_ID);
            if (results[0].CNT == 0) {                
                res.status(500).send({RESULT_CODE:"1025", RESULT_MESSAGE:"존재하지 않는 드론정보"});
                callback(false);
            } else {
                callback(true);
            }
        }
    });
}

DroneResult.prototype.isReady = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT SVC_TYPE, STATUS FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS < '3'"
    , req.body.D_ID);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ');
            if (results.length == 0) {
                res.status(500).send({RESULT_CODE:"1101", RESULT_MESSAGE:"디바이스 연결 해제 상태"});
                callback(false);
            } else {
                if (results[0].SVC_TYPE == 0 && results[0].STATUS == 1) {
                    callback(true);
                } else if (results[0].STATUS == 2) {
                    res.status(500).send({RESULT_CODE:"1121", RESULT_MESSAGE:"이미 영상 촬영 실행 중"});
                    callback(false);
                }
            }
        }
    });
}

DroneResult.prototype.isEnableSnapShot = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS < '3'"
    , req.body.D_ID);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            logger.error({RESULT_CODE:"1000", RESULT_MESSAGE:error.code})
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ');
            if (results[0].CNT == 0) {
                logger.info({RESULT_CODE:"1101", RESULT_MESSAGE:"실행 중인 서비스 없음"})
                res.status(500).send({RESULT_CODE:"1101", RESULT_MESSAGE:"실행 중인 서비스 없음"});
                callback(false);
            } else {
                callback(true);
            }
        }
    });
}

DroneResult.prototype.isRunning = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT COUNT(*) CNT FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS = '2'"
    , req.body.D_ID);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ');
            if (results[0].CNT == 0) {
                res.status(500).send({RESULT_CODE:"1101", RESULT_MESSAGE:"실행 중인 서비스 없음"});
                callback(false);
            } else {
                callback(true);
            }
        }
    });
}

DroneResult.prototype.getAccountDefaultConnected = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT DEV_KEY FROM TB_DEFAULT_CONNECT_INFO WHERE CODE_01 = '900' AND CODE_02 = '999' AND CODE_03 = '%s' AND DEV_TYPE = '3'"
    , req.body.LC_CUST_CODE);
    logger.info('Query: ', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            logger.info('DB Success: ');
            if (results[0].CNT == 0) {
                res.status(500).send({RESULT_CODE:"1123", RESULT_MESSAGE:"수신 가능한 최대 세션 수 초과"});
                callback(false);
            } else {
                callback(result[0]);
            }
        }
    });
}

DroneResult.prototype.insertDrone = function (dbConn, req, res, ip, webport, streamport) {
    // CODE_01, CODE02, UTM_ID 컬럼 필요
    // var rtspUrl = 'rtsp://' + ip + ":" + webport + "/" + req.body.D_ID + "/" + streamport;
    var query = util.format("INSERT INTO TB_DRON_SETUP_INFO (" +
        "DEV_KEY, DEV_NM, DEPT_CODE_01, DEPT_CODE_02, DEPT_CODE_03, CTN, RTSP_URL, INSERT_DATE, UPDATE_DATE)" +
        "VALUES(" +
        "'%s','%s','%s','%s','%s','%s','%s', %s, %s)"
        ,req.body.D_ID, req.body.D_NAME, '900', '999', req.body.LC_CUST_CODE, req.body.D_CTN, '', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")');
    
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리"});
        } 
    });    
}

DroneResult.prototype.modifyDrone = function (dbConn, req, res) {
    // CODE_01, CODE02, UTM_ID 컬럼 필요
    var query = util.format("UPDATE TB_DRON_SETUP_INFO " +
        "SET DEV_NM = '%s', CTN = '%s', UPDATE_DATE = %s " +
        "WHERE DEV_KEY = '%s' AND DEPT_CODE_03 = '%s'"
        ,req.body.D_NAME, req.body.D_CTN, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', req.body.D_ID, req.body.LC_CUST_CODE);
    
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리"});
        } 
    });   
}

DroneResult.prototype.deleteDrone = function (dbConn, req, res) {
    // CODE_01, CODE02, UTM_ID 컬럼 필요
    var query = util.format("DELETE FROM TB_DRON_SETUP_INFO " +
    "WHERE DEV_KEY = '%s' AND DEPT_CODE_03 = '%s'"
    ,req.body.D_ID, req.body.LC_CUST_CODE);
    
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리"});
        } 
    });   
}

DroneResult.prototype.getMetaData = function (dbConn, droneSN, view_index, res) {

    var query = util.format("SELECT b.URL, CASE WHEN CAMERA_TYPE = '3' THEN '1' ELSE '2' END D_CAM_TYPE, " +
    "CASE WHEN WIDTH = '1920' THEN '3' WHEN WIDTH = '1280' THEN '2' ELSE '1' END D_RESOLUTION " +
    "FROM TB_TERMINAL_IMAGE_TRANS a LEFT JOIN TB_VIEW_SERVICE b " +
    "ON a.CUST_CTN = b.P_CUST_CTN " + 
    "WHERE a.DEV_TYPE = '4' AND a.CUST_CTN = '%s' AND a.STATUS = '2' AND b.STATUS < '3' AND b.DEV_INDEX = '%s'"
    ,droneSN, view_index);

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            if (results.length == 0) {
                res.status(500).send({RESULT_CODE:"1124", RESULT_MESSAGE:"수신 가능한 영상 메타 정보 없음"});
            } else {
                var resultObj = {} ;
                resultObj.RESULT_CODE = "0000";
                resultObj.RESULT_MESSAGE = "정상처리";
                resultObj.STREAM_KEY = results[0].URL;
                resultObj.D_CAM_TYPE = results[0].D_CAM_TYPE;
                resultObj.D_RESOLUTION = results[0].D_RESOLUTION;
                logger.info('metaData', JSON.stringify(resultObj))
                res.send(resultObj);
                // res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리", STREAM_KEY:results[0].URL, 
                // D_CAM_TYPE:results[0].D_CAM_TYPE, D_RESOLUTION:results[0].D_RESOLUTION});
            }
        } 
    });   
}

DroneResult.prototype.getServiceHistory = function (dbConn, req, res) {
    var query = util.format("SELECT CUST_CTN D_CTN, CUST_NM D_NAME , DEV_MODEL D_MODEL, INSERT_DATE, UPDATE_DATE, CASE WHEN CAMERA_TYPE = '3' THEN '1' ELSE '2' END D_CAM_TYPE, " +
    "CASE WHEN WIDTH = '1920' THEN '3' WHEN WIDTH = '1280' THEN '2' ELSE '1' END D_RESOLUTION " +
    "FROM TB_TERMINAL_IMAGE_TRANS " +
    "WHERE DEV_TYPE = '4' AND SVC_TYPE > '1' AND STATUS > '2' AND CUST_CTN = '%s' AND INSERT_DATE >= '%s' AND INSERT_DATE < '%s' AND CODE_03 = '%s' "
    ,req.body.D_ID, req.body.START_DATE+'000000', req.body.END_DATE+'235959', req.body.LC_CUST_CODE);

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
        } else {
            res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리", D_ID:req.body.D_ID, RESULT_COUNT:results.length, DATA:results});
        } 
    });   
}

DroneResult.prototype.isFile = function (dbConn, file_name, customer_code, res, callback) {
    var query = util.format("" +
    "SELECT FULL_FILE_NAME, IDENTIFICATION " +
    "FROM TB_FILE_MNG_HISTORY " +
    "WHERE FILE_NAME = '%s' AND CUSTOMER_CODE = '%s'"
    ,file_name, customer_code);
    // "WHERE DEV_KEY = '%s' AND FILE_NAME = '%s' AND CUSTOMER_CODE = '%s'"
    // ,req.body.D_ID, req.body.FILE_NAME, req.body.LC_CUST_CODE);
    
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            logger.error({RESULT_CODE:"1000", RESULT_MESSAGE:error.code})
            res.status(500).send({RESULT_CODE:"1000", RESULT_MESSAGE:error.code});
            callback(false);
        } else {
            if (results.length > 0) {
                var file = results[0].FULL_FILE_NAME;
                if (!fs.existsSync(file)) {
                    logger.info('file not found', file);
                    logger.info({RESULT_CODE:"1150", RESULT_MESSAGE:"파일 미존재"})
                    res.status(500).send({RESULT_CODE:"1150", RESULT_MESSAGE:"파일 미존재"});
                    callback(false);
                } else {
                    logger.info('download request file', file);
                    callback(true, file, results[0].IDENTIFICATION);    
                }
            } else {
                logger.info({RESULT_CODE:"1150", RESULT_MESSAGE:"파일 미존재"})
                res.status(500).send({RESULT_CODE:"1150", RESULT_MESSAGE:"파일 미존재"});
                callback(false);
            }
        } 
    });   
}

DroneResult.prototype.resObjectNoti = function (dbConn, req, res) {
    res.send({RESULT_CODE:"0000", RESULT_MESSAGE:"정상처리"});

    var query = util.format("SELECT CODE_01, CODE_02, CODE_03 FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS < '3'"
    ,req.body.D_ID);
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            if (results.length > 0) {
                var noti = {};
                noti.RESULT_TYPE = 'OBJECT';
                noti.RESULT_MESSAGE = req.body.DESCRIPTION;
                noti.CODE_01 = results[0].CODE_01;
                noti.CODE_02 = results[0].CODE_02;
                noti.CODE_03 = results[0].CODE_03;
                logger.info('resObjectNoti', req.body, noti);
                app.io.sockets.emit('B501', noti);
            }
        } 
    });   
}

module.exports = DroneResult;