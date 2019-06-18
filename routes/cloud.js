var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var logger = require('../libs/logger');
var fs = require('fs');
var pcViewerAPI = require('../pcViewerAPI.js');
var LiveCam2UTM = require('../libs/LiveCam2UTM');
var Protocol = require('../libs/Protocol');
var app = require('../app.js').default;
var utilLib = require('../libs/utilLib');
var https = require('https');
var request = require('request');
var querystring = require('querystring');
var util = require('util');
var CloudLib = require('../libs/CloudLib');
var CloudHistory = require('../libs/CloudHistory');
var app = require('../app.js');

var cloudLib = new CloudLib();
var cloudHis = new CloudHistory();
const REFER_DATABASE = '1';
const REFER_CLOUD = '2';
var type = 1;

module.exports = router;

// 클라우드 상품 가입 요청
router.post('/product/join', function(req, res) {
    logger.info('Path change : /cloud/product/join', req.body, req.body.id);
    cloudLib.joinProduct(req.body.id, req.body.pid, function(bResult, result) {
        if (bResult) {
            res.send({result: true, data: "join product", error: null});
        } else {
            res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
        }
    })
});

// 클라우드 상품 가입 해지
router.post('/product/cancel', function(req, res) {
    logger.info('Path change : /cloud/product/cancel', req.body);
    cloudLib.cancelProduct(req.body.id, req.body.pid, function(bResult, result) {
        if (bResult) {
            res.send({result: true, data: "cancel product", error: null});
        } else {
            res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
        }
    })
});

// 다운로드 조회 요청 (1: 내부 DB 참조, 2: 클라우드 참조)
router.post('/files', function(req, res) {
    logger.info('Path change : /cloud/files');

    if (REFER_DATABASE == type) {
        var query = util.format("" +
        "SELECT @rownum := @rownum + 1 AS ROWNUM, a.* " +
        "FROM TB_FILE_MNG_HISTORY a, (SELECT @rownum := 0) r " +
        // "WHERE UCLOUD_STATUS = '3'  " +
        "WHERE IDENTIFICATION =  '%s' " +
        "AND CUSTOMER_CODE = '%s' " +
        "ORDER BY FILE_NAME ASC", req.body.id, req.session.code_03);
        logger.info('Query: ', query);
        app.dbConn.query(query, function(error, results) {
            if (error) {
                logger.error('DB Error: ', error);
                // res.send('');            
            } else {
                logger.info('DB Success: ');
                res.send(results);
            }
        });
    } else {        // REFER_CLOUD
        cloudLib.getFoldersList(req.session.userid, req.body.id, function(bResult, result) {
            logger.info(bResult, result);
            if (bResult) {
                res.send({result: true, data: result});
            } else {
                res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
            }
        });
    }
});


// 파일 다운로드 요청
router.get('/download', function(req, res) {
    logger.info('Path change : /cloud/download');

    var query = util.format("" +

    "SELECT FILE_ID, FILE_SIZE, FILE_TYPE, FILE_NAME, IDENTIFICATION " +
    "FROM TB_FILE_MNG_HISTORY " +
    "WHERE FILE_ID = '%s'", req.query.file_id);
    logger.info('Query: ', query);
    app.dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            
        } else {
            logger.info('DB Success: ');

            if (results.length == 0 || results[0].FILE_ID == '' || results[0].FILE_SIZE == 0) {
                res.status(500).send('download failed');
                return;
            }
            logger.info(results[0].FILE_ID, Number(results[0].FILE_SIZE)-2);
            cloudLib.download(req, res, results[0], function(bResult, data) {
                if (bResult) {
                    logger.info('download success');
                } else {
                    logger.error('download failed', results[0].FILE_NAME + ' : download failed (' + data.REASON + ')');
                    res.status(500).send(results[0].FILE_NAME + ' : download failed (' + data.REASON + ')');
                }
            });
        }
    });
});

// 업로드 재요청
router.post('/files/upload', function(req, res) {
    logger.info('Path change : /cloud/files/upload', req.body.identification, req.body.file_name);

    var query = util.format("" +
    "SELECT SYS_TYPE, REQ_TYPE, DEV_KEY, IDENTIFICATION, FULL_FILE_NAME, FOLDER_NAME " +
    ", FILE_NAME, FILE_SIZE, RECV_SIZE, FOLDER_ID " +
    "FROM TB_FILE_MNG_HISTORY " +
    "WHERE IDENTIFICATION = '%s' AND FILE_NAME = '%s'", req.body.identification, req.body.file_name);
    logger.info('Query: ', query);
    app.dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            
        } else {
            logger.info('DB Success: ');
            if (results.length == 0 || results[0].FOLDER_ID == '' || results[0].FILE_SIZE == 0) {
                res.status(500).send('이어올리기에 실패');
                return;
            }
            var body = {};
            body.SEND_TYPE = results[0].REQ_TYPE;
            body.MOBILE_NUM = results[0].DEV_KEY;
            body.IDENTIFICATION = results[0].IDENTIFICATION;
            body.FILENAME = results[0].FILE_NAME;
            body.USER_ID = req.session.userid;

            var fileInfo = {};
            fileInfo.uploadName = results[0].FILE_NAME;
            fileInfo.uploadSize = results[0].FILE_SIZE;
            fileInfo.uploadFile = results[0].FULL_FILE_NAME;
            fileInfo.folderName  = results[0].FOLDER_NAME;
            cloudLib.uploadRequest('retry', body, fileInfo, function(bResult, result) {
                if (bResult) {
                    res.send('이어올리기에 성공');
                } else {
                    res.status(500).send('이어올리기에 실패');
                }
            });
        }
    });
});

// 폴더 삭제
router.post('/folders/delete', function(req, res) {
    logger.info('Path change : /cloud/folders/delete', req.body.identification, req.body.folder_id, req.body.folder_name);
    // cloudLib.delete('folder', req.session.userid, req.body.folder_id, function(bResult, result) {
    cloudLib.delete('folder', req.session.userid, req, function(bResult, result) {
        if (bResult) {      // 폴더 삭제 성공 시 DB 상태값 동기화
            cloudHis.updateStatusFolderDelete(app.dbConn, req.body.identification, function(err, bResult) {
                if (err) {
                    res.status(500).send({result: false, data: null, error: {message: err.code}});
                } else {
                    res.send({result: true, data: "폴더 삭제 성공", error: null})
                }
            });
        } else {
            if (result.code == '3013') {  // [폴더가 존재하지 않습니다] 응답 시 DB 상태값 동기화
                cloudHis.updateStatusFolderDelete(app.dbConn, req.body.folder_name, function(err, bResult) {
                    if (err) {
                        res.status(500).send({result: false, data: null, error: {message: err.code}});
                    } else {
                        res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
                    }
                });
            } else {
                res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
            }            
        }
    });        
});

// 파일 삭제
router.post('/files/delete', function(req, res) {
    logger.info('Path change : /cloud/files/delete', req.body.file_id);
    // cloudLib.delete('file', req.session.userid, req.body.file_id, function(bResult, result) {
    cloudLib.delete('file', req.session.userid, req, function(bResult, result) {
        if (bResult) {      // 파일 삭제 성공 시 DB 상태값 동기화
            cloudHis.updateStatusFileDelete(app.dbConn, req.body.file_id, function(err, bResult) {
                if (err) {
                    res.status(500).send({result: false, data: null, error: {message: err.code}});
                } else {
                    res.send({result: true, data: "파일 삭제 성공", error: null})
                }
            });
        } else {
            if (result.code == '3012') {  // [파일이 존재하지 않습니다] 응답 시 DB 상태값 동기화
                cloudHis.updateStatusFileDelete(app.dbConn, req.body.file_id, function(err, bResult) {
                    if (err) {
                        res.status(500).send({result: false, data: null, error: {message: err.code}});
                    } else {
                        res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
                    }
                });
            } else {
                res.status(500).send({result: false, data: null, error: {code: result.code, message: result.message}});
            }
        }
    });
});

// 클라우드 사용량 조회
router.get('/usage', function(req, res) {
    logger.info('Path change : /cloud/usage', req.param('id'));
    cloudLib.getAvailableUsage(req.param('id'), function(bResult, result) {
        if (bResult) {      // 클라우드 사용량 조회 성공
            var total = Number(result.total);
            var available = Number(result.available);
            var usagePer = Math.floor((total - available) / total * 100);
            if (usagePer > 50) {
                res.send({result: true, usage: usagePer, available: available, total: total});
            } else {
                res.send({result: false, usage: usagePer, available: available, total: total});
            }
        } else {            // 클라우드 사용량 조회 실패
            res.send({result: false})
        }
    });
});
