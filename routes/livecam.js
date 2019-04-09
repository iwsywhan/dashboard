var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var logger = require('../libs/logger');
var fs = require('fs');
var ejs = require('ejs');
var pcViewerAPI = require('../pcViewerAPI.js');
var LiveCam2UTM = require('../libs/LiveCam2UTM');
var Protocol = require('../libs/Protocol');
var CloudLib = require('../libs/CloudLib');
var app = require('../app.js');
var utilLib = require('../public/javascripts/utilLib');
var util = require('util');
var decodeJWT = require('../libs/decodeJWT');
var client = require('../socketClient');

var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));

const DEF_ILIVECAM = '1';
const DEF_UTM = '2';

module.exports = router;

/* 드론 기능에 대한 api */
router.post('/v1/startRecording', function(req, res) {
    logger.info('Path change : /livecam/v1/startRecording');
    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var query = util.format("SELECT * FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND SVC_TYPE = '0' AND STATUS = '1'", req.body.MOBILE_NUM);
        app.dbConn.query(query, function (error, results) {
                    if (error) {
                    } else {
                        if (results.length > 0) {                    
                            var body = {};
                            body = req.body;
                            body.DEV_TYPE = '4';
                            body.SYS_TYPE = '1';
                            body.MIN_STOR_SIZE = '10';
                            body.USER_ID = token.id;
                            body.CONTROL_ID = req.body.CONTROL_ID + token.code_03;
            
                            var protocol = new Protocol('B207', body);
                            var packet = protocol.make();
                            client.write(packet);
                            app.droneResult.setResponse(res);
                        } else {
                            res.send({result:false, data: null, error: {code: '100', message:'연결된 드론이 존재하지 않습니다.'}});
                        }
                    }
                });
        }
    });
});

/* 드론 기능에 대한 api */
router.post('/v1/stopRecording', function(req, res) {
    logger.info('Path change : /livecam/v1/stopRecording');
    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var query = util.format("SELECT * FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN LIKE '%s%%' AND STATUS = '2'", req.body.MOBILE_NUM.split('__')[0]);
            logger.info('stopRecording', query);
            app.dbConn.query(query, function (error, results1) {
                if (error) {
                } else {
                    logger.info('results.length', results1[0])
                    if (results1.length) {
                        var body = {};
                        body.MOBILE_NUM = req.body.MOBILE_NUM;
                        body.CTN_DEVICE = results1[0].CTN_DEVICE;
                        body.DEV_TYPE = '4';
                        body.SYS_TYPE = '1';
                        body.USER_ID = token.id;
            
                        var protocol = new Protocol('B903', body);
                        var packet = protocol.make();
                        client.write(packet);
                        app.droneResult.setResponse(res);
                    } else {
                        res.send('이미 종료된 상태입니다.');
                    }
                }
            });
        } 
    });
});

router.post('/v1/startSnapshot', function(req, res) {
    logger.info('Path change : /livecam/v1/startSnapshot', req.body);
    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var query = util.format("SELECT CTN_DEVICE FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS < '3'", req.body.MOBILE_NUM);
            app.dbConn.query(query, function (error, results) {
                if (error) {
                    res.send({result: false, data: null, error: {code:500, message: 'System Error'}});
                } else {
                    var body = {};
                    body.MOBILE_NUM = req.body.MOBILE_NUM;
                    body.CTN_DEVICE = results[0].CTN_DEVICE;
                    body.DEV_TYPE = '4';
                    body.SYS_TYPE = '1';
                    body.SHOT_COUNT = req.body.SHOT_COUNT;
                    body.SHOT_PERIOD = req.body.SHOT_PERIOD;
                    body.RESET_FLAG = req.body.RESET_FLAG;
                    body.JUST_UPLOAD_FLAG = req.body.JUST_UPLOAD_FLAG;
                    body.USER_ID = token.id;
        
                    var protocol = new Protocol('B170', body);
                    var packet = protocol.make();
                    client.write(packet);
                    app.droneResult.setResponse(res);
                }
            });
        }
    });
});

router.post('/v1/upload', function(req, res) {
    logger.info('Path change : /livecam/v1/upload', req.body);

    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var query = util.format("SELECT CTN_DEVICE FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = '%s' AND STATUS < '3'", req.body.MOBILE_NUM);
            app.dbConn.query(query, function (error, results) {
                if (error) {
                    res.send({result: false, data: null, error: {code:500, message: 'System Error'}});
                } else {
                    var body = {};
                    body.MOBILE_NUM = req.body.MOBILE_NUM;
                    body.CTN_DEVICE = results[0].CTN_DEVICE;
                    body.DEV_TYPE = '4';
                    body.SYS_TYPE = '1';
                    body.UPLOAD_TYPE = req.body.UPLOAD_TYPE;
                    body.UPLOAD_DEL_FLAG = req.body.UPLOAD_DEL_FLAG;
                    body.UPLOAD_TODAY_FLAG = req.body.UPLOAD_TODAY_FLAG;
                    body.USER_ID = token.id;
        
                    var protocol = new Protocol('B171', body);// 중계서버랑 통신.
                    var packet = protocol.make();
                    client.write(packet);
                    app.droneResult.setResponse(res); 
                }
            });
        }
    });
});

router.post('/v1/file/encrypt', function(req, res) {
    logger.info('Path change : /livecam/v1/file/encrypt', req.body);

    var body = {};
    body.SYS_TYPE = req.body.SVC_TYPE;
    body.USER_ID = req.session.userid;
    body.OFILE_NAME = req.body.FILE_NAME;
    body.IDENTIFICATION = req.body.IDENTIFICATION;
    var protocol1 = new Protocol('B280', body);
    var packet1 = protocol1.make();
    client.write(packet1);
    app.droneResult.setResponse(res);
});

router.get('/v1/file/download', function(req, res) {
    logger.info('Path change : /livecam/v1/file/download', req.query.ofile_name, req.query.dfile_name);
    // var enc_file_name = req.query.file_name;
    // var dec_file_name = enc_file_name.split('_')[1];
    var dec_file_name = req.query.ofile_name;
    var enc_file_name = req.query.dfile_name;

    app.droneResult.isFile(app.dbConn, dec_file_name, req.session.code_03, res, function(result, file) {
        if (result) {
            // file = file
            var index = file.lastIndexOf('/');
            var path = file.substr(0, index+1);
            if (typeof req.query.dfile_name === "undefined") {
                logger.info("jpg", path + req.query.ofile_name)
                res.download(path + req.query.ofile_name);
            } else {
                res.setHeader('Content-disposition', 'attachment; filename='+dec_file_name);
                res.setHeader('Content-type', 'video/mp4');
                // var index = file.lastIndexOf('/');
                // var path = file.substr(0, index+1);
                logger.info("mp4", path + enc_file_name)
                res.download(path + enc_file_name, dec_file_name);
            }
        }
    });
});

router.get('/v1/bitrate', function(req, res) {
    var bitRate = JSON.parse(fs.readFileSync("./config/bitRate.json"));    
    logger.info('Path change : /livecam//v1/bitrate', req.query);
    var codec = req.query.codec;
    var resolution = req.query.resolution;
    var fps = req.query.fps;
    res.send({"bitrate": bitRate[codec][resolution][fps]});
})

