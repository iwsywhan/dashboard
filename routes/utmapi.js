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
var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));
var decodeJWT = require('../libs/decodeJWT');
var client = require('../socketClient')
var AccountResult = require('../libs/AccountResult')
var accountC = require('../controllers/accountController');

const DEF_ILIVECAM = '1';
const DEF_UTM = '2';

var cloudLib = new CloudLib();
var accountResult = new AccountResult();

module.exports = router;

router.post('/v1/checkAccount', function(req, res) {
    logger.info('Path change : /utmapi/v1/checkAccount');
    if (accountResult.checkParam(req, res)) {
        accountResult.checkCustomer(app.dbConn, req, res, function(result) {
            if (result) {
                accountResult.isEntry(app.dbConn, req, res);
            }
        });
    }
});

router.post('/v1/createAccount', function(req, res) {
    logger.info('Path change : /utmapi/v1/createAccount');

    // CODE_01, CODE02, UTM_ID 컬럼 필요
    if (accountResult.checkParam(req, res)) {
        accountResult.checkCustomer(app.dbConn, req, res, function(result1) {
            if (result1) {
                accountResult.isEntry(app.dbConn, req, res, function(result2) {
                    if (result2) {
                        accountResult.insertAccount(app.dbConn, req, res);
                    }
                });
            }
        });
    }   
});

/* Cloud AccessToken 발급 api */
router.post('/v1/assignCloudToken', function(req, res) {
    logger.info('Path change : /utmapi/v1/assignCloudToken');
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                cloudLib.getApiToken(req.body.ID, function(apiToken, result2) {
                    if (apiToken) {
                        res.send({RESULT_CODE: "0000", RESULT_MESSAGE: "정상 처리", ACCESS_TOKEN: apiToken, EXPIRE_TIMESTAMP: result2});
                    } else {
                        res.status(500).send({RESULT_CODE: result2.code, RESULT_MESSAGE: result2.message});
                    }
                });
            }
        });
    }
});

router.post('/v1/createDevice', function(req, res) {
    logger.info('Path change : /utmapi/v1/createDevice');
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isDuplicate(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.insertDrone(app.dbConn, req, res, serverConf.WebServerIP, serverConf.WebPort, '7861');
                        
                        // 드론 등록 시 클라우드 내의 폴더 생성 후 파일 저장
                        cloudLib.createDefaultFolder(req.body.D_ID, req.body.ID, function(bResult) {
                            if (bResult) {
                                logger.info('drone create default folder success');
                            } else {
                                logger.info('drone create default folder fail');
                            }
                        })
                    }
                })    
            }
        });
    }
});

router.post('/v1/modifyDevice', function(req, res) {
    logger.info('Path change : /utmapi/v1/modifyDevice');
  
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.modifyDrone(app.dbConn, req, res);
                    }
                })    
            }
        });
    }
});

router.post('/v1/deleteDevice', function(req, res) {
    logger.info('Path change : /utmapi/v1/deleteDevice');
  
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.deleteDrone(app.dbConn, req, res);
                    }
                })    
            }
        });
    }
});

router.post('/v1/startRecording', function(req, res) {
    logger.info('Path change : /utmapi/v1/startRecording', req.body);
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.isReady(app.dbConn, req, res, function (result3) {
                            if (result3) {
                                // 내부 규격과 UTM 규격이 달라 값 보정
                                req.body.D_VCODEC = req.body.D_VCODEC == 1 ? 0 : 1;
                                if (req.body.D_RESOLUTION == '1') {
                                    req.body.D_RESOLUTION = '3';
                                } else if (req.body.D_RESOLUTION == '3') {
                                    req.body.D_RESOLUTION = '1';
                                }

                                if (req.body.D_FPS == '1') {
                                    req.body.D_FPS = '30';
                                } else {
                                    req.body.D_FPS = '60';
                                }
                                // ------------------------------------------------

                                var condition;
                                condition = req.body.D_VCODEC == 0 ? 'H264_': 'H265_';
                                condition += req.body.D_FPS + '_';
                                if (req.body.D_RESOLUTION == '1')
                                    condition += 'FHD_';
                                else if (req.body.D_RESOLUTION == '2')
                                    condition += 'HD_';
                                else
                                    condition += 'SD_';
                                condition += 'BITRATE';                                

                                var query1 = util.format("" + 
                                "SELECT C_VALUE BIT_RATE " +
                                "FROM TB_COMMON " +
                                "WHERE C_NAME = '%s'", condition);
                                logger.info('Query :', query1);
                                app.dbConn.query(query1, function (error, result1) {
                                    if (error) {
                                        logger.error(error);
                                        return;
                                    } else {
                                        if (result1.length > 0) {
                                            var body = {};
                                            body.MOBILE_NUM = req.body.D_ID;
                                            body.CTN_DEVICE = req.body.D_CTN; 
                                            body.DEV_TYPE = '4';
                                            body.SYS_TYPE = DEF_UTM;
                                            body.CONTROL_ID = '900999' + req.body.LC_CUST_CODE;
                                            body.USER_ID = req.body.ID;
                                            body.MIN_STOR_SIZE = '10';
                                            body.CAM_LIST_CNT = '1'
                                            body.CAM_LIST = '1|1|1|' + req.body.D_RESOLUTION + '|' + result1[0].BIT_RATE + '|' + req.body.D_FPS + '|' + req.body.D_VCODEC;
                                            body.CHAN_CNT = '1';
                                            body.CHAN_LIST = '0|1';
                                            var protocol = new Protocol('B207', body);
                                            var packet = protocol.make();
                                            client.write(packet);
                                            app.droneResult.setResponse(res, req.body.D_FLIGHT_ID);
                                        }
                                    }
                                });                
                            }
                        });
                    }
                })    
            }
        });
    }
});

router.post('/v1/stopRecording', function(req, res) {
    logger.info('Path change : /utmapi/v1/stopRecording', req.body);

    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.isRunning(app.dbConn, req, res, function (result3) {
                            if (result3) {
                                var body = {};
                                body.MOBILE_NUM = req.body.D_ID;
                                body.CTN_DEVICE = req.body.D_CTN;
                                body.DEV_TYPE = '4';
                                body.SYS_TYPE = DEF_UTM;
                                body.USER_ID = req.body.ID;
                    
                                var protocol = new Protocol('B903', body);
                                var packet = protocol.make();
                                client.write(packet);
                                app.droneResult.setResponse(res);                    
                            }
                        });
                    }
                })    
            }
        });
    }
});

router.post('/v1/startSnapshot', function(req, res) {
    logger.info('Path change : /utmapi/v1/startSnapshot', req.body);

    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.isEnableSnapShot(app.dbConn, req, res, function (result3) {
                            if (result3) {
                                var body = {};
                                body.MOBILE_NUM = req.body.D_ID;
                                body.CTN_DEVICE = req.body.D_CTN;
                                body.DEV_TYPE = '4';
                                body.SYS_TYPE = DEF_UTM;
                                body.SHOT_COUNT = req.body.SHOT_COUNT;
                                body.SHOT_PERIOD = req.body.SHOT_PERIOD;
                                body.RESET_FLAG = req.body.RESET_FLAG;
                                body.JUST_UPLOAD_FLAG = req.body.RT_UPLOAD_FLAG;
                                body.USER_ID = req.body.ID;

                                var protocol = new Protocol('B170', body);
                                var packet = protocol.make();
                                client.write(packet);
                                app.droneResult.setResponse(res);
                            }
                        });
                    }
                })    
            }
        });
    }
});


router.post('/v1/upload', function(req, res) {
    logger.info('Path change : /utmapi/v1/upload', req.body);

    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.isReady(app.dbConn, req, res, function (result3) {
                            if (result3) {
                                var body = {};
                                body.MOBILE_NUM = req.body.D_ID;
                                body.CTN_DEVICE = req.body.D_CTN;
                                body.DEV_TYPE = '4';
                                body.SYS_TYPE = DEF_UTM;
                                body.UPLOAD_TYPE = req.body.UPLOAD_TYPE;
                                body.UPLOAD_DEL_FLAG = req.body.UPLOAD_DEL_FLAG;
                                body.UPLOAD_TODAY_FLAG = req.body.UPLOAD_TODAY_FLAG;
                                body.USER_ID = req.body.ID;
                    
                                var protocol = new Protocol('B171', body);
                                var packet = protocol.make();
                                client.write(packet);
                                app.droneResult.setResponse(res); 
                            }
                        });
                    }
                })    
            }
        });
    }
});

router.post('/v1/metaData', function(req, res) {
    logger.info('Path change : /utmapi/v1/metaData', req.body);

    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.isRunning(app.dbConn, req, res, function (result3) {
                            if (result3) {
                                app.droneResult.getMetaData(app.dbConn, req, res);
                            }
                        });
                    }
                })    
            }
        });
    } 
});

router.post('/v1/searchHistory', function(req, res) {
    logger.info('Path change : /utmapi/v1/searchHistory', req.body);
    
    if (app.droneResult.checkParam(req, res)) {
        app.droneResult.checkCustomer(app.dbConn, req, res, function (result1) {
            if (result1) {
                app.droneResult.isEntry(app.dbConn, req, res, function (result2) {
                    if (result2) {
                        app.droneResult.getServiceHistory(app.dbConn, req, res);
                    }
                })    
            }
        });
    }  
});