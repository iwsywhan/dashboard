var net = require('net');
var logger = require('../libs/logger');
var merge = require('merge');
var struct = require('../coupledMessage.js');
var aes256cbc = require('../aes256cbc.js');
var dbConn = require('../db');
// var gcm = require('node-gcm');
var fcm = require('fcm-node');
var util = require('util');
var fs = require('fs');
var app = require('../app');
var i18next =  require('i18next');
var jPush = require('../libs/jPushServiceAPI.js')

var socket = new net.Socket();
var appServerIP = '127.0.0.1';
var appServerPort = 12345;
var client;

var serverConf = JSON.parse(fs.readFileSync('./config/server.json'));
var retryInterval = 3000;
var retriedTimes = 0;
var maxRetries = 10;

var MOBILE = 1;
var STB = 2;
var PC = 3;

var regQueue = [];

if (false) {
(function connect() {

    function reconnect() {
        if (retriedTimes >= maxRetries) {
            throw new Error('retriedTimes > maxRetries');
        }

        retriedTimes += 1;
        setTimeout(connect, retryInterval);
    }
    var svip = {
        port: appServerPort,
        host: appServerIP,
        localAddress: appServerIP,
        localPort: 30000
    };
    //client = socket.connect(appServerPort, appServerIP, function() {
    client = socket.connect(svip, function() {
        logger.info('App Server tcp connected success');
    });

    client.on('connect', function() {

        retriedTimes = 0;
        logger.info('connect event emit');
    });

    var recvData = '';
    client.on('data', function(data) {
        logger.info('Noti message ocurred!');

        parsingMessage(data);
    });

    client.on('close', function() {
        // logger.crit('Connection closed');
        reconnect();
    });

    client.on('error', function(err) {
        // logger.crit('connect error', err);
    });

    //process.stdin.pipe(client, {end: false});
}());
}

function parsingMessage(data) {
    struct.parsingBodyData(data, function(error, header, body, unProcessedBuf) {

        if (error) {
            logger.crit(error);
        } else {
                switch (header.command) {// 중계서버에서 이벤트를 받음
                    case 'B410':
                        body.LOCATION_X = aes256cbc.decrypt(body.LOCATION_X);
                        body.LOCATION_Y = aes256cbc.decrypt(body.LOCATION_Y);
                        app._io.sockets.emit(header.command, body);
                        break
                    case 'B400':
                        // app._io.sockets.emit(header.command, body);
                        // break;
                    case 'B500': // STB Status Message (noti)
                    case 'B501': // Mobile Viewer Status Message (noti)
                        // break;
                    case 'B600':
                        app._io.sockets.emit(header.command, body);
                        break;
                    case 'B601': // 단말 수신측 종료에 의한 Mobile 서비스 종료
                    case 'B900': // PC Viewer 비정상 종료
                    case 'B801': // PC Viewer 단말 송신측 종료 (noti)
                    case 'B902': // PC Viewer
                    case 'B231': // 공지사항 작성 배포
                        app._io.sockets.emit(header.command, body);
                        break;
                    case 'B101': // Quick connect
                    case 'B104': // Multi control
                        if (header.resultCode != '0000') {
                            app._io.sockets.emit('B998', body);
                        } else {
                            var query;
                            var code_01 = body.CONTROL_ID.substring(0, 3);
                            var code_02 = body.CONTROL_ID.substring(3, 6);
                            var code_03 = body.CONTROL_ID.substring(6, 9);

                            function fetchID(callback) {
                                var query1 = 'SELECT DEFAULT_DEVICE FROM TB_CONTROL ';
                                query1 += 'WHERE CODE_01 = \'' + code_01 + '\' AND CODE_02 = \'' + code_02 + '\' AND CODE_03 = \'' + code_03 + '\'';
                                dbConn.query(query1, function(err, rows) {
                                    logger.info('Query: ', query1);
                                    if (err) {
                                        logger.error('DB Error: ', err);
                                        callback(err, null);
                                    } else {
                                        if (Object.keys(rows).length > 0) {
                                            callback(null, rows[0].DEFAULT_DEVICE);
                                        } else {
                                            callback(err, null);
                                        }
                                    }
                                });
                            }

                            var device, isService;
                            fetchID(function(err, content) {
                                device = content;

                                if (device == STB) {

                                    query = 'SELECT a.STB_MAC_ADDR,a.STB_NM ,a.STB_DEPT_NM,a.SVC_STB_IP,a.STB_DEPT_CODE_01,a.STB_DEPT_CODE_02,a.STB_DEPT_CODE_03,a.STB_LOCATION,a.STB_ADMIN_INFO,a.CTN_SEQ,b.STATUS';
                                    query += ' FROM TB_STB_INFO a left join ( SELECT STATUS ,STB_MAC_ADDR FROM TB_STB_SERVICE WHERE STATUS < \'3\' ) b';
                                    query += ' ON a.STB_MAC_ADDR = b.STB_MAC_ADDR';
                                    query += ' WHERE STB_DEPT_CODE_01 =\'' + code_01 + '\' and STB_DEPT_CODE_02 = \'' + code_02 + '\' and STB_DEPT_CODE_03 =\'' + code_03 + '\' and b.STATUS is null';
                                    query += ' GROUP BY a.STB_MAC_ADDR ORDER BY a.STB_DEPT_NM, a.STB_NM Limit 1';

                                    dbConn.query(query, function(error, results) {
                                        logger.info('Query:', query);

                                        if (error) {
                                            logger.error('DB Error:', error);
                                        } else {
                                            //logger.info('DB success');

                                            var jsonData;
                                            if (Object.keys(results).length > 0) {
                                                logger.info('body:', body);
                                                var stbInfo = merge(results[0], body);
                                                jsonData = struct.makeJsonTypeAddSTB(stbInfo);
                                                isService = 'Y';
                                            } else {
                                                isService = 'N';
                                                jsonData = struct.makeJsonTypeFullUse(body);
                                            }


                                            packet = struct.makeData(header.command, body, isService);
                                            client.write(packet);


                                            // if (header.command == 'B101' || header.command == 'B103' || header.command == 'B104')
                                                packet = struct.makeData('B300', jsonData);
                                            // else
                                            //     packet = struct.makeData('D300', jsonData);
                                            client.write(packet);
                                        }
                                    });

                                } else if (device == MOBILE || device == PC) {

                                    query = 'SELECT DEV_KEY, DEV_NM, DEV_DEPT_NM';
                                    query += ' FROM TB_DEFAULT_CONNECT_INFO';
                                    query += ' WHERE CODE_01 =\'' + code_01 + '\' and CODE_02 = \'' + code_02 + '\' and CODE_03 =\'' + code_03 + '\' and DEV_TYPE = \'' + device + '\'';
                                    query += ' ORDER BY DEV_DEPT_NM, DEV_NM';

                                    dbConn.query(query, function(error, results) {
                                        logger.info('Query:', query);

                                        if (error) {
                                            logger.error('DB Error:', error);
                                        } else {
                                            //logger.info('DB success');

                                            var jsonData;
                                            if (Object.keys(results).length > 0) {
                                                logger.info('body:', body);

                                                isService = 'Y';
                                                packet = struct.makeData(header.command, body, isService);
                                                client.write(packet);

                                                var mobileArray = new Array();
                                                for (var i = 0; i < results.length; i++) {
 
                                                    if (device == MOBILE) {
                                                        var mobileInfo = new Object();

                                                        mobileInfo.name = results[i].DEV_NM;
                                                        mobileInfo.dept = 'iwsys'; //results[i].DEV_DEPT_NM;
                                                        mobileInfo.ctn = results[i].DEV_KEY;
                                                        mobileInfo.index = '0';
                                                        mobileArray.push(mobileInfo);

                                                        logger.info('mobileArrary push :', mobileInfo);

                                                        // 결과값을 다 받으면 한번에 전송
                                                        if (mobileArray.length == results.length) {
                                                            var mobileInfoList = {};
                                                            mobileInfoList.COMMAND = 'B302';
                                                            mobileInfoList.CTN_DEVICE = body.CTN_DEVICE;
                                                            mobileInfoList.MOBILE_NUM = body.MOBILE_NUM;
                                                            mobileInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                                            mobileInfoList.VIEW_TYPE = device;
                                                            mobileInfoList.mobileList = mobileArray;
                                                            packet = struct.makeData(mobileInfoList.COMMAND, mobileInfoList);
                                                            client.write(packet);
                                                        }
                                                    } else {
                                                        app.pcViewerAPI.GetViewerIndex2(dbConn, results[i], device, function(obj, viewInfo) {
                                                            logger.info('getViewerIndex callback :', obj[0].VIEW_INDEX);

                                                            viewInfo.index = obj[0].VIEW_INDEX;
                                                            var mobileInfo = new Object();
                                                            mobileInfo.name = viewInfo.DEV_NM;
                                                            mobileInfo.dept = viewInfo.DEV_DEPT_NM;
                                                            mobileInfo.ctn = viewInfo.DEV_KEY;
                                                            mobileInfo.index = viewInfo.index;
                                                            mobileArray.push(mobileInfo);
                                                            logger.info('mobileArrary push :', mobileInfo);

                                                            // 결과값을 다 받으면 한번에 전송
                                                            if (mobileArray.length == results.length) {
                                                                var mobileInfoList = {};
                                                                mobileInfoList.COMMAND = 'B302';
                                                                mobileInfoList.CTN_DEVICE = body.CTN_DEVICE;
                                                                mobileInfoList.MOBILE_NUM = body.MOBILE_NUM;
                                                                mobileInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                                                mobileInfoList.VIEW_TYPE = device;
                                                                mobileInfoList.mobileList = mobileArray;
                                                                packet = struct.makeData(mobileInfoList.COMMAND, mobileInfoList);
                                                                client.write(packet);
                                                            }
                                                        });
                                                    }
                                                }
                                            } else {
                                                isService = 'N';
                                                packet = struct.makeData(header.command, body, isService);
                                                client.write(packet);

                                                jsonData = struct.makeJsonTypeFullUse(body);
                                                packet = struct.makeData('B302', jsonData);
                                                client.write(packet);
                                            }
                                        }
                                    });
                                }
                            });
                            app._io.sockets.emit(header.command, body);
                        }
                        break;
                    case 'B105' :
                        var voiceArray = [];

                        var fav_key = body.FAV_KEY;
                        lcsServiceAPI.getBookMarkList(dbConn, fav_key, function (nestResult) {
                            if (Object.keys(nestResult).length > 0) {

                                for (var i = 0; i < nestResult.length; i++) {
                                    if (nestResult[i].DEV_TYPE == MOBILE) {

                                        var viewArray = [];
                                        var viewInfo = {};
                                        viewInfo.name = nestResult[i].DEV_NM;
                                        viewInfo.dept = nestResult[i].DEV_DEPT_NM;
                                        viewInfo.ctn  = nestResult[i].DEV_KEY;
                                        viewInfo.index = '0';
                                        viewArray.push(viewInfo);

                                        var viewInfoList = {};
                                        viewInfoList.COMMAND = 'B302';
                                        viewInfoList.CTN_DEVICE  = body.CTN_DEVICE;
                                        viewInfoList.MOBILE_NUM  = body.MOBILE_NUM;
                                        viewInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                        viewInfoList.VIEW_TYPE   = MOBILE;
                                        viewInfoList.mobileList  = viewArray;

                                        packet = struct.makeData('B302', viewInfoList);
                                        client.write(packet);
                                    } else if (nestResult[i].DEV_TYPE == STB) {

                                        var stbArray = [];
                                        var stbInfo = {};
                                        stbInfo.name = nestResult[i].DEV_NM;
                                        stbInfo.dept = nestResult[i].DEV_DEPT_NM;
                                        stbInfo.mac  = nestResult[i].DEV_KEY;
                                        stbArray.push(stbInfo);

                                        var stbInfoList = {};
                                        stbInfoList.COMMAND = 'B300';
                                        stbInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                        stbInfoList.CTN_DEVICE = body.CTN_DEVICE;
                                        stbInfoList.MOBILE_NUM = body.MOBILE_NUM;
                                        stbInfoList.stbList = stbArray;

                                        packet = struct.makeData('B300', stbInfoList);
                                        client.write(packet);
                                    } else if (nestResult[i].DEV_TYPE == PC){

                                        app.pcViewerAPI.GetViewerIndex2(dbConn, nestResult[i], PC, function (obj, viewInfo) {
                                            logger.info('getViewerIndex callback :', obj[0].VIEW_INDEX);

                                            var pcArray = [];
                                            var pcInfo = {};
                                            pcInfo.name = viewInfo.DEV_NM;
                                            pcInfo.dept = viewInfo.DEV_DEPT_NM;
                                            pcInfo.ctn  = viewInfo.DEV_KEY;
                                            pcInfo.index = obj[0].VIEW_INDEX;
                                            pcArray.push(pcInfo);
                                            logger.info('pcArray push :', pcInfo);

                                            var viewInfoList = {};
                                            viewInfoList.COMMAND = 'B302';
                                            viewInfoList.CTN_DEVICE  = body.CTN_DEVICE;
                                            viewInfoList.MOBILE_NUM  = body.MOBILE_NUM;
                                            viewInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                            viewInfoList.VIEW_TYPE   = PC;
                                            viewInfoList.mobileList  = pcArray;
                                            packet = struct.makeData('B302', viewInfoList);
                                            client.write(packet);
                                        });
                                    } else { // VOICE
                                        //if (body.TEL_YN == 'Y') {
                                            var voiceInfo = {};
                                            voiceInfo.name = nestResult[i].DEV_NM;
                                            voiceInfo.dept = nestResult[i].DEV_DEPT_NM;
                                            voiceInfo.ctn  = nestResult[i].DEV_KEY;
                                            voiceInfo.arank = '-';
                                            voiceArray.push(voiceInfo);
                                            logger.info('voiceArray push :', voiceInfo);
                                        //}
                                    }
                                }
                            }
                        });

                        if (body.TEL_YN == 'Y') {

                            var code_01 = body.CONTROL_ID.substring(0,3);
                            var code_02 = body.CONTROL_ID.substring(3,6);
                            var code_03 = body.CONTROL_ID.substring(6,9);

                            lcsServiceAPI.getPhoneNumberOfControl(dbConn, code_01, code_02, code_03, function (obj) {
                                logger.info('getPhoneNumberOfControl:', obj[0].CTL_TEL_NUM);

                                var voiceInfo2 = {};
                                voiceInfo2.name = obj[0].CTL_NM;
                                voiceInfo2.dept = obj[0].CTL_ADMIN_NM;
                                voiceInfo2.ctn  = obj[0].CTL_TEL_NUM;
                                voiceInfo2.arank = '-';
                                voiceArray.push(voiceInfo2);

                                var voiceInfoList = {};
                                voiceInfoList.COMMAND = 'B200';
                                voiceInfoList.CTN_DEVICE  = body.CTN_DEVICE;
                                voiceInfoList.MOBILE_NUM  = body.MOBILE_NUM;
                                voiceInfoList.INSERT_DATE = body.P_INSERT_DATE;
                                voiceInfoList.voiceList  = voiceArray;

                                packet = struct.makeData('B200', voiceInfoList);
                                logger.info('B105 packet send');
                                client.write(packet);
                            });
                        }
                        break;
                    case 'B202': // 영상 서비스 중 mVoIP통화 연결을 하면 푸시

                        var code_01 = body.CONTROL_ID.substring(0, 3);
                        var code_02 = body.CONTROL_ID.substring(3, 6);
                        var code_03 = body.CONTROL_ID.substring(6, 9);

                        // 관제센터 디폴트가 mobile이 아니고 mVoIP 연결계정이 있을 경우 푸시 메세지 전송
                        logger.info('getCallId callback');

                        function getCallId(callback) {
                            var query3 = 'SELECT *, b.SV_OP_SV_V,c.DEV_KEY FROM TB_CONTROL a left join TB_CUSTOMER b ON a.CODE_03 = b.CUSTOMER_CODE';
                            query3 += ' left join (SELECT * FROM TB_DEFAULT_CONNECT_INFO WHERE DEV_TYPE = \'1\') c ';
                            query3 += ' ON a.CODE_01 = c.CODE_01 and a.CODE_02 = c.CODE_02 and a.CODE_03 = c.CODE_03 AND a.DEFAULT_DEVICE = c.DEV_TYPE'
                            query3 += ' WHERE a.CODE_01 = \'' + code_01 + '\' AND a.CODE_02 = \'' + code_02 + '\' AND a.CODE_03 = \'' + code_03 + '\'';
                            dbConn.query(query3, function(err, rows) {
                                logger.info('Query: ', query3);
                                if (err) {
                                    logger.error('DB Error: ', err);
                                    callback(err, null);
                                } else {
                                    if (Object.keys(rows).length > 0) {
                                        callback(null, rows[0]);
                                    } else {
                                        callback(err, null);
                                    }
                                }
                            });
                        }

                        getCallId(function(err, content) {
                            if (content == null) {
                                logger.info('control is null');
                                return;
                            }
                            logger.info('CALL_ID : ', content.CALL_ID);
                            //if (content.SV_OP_SV_V == 'Y' && body.CALL_TYPE == 'M' && body.F_CALL_TYPE == '1') {
                            if (content.SV_OP_SV_V == 'Y' && body.CALL_TYPE == 'M') {
                                //if(content.DEFAULT_DEVICE != MOBILE || content != '-') {
                                if (body.F_CALL_TYPE == '1') { // mobile 일 경우  gcm push
                                    logger.info('DEV_KEY : ' + content.DEV_KEY + '	F_MOBILE_NUM : ' + body.F_MOBILE_NUM);
                                    // 디폴트가 모바일이고 관제탑 전화번호와 디폴트 모바일 전화번호가 다를 경우 관제탑 전화로  mVoIP로 연결하기 위해 푸시
                                    if (body.F_MOBILE_NUM != content.DEV_KEY) {
                                        var voiceInfo = {};
                                        voiceInfo.name = content.CTL_NM;
                                        voiceInfo.device_id = content.
                                        //voiceInfo.ctn = content.CTL_TEL_NUM;
                                        voiceInfo.ctn = body.F_MOBILE_NUM;
                                        voiceInfo.view_ctn_device = body.VIEW_CTN_DEVICE;
                                        voiceInfo.dept = content.CTL_ADMIN_NM;
                                        voiceInfo.arank = '';

                                        var voiceArray = [];
                                        voiceArray.push(voiceInfo);

                                        var push_data = {};
                                        push_data.INSERT_DATE = body.P_INSERT_DATE;
                                        push_data.CTN_DEVICE = body.CTN_DEVICE;
                                        push_data.MOBILE_NUM = body.MOBILE_NUM;
                                        push_data.CALL_TYPE = '1';
                                        push_data.mobileList = voiceArray;

                                        push_gcm(push_data);
                                    }
                                } else { // 3 : pc 일 경우
                                    app._io.sockets.emit(header.command, body);
                                }
                            }
                        })
                        break;
                    case 'B200': // Voice 추가 응답
                    case 'B300': // STB 추가 응답
                    case 'B302': // Viewer 추가 응답
                    case 'B303': // Viewer 삭제 응답

                        // error 응답 처리
                        if (header.resultCode != '0000') {
                            app._io.sockets.emit('B999', body);
                        } else {

                            // Mobile이고 추가 했을 경우는 PUSH 메세지 전송
                            if (header.command == 'B302' && body.VIEW_TYPE == MOBILE) {

                                //add mobile 응답 확인 후에 PUSH MESSAGE 전송을 해야 함
                                var mobileArray = new Array();

                                var mobileInfo = new Object();
                                mobileInfo.ctn = body.VIEW_NUM;
                                mobileInfo.view_ctn_device = body.VIEW_CTN_DEVICE;
                                mobileArray.push(mobileInfo);

                                var mobileInfoList = new Object();
                                mobileInfoList.INSERT_DATE  = body.LAST_DATE;
                                mobileInfoList.MOBILE_NUM   = body.MOBILE_NUM;
                                mobileInfoList.DEV_NM       = body.DEV_NM;
                                mobileInfoList.DEV_DEPT_NM  = body.DEV_DEPT_NM;
                                mobileInfoList.LOCALE 		= body.LOCALE;
                                mobileInfoList.mobileList   = mobileArray;

                                var default_flag = body.DEFAULT_FLAG;
                                if (default_flag == '1') { // 기본연결이고 관제탑 전화번호와 수신 단말의 전화번호가 같을 경우 5초 딜레이
                                    setTimeout(function() {
                                        if (body.LOCALE.toUpperCase() == 'ZH') { 
                                            push_jpush(mobileInfoList);                                            
                                        } else {
                                            push_gcm(mobileInfoList); 
                                        }
                                    }, 5000);
                                } else {
                                    if (body.LOCALE.toUpperCase() == 'ZH') {
                                        push_jpush(mobileInfoList);
                                    } else {
                                        push_gcm(mobileInfoList);
                                    }
                                }
                            }else if(header.command == 'B302' && body.VIEW_TYPE == PC) {
                                // var query = 'INSERT INTO TB_LOCATION_ADMIN_MAPPING ' +
                                //     '(P_CUST_CTN, P_INSERT_DATE, STATUS, ADMIN_ID, INSERT_DATE ) VALUES (\'' + body.MOBILE_NUM + '\', \'' + body.LAST_DATE + '\',7,\'' + body.VIEW_NUM + '\',DATE_FORMAT(now(),"%Y%m%d%H%i%s") ) ';
                                var now = new Date().formatDate("yyyyMMddhhmmss");
                                var query = util.format("INSERT INTO TB_LOCATION_ADMIN_MAPPING (P_CUST_CTN, P_INSERT_DATE, STATUS, ADMIN_ID, INSERT_DATE) " +
                                "VALUES('%s', '%s', '%s', '%s', '%s') ON DUPLICATE KEY UPDATE INSERT_DATE = '%s'"
                                ,body.MOBILE_NUM, body.LAST_DATE, '7', body.VIEW_NUM, now, now);    
                                dbConn.query(query, function(error, result) {
                                    logger.info('Query:', query);
                                    if (error) {
                                        logger.error('DB Error', error);
                                    } else {
                                        //logger.info('DB success');
                                    }
                                });
                            }

                            app._io.sockets.emit(header.command, body);
                        }
                        break;
                    case 'B304': // 영상 서비스 수신 시작
                    case 'B305': // 영상 서비스 수신 종료
                        // error 응답 처리
                        if (header.resultCode == '0009') {
                            app._io.sockets.emit('B998', body);
                        } else if (header.resultCode == '0099') {
                            app._io.sockets.emit('B997', body);
                        } else {
                            app._io.sockets.emit(header.command, body);
                        }
                        break;
                    case 'B001': // reg id 등록 /수정

                        app.pushServiceAPI.checkValidRegID(dbConn, body, function(error, results) {

                            var date = new Date().formatDate("yyyyMMddhhmmss");
                            if (Object.keys(results).length == 0) { // regId 최초등록

                                var query = util.format('INSERT INTO TB_PUSH_REG_INFO (DEV_KEY, DEV_TYPE, REG_ID, REG_STATUS, INSERT_DATE, UPDATE_DATE) VALUES' +
                                    '( \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\')', body.MOBILE_NUM, '1', body.REG_ID, '1', date, date);
                            } else { // update

                                var query = util.format('UPDATE TB_PUSH_REG_INFO SET REG_ID = \'%s\', UPDATE_DATE = \'%s\' WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'%s\'', body.REG_ID, date, body.MOBILE_NUM, '1');

                            }

                            var responseValue;
                            dbConn.query(query, function(error, result) {

                                logger.info('Query:', query);

                                if (error) {
                                    responseValue = '1';
                                    logger.error('DB Error:', error);
                                } else {
                                    //logger.info('DB success');
                                    responseValue = '0';
                                }

                                var resBody = 'REG_RST=' + responseValue + '&MOBILE_NUM=' + body.MOBILE_NUM;
                                var packet = struct.makeData(header.command, resBody);
                                client.write(packet);
                            });
                        });
                        break;
                    case 'B003':

                        //console.log(body.PUSH_MSG);
                        app.pushServiceAPI.insertPushResponseHistory(dbConn, body, function() {

                            logger.info('insertPushResponseHistory end');

                            var packet = struct.makeData(header.command, '');
                            client.write(packet);

                            app._io.sockets.emit(header.command, body);
                        });
                        break;
                    case 'B216' :
                        if (header.reqType == 1) app._io.sockets.emit(header.command, body);
                            break;
                    // drone message
                    case 'B207' :
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('startRecording', resData);
                        break;
                    case 'B903' :
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('stopRecording', resData);
                        // var folderName = new Date().formatDate("yyyyMMddhhmmss");
                        // cloudLib.createFolder(body.USER_ID, body.MOBILE_NUM, '3', folderName, body.IDENTIFICATION, fileName, function(err, bResult, result) {
                        //     logger.info(err, bResult, result);
                        // });
                        break;
                    case 'B170' :
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('startSnapshot', resData);
                        if (body.JUST_UPLOAD_FLAG == '1') { // 실시간 업로드 요청일 경우에만 폴더 생성
                            // var folderName = new Date().formatDate("yyyyMMddhhmmss");
                            var folderName = body.IDENTIFICATION.substr(0, 14);
                            app.cloudLib.createFolder(body.USER_ID, body.MOBILE_NUM, '2', folderName, body.IDENTIFICATION, function(err, bResult, result) {
                                logger.info(err, bResult, result);
                            });
                        }
                        break;
                    case 'B171' :
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('upload', resData);
                        // var folderName = new Date().formatDate("yyyyMMddhhmmss");
                        var folderName = body.IDENTIFICATION.substr(0, 14);
                        app.cloudLib.createFolder(body.USER_ID, body.MOBILE_NUM, '1', folderName, body.IDENTIFICATION, function(err, bResult, result) {
                            logger.info(err, bResult, result);
                        });
                        break;
                    case 'B172':    // 파일 전체 업로드 완료
                        app._io.sockets.emit(header.command, body);
                        break;
                    case 'B173' :   // 파일 [드론 클라이언트] -> [중계서버] 업로드 완료
                        // [중계서버] -> [유클라우드] 업로도 수행
                        if (body.USER_ID != "undefined") {      // 웹서버 재부팅으로 세션이 없을 때는 처리 안하도록
                            var fileInfo = {};
                            fileInfo.uploadName = body.FILENAME;
                            fileInfo.uploadSize = body.FILESIZE;
                            fileInfo.uploadFile = body.PATH + '/' + body.FILENAME;
                            // cloudLib.uploadRequest(body, fileInfo);
                            this.setTimeout(function() {
                                app.cloudLib.uploadRequest('new', body, fileInfo);
                            }, 2000);
                            // cloudLib.uploadRequest('new', body, fileInfo);
                            app._io.sockets.emit(header.command, body);
                        } else {
                            app._io.sockets.emit('serverdown');
                        }
                        break;
                    case 'B904':
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('stopRecording', resData);
                        break;
                    case 'B280':
                        var resData = {};
                        resData.header = header;
                        resData.body = body;
                        app.droneResult.emit('encrypt', resData);
                        // io.socket.emit(header.command, body);
                        break;
                    default:
                        var protocolMsg = merge(header, body);
                        app._io.sockets.emit(header.command, protocolMsg);
                        break;
                }

            logger.info('Noti message emit:', header.command);

            if (unProcessedBuf.length > 0) {
                logger.info('recursive coupled massage data  <== ', unProcessedBuf.toString());
                parsingMessage(unProcessedBuf);
            }
        }
    });
}

function push_gcm(data) {
    // push gcm start
    if (data != null) {
        //logger.info('[push_gcm] : ', JSON.stringify(data));
        regQueue.push(data);
        logger.info('regQueue : ', regQueue);
        logger.info('regQueue pushed');
    }

    // 우선순위 재조립
    logger.info('sort');
    // Sort();

    // GCM Server와 동기 작업을 위해 요청 상태인지 체크
    logger.info('regQueue length check : ', regQueue.length);
    if (data != null && regQueue.length > 1) {
        return;
    }

    // get reg_id
    logger.info('Get Regid to target device');
    app.pushServiceAPI.GetRegIds(dbConn, regQueue[0], function(tarGetInfo, regIdGrp) {        
        i18next.changeLanguage(tarGetInfo.LOCALE.toLowerCase());
        if (typeof tarGetInfo.CALL_TYPE == "undefined" || tarGetInfo.CALL_TYPE == null) tarGetInfo.CALL_TYPE = 3;
        if (tarGetInfo.CALL_TYPE == 1) {
            tarGetInfo.title = '[IIOT-LIVECAM] mVoIP' + i18next.t("push.voice_title");
            tarGetInfo.content = tarGetInfo.MOBILE_NUM + i18next.t("push.voice_desc1") + "\n\n" + i18next.t("push.voice_desc2");
            tarGetInfo.MSG_TYPE = 'CALL';
            tarGetInfo.PUSH_TYPE = '3';
        } else {
            tarGetInfo.title = '[IIOT-LIVECAM] ' + i18next.t("push.video_title");
            tarGetInfo.content = tarGetInfo.MOBILE_NUM + '/' + tarGetInfo.DEV_NM + '/' + tarGetInfo.DEV_DEPT_NM + i18next.t("push.video_desc1");
            tarGetInfo.MSG_TYPE = 'VIEW';
            tarGetInfo.PUSH_TYPE = '1';
        }
        pushMessage(tarGetInfo, regIdGrp);
    });
}

function pushMessage(info, registrationIds) {

    //var server_access_key = "AIzaSyAURTN3yKn0U8s6Lbl8rKylrhC4INCi6FA";
    var sender = new gcm.Sender(serverConf.server_access_key);

    var message = new gcm.Message();

    // send push message
    info.cust_key = new Date().getTime();
    info.requestTime = new Date().formatDate("yyyyMMddhhmmss") + '' + new Date().getMilliseconds();

    message.addData('P_CUST_CTN', info.MOBILE_NUM);
    message.addData('P_INSERT_DATE', info.INSERT_DATE);

    // 추가
    message.addData('VIEW_NUM', info.mobileList[0].ctn);
    message.addData('VIEW_CTN_DEVICE', info.mobileList[0].view_ctn_device);

    message.addData('MSG_TYPE', info.MSG_TYPE);
    message.addData('CUST_KEY', info.cust_key);
    message.addData('PUSH_TYPE', info.PUSH_TYPE);
    message.addData('TITLE', info.title);
    message.addData('MESSAGE', info.content);
    message.addData('REQUEST_TIME', info.requestTime);

    logger.info('send message : ', message);
    sender.send(message, {
        registrationTokens: registrationIds
    }, 1, function(err, response) {

        if (err) {
            logger.crit('gcm send error:', err);
        }

        var curTime = new Date().formatDate("yyyyMMddhhmmss") + '' + new Date().getMilliseconds();
        info.responseTime = curTime;

        logger.info('response : ', response);

        // call back
        //-- 응답 결과 데이터 Insert
        app.pushServiceAPI.insertResult(dbConn, info, registrationIds, response);

        //-- 응답 결과 분석 후 reg_id DB 수정
        app.pushServiceAPI.manageRegID(dbConn, info, response, function(ret) {

            // 재전송 필요
            if (ret != null) {
                logger.info('retry regQueue add : ', ret);
                if (retransCount < 3) {
                    regQueue.push(ret);
                    retransCount++;
                } else {
                    retransCount = 0;
                }
            }

            logger.info('manageRegID end');
        });


        // 처리된 push 요청 제거
        logger.info('queue 제거');
        regQueue.shift();

        //addpushdelay = addpushdelay - 1;

        //-- queue에 보낼 요청이 남아 있다면 send push message
        if (regQueue.length > 0) {
            logger.info('regQueue.length :', regQueue.length);
            logger.info('recursive push_gcm');
            push_gcm(null);
        }

        //-- 없으면 빠져 나오기
        logger.info('exit push_gcm');
    });
}

function push_jpush(data)
{
	// get reg_id
	logger.info('Get Regid to target device');
	// pushServiceAPI.GetRegIds(dbConn, regQueue[0], function(tarGetInfo, regIdGrp){
	pushServiceAPI.GetRegIds(dbConn, data, function(tarGetInfo, regIdGrp){

		i18n.changeLanguage(tarGetInfo.LOCALE.toLowerCase());
		tarGetInfo.title = '[IIOT-LIVECAM] mVoIP ' + i18n.t("msg.push.video_title");
		tarGetInfo.content = tarGetInfo.MOBILE_NUM + '|' + tarGetInfo.DEV_NM + '|' + tarGetInfo.DEV_DEPT_NM + '|' + tarGetInfo.CHANNEL_NM + i18n.t("msg.push.video_desc1");
		tarGetInfo.MSG_TYPE = 'VIEW';
		tarGetInfo.PUSH_TYPE = '1';
		tarGetInfo.CUST_KEY = new Date().getTime();
		tarGetInfo.REQUEST_TIME = new Date().formatDate("yyyyMMddhhmmss") + '' +  new Date().getMilliseconds();

		jPush.sendJPush(tarGetInfo, regIdGrp);		
	});
}

module.exports = client;
