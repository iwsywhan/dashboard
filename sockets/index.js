
var logger = require('../libs/logger');
var dbConn = require('../db');
var util = require('util');
var socketIO = require('socket.io');
var struct = require('../coupledMessage');
var EVENTS = require('./events');
var client = require('../socketClient');
var app = require('../app');
var io = null;
var gcm = require('node-gcm');
var util = require('util');
var app = require('../app');
var i18next =  require('i18next');
var jPush = require('../libs/jPushServiceAPI.js')
var dbConn = require('../db');
var fs = require('fs');

var serverConf = JSON.parse(fs.readFileSync('./config/server.json'));

var regQueue = [];

exports.io = function() {
    return io;
};

exports.initialize = function(server) {
    io = socketIO(server);
    io.set({'transports': ['polling'], upgrade: false});
    io.on('connection', function (socket) {

        socket.on('disconnect', function() {
            logger.info(socket.id + ' has disconnected from the chat.');
        });
    
        socket.on('addVoice', function(data) {
            logger.info('Add Voice Event occurred.');
            //logger.info('Receive Data:', data);
    
            packet = struct.makeData(data.COMMAND, data);
    
            //logger.info('packet:', packet);
            var retVal = client.write(packet, function(){
                if (retVal){
                    logger.info('packet write success');
                    //io.sockets.connected[id].emit('insertVoiceList', data);
                    // logger.info('socket emit msgEvent / id:', id);
    
                    // 관제센터 영상 추가 시 푸시 메세지
                    //if(request.session.mVoIP == 'Y' && data.CALL_TYPE == '1') {

                    // var query = util.format(''
                    // ,data.voiceList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
                    // dbConn.query(query, function (error, results) {    
                    //     logger.info('Query:', query);
    
                    //     if (error){
                    //         logger.error('DB Error:', error);
                    //     }else {
                            
                    //     }
                    // });

                    if(data.mVoIP == 'Y' && data.CALL_TYPE == '1') {
                        data.mobileList = data.voiceList;
                        push_gcm(data);
                    }
                } else{
                    logger.info('packet write fail');
                }
            });
        });
    
        socket.on('retryVoice', function(data) {
            logger.info('retryVoice Event occurred.');
            //logger.info('Receive Data:', data);
            packet = struct.makeData(data.COMMAND, data);
    
           // logger.info('packet:', packet);
            var retVal = client.write(packet, function(){
                if (retVal){
                    logger.info('packet write success');
                    //io.sockets.connected[id].emit('insertVoiceList', data);
    
                    var query = util.format('update TB_TERMINAL_IMAGE_TRANS set CTN_CNT=IFNULL(CTN_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
                        ,data.voiceList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
                    dbConn.query(query, function (error, results) {
    
                        logger.info('Query:', query);
    
                        if (error){
                            logger.error('DB Error:', error);
                        }else {
                            //logger.info('DB success');
                        }
                    });
    
                    //console.log('socket emit msgEvent / id:', id);
                } else{
                    logger.error('packet write fail');
                }
            });
        });
    
        socket.on('addSTB', function(data) {
            logger.info('Add STB event occurred');
            //logger.info('Receive Data:', data);
            packet = struct.makeData(data.COMMAND, data);
    
            //logger.info('packet:', packet);
            var retVal = client.write(packet, function(){
                if (retVal){
                    logger.info('packet write success');
    
                    var query = util.format('update TB_TERMINAL_IMAGE_TRANS set STB_CNT=IFNULL(STB_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
                        ,data.stbList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
                    dbConn.query(query, function (error, results) {
    
                        logger.info('Query:', query);
    
                        if (error){
                            logger.error('DB Error:', error);
                        }else {
                            //logger.info('DB success');
                            //response.send(results);
                        }
                    });
    
                    //io.sockets.connected[id].emit('insertSTBList', data);
                    // logger.info('socket emit msgEvent / id:', id);
                } else{
                    logger.error('packet write fail');
                }
            });
        });
    
        socket.on('retrySTB', function(data) {
            logger.info('retrySTB event occurred');
            //logger.info('Receive Data:', data);
            packet = struct.makeData(data.COMMAND, data);
    
            //logger.info('packet:', packet);
            var retVal = client.write(packet, function(){
                if (retVal){
                    logger.info('packet write success');
    
                    var query = util.format('update TB_TERMINAL_IMAGE_TRANS set STB_CNT=IFNULL(STB_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
                        ,data.stbList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
                    dbConn.query(query, function (error, results) {
    
                        logger.info('Query:', query);
    
                        if (error){
                            logger.error('DB Error:', error);
                        }else {
                            //logger.info('DB success');
                            //response.send(results);
                        }
                    });
    
                } else{
                    logger.error('packet write fail');
                }
            });
        });
    
        socket.on('deleteSTB', function(data) {
            logger.info('Delete STB event occurred', data);
            //logger.info('Receive Data:', data);
            packet = struct.makeData(data.COMMAND, data);
            //logger.info('packet:', packet);
    
            var retVal = client.write(packet, function(){
            });
    
        });
    
        socket.on('addMobile', function(data) {
            logger.info('addMobile event occurred');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function() {
                logger.info('addMobile packet was sent to Application Server');
            });
        });
    
        socket.on('deleteMobile', function(data) {
            logger.info('deleteMobile event occurred');
            //logger.info('Receive Data:', data);
            packet = struct.makeData(data.COMMAND, data);
            //logger.info('packet:', packet);
    
            var retVal = client.write(packet, function() {
                logger.info('deleteMobile packet was sent to Application Server');
            });
        });
        //#2 End
    
        socket.on('changeSetupEvent', function(data) {
    
            logger.info('changeSetupEvent occured');
    
            if (data.COMMAND == "B708")
                packet = struct.makeData(data.COMMAND, data);
            else
                packet = struct.makeData(data, '');
    
            logger.info('make changeSetupEvent message');
            var retVal = client.write(packet, function() {
                if (retVal) {
                    logger.info('changeSetupEvent to AppServer was sent');
                }
            });
        });
    
    
        socket.on('socketControl', function(data) {
            logger.info('socketControl event occurred');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function() {
                logger.info('socketControl packet was sent to Application Server');
            });
        });
    
    
        socket.on('service_close', function(data) {
    
            logger.info('service_close occured');
    
            var resBody = 'MOBILE_NUM='+data.MOBILE_NUM+'&CTN_DEVICE='+data.CTN_DEVICE+'&INSERT_DATE='+data.INSERT_DATE;
            packet = struct.makeData(data.COMMAND, resBody);
    
            logger.info('make service_close message');
            var retVal = client.write(packet, function() {
                if (retVal) {
                    logger.info('service_close to AppServer was sent');
                }
            });
        });
    
        socket.on('startStream', function (data) {
    
            logger.info('startStream event occured!');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function () {
                if (retVal) {
                    logger.info('startStream event to AppServer was sent');
                }
            });
        });
    
        socket.on('EndStream', function (data) {
    
            logger.info('endStream event occured!');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function () {
                if (retVal) {
                    logger.info('endStream event to AppServer was sent');
                }
            });
        });
    
        socket.on('Abnormal', function (data) {
    
            logger.info('Abnormal event occured!');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function () {
                if (retVal) {
                    logger.info('Abnormal event to AppServer was sent');
                }
            });
        });
    
        //# start 20170828 by ywhan
        // VOD Play range
        socket.on('B306', function (data) {
            logger.info('B306 event occured');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function(){
                logger.info('B306 event to AppServer was sent');
            });
        });
    
        // VOD Pause
        socket.on('B307', function (data) {
            logger.info('B307 event occured');
            packet = struct.makeData(data.COMMAND, data);
    
            var retVal = client.write(packet, function(){
                logger.info('B307 event to AppServer was sent');
            });
        });
        //# end
    
        //# start 20170531 by ywhan
        // AR Memo set up message [B210]
        socket.on('B210', function (data) {
            logger.info('B210 event occured');
            packet = struct.makeData(data.COMMAND, data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B210 event to AppServer was sent');
            });
        });
        // AR Memo play message [B211]
        socket.on('B211', function (data) {
            logger.info('B211 event occured');
            packet = struct.makeData(data.COMMAND, data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B211 event to AppServer was sent');
            });
        });
        // AR Memo add new pcviewer message [B212]
        socket.on('B212', function (data) {
            logger.info('B212 response event occured');
            //packet = struct.makeData(data.COMMAND, data.BODY);
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B212 event to AppServer was sent');
            });
        });
    
        // AR Memo History pcviewer message [B214]
        socket.on('B214', function (data) {
            logger.info('B214 event occured');
            packet = struct.makeData(data.COMMAND, data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B214 event to AppServer was sent');
            });
        });
    
        // AR Memo status notice message [B215]
        socket.on('B215', function (data) {
            logger.info('B215 event occured');
            packet = struct.makeData(data.COMMAND, data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B215 event to AppServer was sent');
            });
        });
        // AR Memo stop message [B216]
        socket.on('B216', function (data) {
            logger.info('B216 event occured');
            if (data.METHOD == "request") {
                logger.info('B216 request event occured');
                packet = struct.makeData(data.COMMAND, data.BODY);
            } else {
                logger.info('B216 response event occured');
                packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);
            }
    
            var retVal = client.write(packet, function(){
                logger.info('B216 event to AppServer was sent');
            });
        });
        //# end 20170531
    
        // notice wirte request [B230]
        socket.on('B230', function (data) {
            logger.info('B230 event occured');
            packet = struct.makeData(data.COMMAND, data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B230 event to AppServer was sent');
            });
        });
    
        // notice recieve response [B231]
        socket.on('B231', function (data) {
            logger.info('B231 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);
    
            var retVal = client.write(packet, function(){
                logger.info('B231 event to AppServer was sent');
            });
        });
    
        // start to voice  [B260]
        socket.on('B260', function (data) {
            logger.info('B260 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

            var retVal = client.write(packet, function(){
                logger.info('B260 event to AppServer was sent');
            });
        });

        // end to voice [B261]
        socket.on('B261', function (data) {
            logger.info('B261 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

            var retVal = client.write(packet, function(){
                logger.info('B261 event to AppServer was sent');
            });
        });

        // mVoIP member status [B262]
        socket.on('B262', function (data) {
            logger.info('B262 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

            var retVal = client.write(packet, function(){
                logger.info('B262 event to AppServer was sent');
            });
        });

        // start to listen [B263]
        socket.on('B263', function (data) {
            logger.info('B263 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

            var retVal = client.write(packet, function(){
                logger.info('B263 event to AppServer was sent');
            });
        });

        // end to listen [B264]
        socket.on('B264', function (data) {
            logger.info('B264 response event occured');
            packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

            var retVal = client.write(packet, function(){
                logger.info('B264 event to AppServer was sent');
            });
        });        
        socket.on('log_OperatePCViewer', function (data) {    
            var logMsg;
            logMsg = 'OperatePCViewer' + ' [' + data.USER_ID + ']' + '[' + data.DIR + ']' + '[' + data.OPERATE + ']' + '[' + data.PARAM + ']' + ' : ' + data.RESULT;
            logger.info(logMsg);
        });
    });
    return io;
};

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

        if (typeof tarGetInfo.LOCALE == "undefined") {
            i18next.changeLanguage("ko");    
        } else {
            i18next.changeLanguage(tarGetInfo.LOCALE.toLowerCase());    
        }

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
