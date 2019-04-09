var logger = require('./logger');
var util = require('util');
var EventEmitter   = require('events').EventEmitter;
var Result = require('./Result');
var fs = require('fs');
var request = require('request');
var querystring = require('querystring');
var http = require('http');
var path = require('path');
var CloudHistory = require('./CloudHistory');
// var app = require('../app.js')
// var io = app.io;

module.exports = AnalysisObjectLib;

var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));

function AnalysisObjectLib() {
}

AnalysisObjectLib.prototype.serviceNotification = function serviceNotification(type, info, callback) {
    var headers = {
        "Content-Type" : "application/json",
        // "Content-Type" : "application/x-www-form-urlencoded"
    };

    // 규격 필요
    var body = {
        ID: info.USER_ID,
        SVC_ID: 'iliveCam',
        LC_CUST_CODE: info.CONTROL_ID.substring(6, 9),
        D_ID: info.MOBILE_NUM,
        D_CTN: '01022330436',
        NOTI_TYPE: type
    };

    // 규격 필요
    var baseUrl, port, uri;
    // if (body.LC_CUST_CODE == "003") {           // 베이리스 utm server
        baseUrl = serverConf.utm.baseUrl
        port = serverConf.utm.port;
        uri = '/utmapi/v1/recording_status';
    // } else if (body.LC_CUST_CODE == "022") {    // analysis object server
    //     baseUrl = serverConf.analysisObject.baseUrl
    //     port = serverConf.analysisObject.port;
    //     uri = '/serviceNotification';
    // } else {                                    // 그 외에는 처리 x
    //     return;
    // }

    requestSever('POST', baseUrl, port, uri, headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(err, false, resBody);
            }
        }
    });    
}

//------ 객체 분석 서버 요청 함수
function requestSever(method, baseUrl, port, uri, headers, body, callback) {
    logger.info('requestSever :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));
    request({
        method: method,
        baseUrl: baseUrl + ':' + port.toString(),
        uri: uri,
        headers: headers,
        json: body,
        rejectUnauthorized : false
    }
    , function(err, res, resBody) {
        if (err) {
            logger.info('requestSever :', uri, err);
            callback(err, null, null);
        } else {
            logger.info('requestSever :', uri, res.statusCode, resBody);
            callback(null, res.statusCode, resBody);
        }
    });    
}


// function requestSever(method, baseUrl, port, uri, headers, body, callback) {
//     logger.info('requestSever :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));

//     var bodyString = JSON.stringify(body);
//     logger.info('body : ', bodyString);

//     var headers = {
//         'Content-Type': 'application/x-www-form-urlencoded',
//         'Content-Length': Buffer.byteLength(bodyString)
//       }

//     var options = {
//         hostname: baseUrl,
//         port: port,
//         path: uri,
//         method: method,
//         headers : headers
//     };

//     var req = http.request(options, function (res) {
//         logger.info('statusCode:', res.statusCode);

//         var body = '';
//         res.on('data', function (d) {
//             body += d;
//         });

//         res.on('end', function (d) {
//             logger.info('end');
//             callback(null, res.statusCode, body);
//         });

//         res.on('error'), function (e) {
//             logger.info('error');
//             callback(e, null, null);
//         }
//     })

//     req.write(bodyString);
//     req.end();
// }
