var logger = require('./logger');
var util = require('util');
var EventEmitter   = require('events').EventEmitter;
var Result = require('./Result');
var fs = require('fs');
var request = require('request');
var querystring = require('querystring');
var crypto = require('crypto');
var http = require('http');
var path = require('path');
var CloudHistory = require('./CloudHistory');
var app = require('../app.js')

module.exports = TerraLib;

var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));

function TerraLib() {
    this._token = null;
}

TerraLib.prototype.createToken = function (email, password, callback) {
    var headers = {
        "Content-Type" : "application/json"
    };
    var body = {
        "email": email,
        "password": password
    };

    requestTerra('POST', serverConf.terra.baseUrl, 'v1/login', headers, body, function(err, status, resBody) {
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

TerraLib.prototype.getApiToken = function (callback) {
    var self = this;
    self.createToken(serverConf.terra.email, serverConf.terra.password, function (err, bResult, result) {
        if (err) {
            logger.error(err);
            callback(err, false, null);
            return;
        }   

        if (bResult) {
            callback(null, true, result.data.token)
        } else {
            // if (result.message.error == 'TOKEN_EXPIRED') {      // 토큰 인증 유효기간 종료
            if (result.error.code > 0) {      // 토큰 인증 유효기간 종료
                callback(null, false, result.error);
            }
        }
    })
}

TerraLib.prototype.droneSync = function (accessToken, serial, name, manufacture, callback) {
    var headers = {
        "Content-Type" : "application/json" ,
        "Authorization": "Bearer " + accessToken,
    };
    var body = {
        serial: serial, 
        name: name,
        manufacture: manufacture
    };

    requestTerra('GET', serverConf.terra.baseUrl, '/v1/drones', headers, body, function(err, status, resBody) {
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

function requestTerra(method, baseUrl, uri, headers, body, callback) {
    logger.info('requestTerra :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));

    // queryDNS(baseUrl, function(err1, ipAddr) {
        // logger.info('ipAddr', ipAddr);
        // if (err) {
        //     callback(err1, null, null);
        // } else {
            request({
                method: method,
                baseUrl: baseUrl,
                uri: uri,
                headers: headers,
                json: body,
                rejectUnauthorized : false
            }
            , function(err, res, resBody) {
                if (err) {
                    logger.error('responseTerra :', uri, err);
                    callback(err, null, null);
                } else {
                    logger.info('responseTerra :', uri, res.statusCode, resBody);
                    callback(null, res.statusCode, resBody);
                }
            });
        // }
    // });    
}
