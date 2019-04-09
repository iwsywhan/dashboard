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
const dns = require('dns');
const DEF_NODE_VERSION = process.version;

module.exports = ClouldLib;

var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));

function ClouldLib() {
    this.PARTY_TOKEN = {};
    // this.API_TOKEN = {};
    this.cloudHis = new CloudHistory();
}

// OpenAPI 2.0
// ----- 클라우드 처리 함수
function requestCloud(method, baseUrl, uri, headers, body, callback) {
    logger.info('requestCloud :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));

    queryDNS(baseUrl, function(err1, ipAddr) {
        logger.info('ipAddr', ipAddr);
        if (err1) {
            callback(err1, null, null);
        } else {
            request({
                method: method,
                // baseUrl: ipAddr,
                baseUrl: baseUrl,
                uri: uri,
                headers: headers,
                json: body,
                rejectUnauthorized : false
            }
            , function(err, res, resBody) {
                if (err) {
                    logger.error('responseCloud :', uri, err);
                    callback(err, null, null);
                } else {
                    if (res.statusCode != '200') {
                        if (resBody.code != '3002') {
                            logger.error('responseCloud :', uri, res.statusCode, resBody);
                        } else {
                            logger.info('responseCloud :', uri, res.statusCode, resBody);
                        }
                    } else {
                        logger.info('responseCloud :', uri, res.statusCode, resBody);
                    }
                    
                    callback(null, res.statusCode, resBody);
                }
            });
        }
    });    
}

function requestCloud_D(method, baseUrl, uri, headers, body, res, callback) {
    logger.info('requestCloud_D :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));

    queryDNS(baseUrl, function(err1, ipAddr) {
        if (err1) {
            callback(err1, null);
        } else {
            var stream = request({
                method: method,
                baseUrl: ipAddr,
                uri: uri,
                headers: headers,
                encoding: null
            })
            .on('response', function(res) {
                logger.info('responseCloud_D :', uri, res.statusCode);
                callback(null, res.statusCode);
            })
            .pipe(res)
            .on('error', function(err) {
                logger.error('download error', err);
                callback(err, null);
            })
            .on('finish', function(res) {
                logger.info('download done');
            })
        }
    });
}
// function requestCloud_D(method, baseUrl, uri, headers, body, callback) {
//     logger.info('requestCloud_D :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(body));
//     request({
//         method: method,
//         baseUrl: baseUrl,
//         uri: uri,
//         headers: headers,
//         encoding: null
//     }
    // , function(err, res, resBody) {
    //     if (typeof res.statusCode == "undefined") {
    //         logger.info('responseCloud_D :', uri, err);
    //     } else {
    //         logger.info('responseCloud_D :', uri, err, res.statusCode);
    //     }
    //     if (err) {
    //         callback(err, null, null);
    //     } else {
    //         callback(null, res.statusCode, resBody);
    //     }
    // });    
// }

function requestCloud_U(method, baseUrl, uri, headers, formData, callback) {
    logger.info('requestCloud_U :', method, baseUrl, uri, JSON.stringify(headers), JSON.stringify(formData));

    queryDNS(baseUrl, function(err1, ipAddr) {
        if (err1) {
            callback(err1, null, null);
        } else {
            request({
                method: method,
                baseUrl: ipAddr,
                uri: uri,
                headers: headers,
                formData: formData //,
                // rejectUnauthorized : false
            }
            , function(err, res, resBody) {
                if (err) {
                    logger.error('responseCloud_U :', uri, err);
                    callback(err, null, null);
                } else {
                    logger.info('responseCloud_U :', uri, res.statusCode, resBody);
                    callback(null, res.statusCode, resBody);
                }
            });
        }
    })    
}

function queryDNS(hostname, callback) {
    var options;
    if (DEF_NODE_VERSION == 'v0.10.35') {
        options = 4;
    } else {
        options = {
            family: 4,
            hints: dns.ADDRCONFIG | dns.V4MAPPED
        };

    }

    var protocolPos = hostname.indexOf('//')
    var protocol = hostname.slice(0, protocolPos-1);
    var url = hostname.slice(protocolPos+2, hostname.length);
    var domain = url.split(':')[0];
    var port = url.split(':')[1];
    
    dns.lookup(domain, options, function (err, address, family) {
        if (err) {
            callback(err, null);
        } else {
            if (typeof port === 'undefined')
                callback(null, protocol + '://' + address);
            else
                callback(null, protocol + '://' + address + ':' + port);
        }
    })
}

function isEnableToken(token) {
    if (typeof token.accessToken === "undefined") {
        return false;
    } else {
        if (Number(token.expireTimeStamp) < Number(new Date().getTime())) {
            return false;
        }
    }
    return true;
}

function encrypt(salt, f_key) {
    var plainText = f_key + salt.toString();
    var cipher = crypto.createCipher('aes-128-ecb', serverConf.cloud.authKey)
    cipher.setAutoPadding(true);
    var crypted = cipher.update(plainText,'utf8','base64')
    crypted += cipher.final('base64')
    return crypted;
}

////-------------------- Cloud OAuth API 2.0 ---------------------////
ClouldLib.prototype.createPartyToken = function createPartyToken(callback) {
    var headers = {
        "Content-Type" : "application/json"    
    };
    var body = {
        authId: serverConf.cloud.authId, 
        authKey: serverConf.cloud.authKey
    };

    requestCloud('POST', serverConf.cloud.baseUrl, '/oauth2/tokens/party', headers, body, function(err, status, resBody) {
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

function createFKey(partyToken, id, pid, callback) {

    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + partyToken,
        "Referer": "http://106.243.121.204:11443"
    };
    var body = {
        pid: pid,
        identity: id
    };

    requestCloud('POST', serverConf.cloud.baseUrl, '/oauth2/users/party', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            // if (status == 200 || (status == 500 && resBody.code == '6104')) {   // 계정 생성 성공 혹은 계정 중복 시에도 가입 가능
            if (status == 200) { // || (status == 500 && resBody.code == '6104')) {   // 계정 생성 성공 혹은 계정 중복 시에도 가입 가능
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}


ClouldLib.prototype.createApiToken = function (accessToken, salt, signature, callback) {

    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + accessToken,
        "Salt": salt,
        "Signature": signature
    };
    var body = {
    };

    requestCloud('POST', serverConf.cloud.baseUrl, '/oauth2/users/me', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

//////////////////////////////////////////////////
ClouldLib.prototype.getFKey = function getFKey(id, pid, callback) {
    var self = this;
    self.cloudHis.isCreatedFKey(app.dbConn, id, function(err, bResult1, result1) {
        if (!bResult1) {         // 생성된 F_KEY가 없을 경우 생성
            self.getPartyToken(function(partyToken) {
                if (partyToken) {
                    createFKey(partyToken, id, pid, function(err, bResult, result) {
                        if (bResult) {
                            logger.info(result);
                            self.cloudHis.insertFKey(app.dbConn, id, result.f_key, function(err, bResult) {
                                if (bResult) {
                                    callback(true, result);
                                } else {
                                    callback(false, err);
                                }
                            });
                        } else {
                            if (result.code == '6104') {        // 계정이 존재합니다.
                                callback(true, result);
                            } else {
                                callback(false, result);
                            }
                        }
                    });
                } else {
                    logger.info('대표토큰 발급 실패');
                    callback(false, {code: '00001', message: '대표토큰 발급 실패'});
                }
            })
        } else {
            callback(true, result1);
        }
    })
}

ClouldLib.prototype.getPartyToken = function getPartyToken(callback) {
    var self = this;
    if (!isEnableToken(self.PARTY_TOKEN)) {
        self.createPartyToken(function(err, bResult, body) {
            if (bResult) {
                self.PARTY_TOKEN = body;
                callback(self.PARTY_TOKEN.accessToken)
            } else {
                callback(false, body);
            }
        })
    } else {
        callback(self.PARTY_TOKEN.accessToken);
    }
}

ClouldLib.prototype.getApiToken = function getApiToken(identity, callback) {
    // API 토큰 유효성 체크
    var self = this;
    self.cloudHis.getAvailableToken(app.dbConn, identity, function(err, bResult1, result1) {
        logger.info('getAvailableToken', err, bResult1, result1)
        if (bResult1) {         // 유효하다면
            callback(result1.ACCESS_TOKEN, result1.EXPIRE_DATE);
        } else {        // DB에 유효한 토큰이 존재하지 않다면 클라우드에 토큰 발급 요청
            self.getPartyToken(function(token, result) {     // 제휴사 대표 토큰을 가져와서 Api 토큰 발급 요청            
                if (token) {
                    var salt = new Date().getTime();
                    var f_key = result1.F_KEY;
                    var signature = encrypt(salt, f_key);
                    self.createApiToken(token, salt, signature, function(err, bResult2, result2) {
                        logger.info('createApiToken : ', err, bResult2, result2);
                        if (bResult2) {
                            self.cloudHis.updateToken(app.dbConn, result1.ADMIN_ID, result2, function(err, bResult3, result3) {
                                logger.info('updateToken : ', err, bResult3, result3);
                                if (bResult3) {
                                    callback(result2.accessToken, result2.expireTimeStamp);
                                } else {
                                    callback(false);
                                }
                            })
                        } else {
                            callback(false, result2);
                        }
                    })
                } else {
                    logger.info('대표토큰 발급 실패');
                    callback(false, result);
                }
            })
        }
    });
}

// 클라우드 스토리지 상품을 가입한 회원 상태를 조회
function getInfoStatus() {
    var salt = new Date().getTime();
    var f_key = "N84GhOqATDbYa0Ud/ad6Q5eGikqBjghOqj47G9X9Q0M=";
    var signature = encrypt(salt, f_key);
    getMemberStatus(salt, signature, function(err, bResult, body) {
        if (bResult) {
            callback(body.status);
        } else {
            callback(false);
        }
    })    
}

function getMemberStatus(salt, signature, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + this.PARTY_TOKEN.accessToken,
        "Salt": salt,
        "Signature": signature
    };
    requestCloud('GET', serverConf.cloud.baseUrl, '/oauth2/infos/status', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}

////-------------------- Cloud Open API 2.0 ---------------------////

// 전체 목록 조회(신규)
ClouldLib.prototype.getFoldersListAll = function getFoldersListAll(apiToken, folderId, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiToken
    };

    // var params = 'folderId='+folderId+'&cate=7&orderCondition=R';
    var params = 'folderId='+folderId+'&cate=7&orderCondition=K&searchCount=200';    
    requestCloud('GET', serverConf.cloudOpenAPI.baseUrl, 'v2/search/contenttype?'+params, headers, {}, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}


// 폴더 생성
ClouldLib.prototype.createFolderRequest = function createFolderRequest(token, parentFolderId, folderName, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    };
    var body = {
        folderName: folderName
    };

    requestCloud('POST', serverConf.cloudOpenAPI.baseUrl, 'v2/folders/control/'+parentFolderId, headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

// 업로드 서버 정보 조회(신규)
ClouldLib.prototype.getUploadServerInfo = function getUploadServerInfo(apiToken, params, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiToken
    };
    var body = {};
    requestCloud('GET', serverConf.cloudOpenAPI.baseUrl, 'v2/scn/files/info/uploadinfo?'+params, headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}

// 업로드(신규)
ClouldLib.prototype.uploadFiles = function uploadFiles(apiToken, url, params, callback) {
    var headers = {
        "Content-Type": "multipart/form-data",
        "Authorization": "Bearer " + apiToken
    };

    if (!fs.existsSync(params.uploadFile)) {
        callback('file not found', null, null);
        return;
    }

    var formData = {
        folderId: params.folderId,
        uploadName: params.uploadName,
        uploadSize: params.uploadSize,
        traceId: params.traceId,
        uploadId: params.uploadId,
        offset: params.offset,
        uploadFin: params.uploadFin,
        uploadMode: params.uploadMode,
        uploadFile: {
            value: fs.createReadStream(params.uploadFile),
            options: {
                filename: params.uploadName,
                contentType: "multipart/form-data"
            }
        }
    };    
    
    requestCloud_U('POST', url, 'scn/open/uploadfile', headers, formData, function(err, status, resBody) {        
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}

// 다운로드 서버 정보 조회
function getDownloadServerInfo(token, fileId, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    };
    requestCloud('GET', serverConf.cloudOpenAPI.baseUrl, 'v2/scn/files/'+fileId+'/info/download', headers, {}, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}

// 다운로드
// function downloadFiles(token, url, range, nonce, fileId, res) {
//     var headers = {
//         "Authorization": "Bearer " + token,
//         "Range": range,
//         "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
//     };
//     var params = "nonce="+nonce+"&fileId="+fileId;

//     requestCloud_D('GET', url, '/scn/open/download?'+params, headers, {}, res);
// }

function downloadFiles(token, url, range, nonce, fileId, res, callback) {
    var headers = {
        "Authorization": "Bearer " + token,
        "Range": range,
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    };
    var params = "nonce="+nonce+"&fileId="+fileId;

    requestCloud_D('GET', url, '/scn/open/download?'+params, headers, {}, res, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200 || status == 206) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

// 파일 삭제
function deleteFolders(token, folder_id, callback) {
    var headers = {
        "Authorization": "Bearer " + token
    };

    var body = {};
    body.folderIds = [];
    body.folderIds.push(folder_id);
    requestCloud('POST', serverConf.cloudOpenAPI.baseUrl, 'v2/folders/control/delete', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

// 파일 삭제
function deleteFiles(token, file_id, callback) {
    var headers = {
        "Authorization": "Bearer " + token
    };

    var body = {};
    body.fileIds = [];
    body.fileIds.push(file_id);
    requestCloud('POST', serverConf.cloudOpenAPI.baseUrl, 'v2/files/control/delete', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

// 클라우드 사용량 조회
function getAvailableUsageRequest(token, callback) {
    var headers = {
        "Authorization": "Bearer " + token
    };

    var body = {};
    requestCloud('GET', serverConf.cloudOpenAPI.baseUrl, 'v2/users/me/infos/usage', headers, body, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });    
}

// ClouldLib.prototype.createFolder = function createFolder(apiToken, droneName, folderType, folderName, identification, callback) {
ClouldLib.prototype.getFolderId = function getFolderId(userId, droneName, folderType, folderName, identification, callback) {
    var self = this;
    // 1:업로드 요청, 2:실시간 스냅샷, 3:실시간 영상
    var fileTypeName;
    if (folderType == 1) {
        fileTypeName = 'UPLOAD';
    } else if (folderType == 2) {
        fileTypeName = 'RT_SNAPSHOT';
    } else {        // 3
        fileTypeName = 'RT_VIDEO';
    }

    // 폴더 존재 여부 확인
    self.cloudHis.isCreatedFolderId(app.dbConn, identification, folderType, function(err, bResult2, result2) {
        logger.info('isCreatedFolderId', err, bResult2, result2);
        if (bResult2) {     // 폴더 존재 시 기존 folderid 이용
            callback(null, true, result2, result2.PARENT_FOLDER_ID);
        } else {            // 폴더 존재하지 않을 시 생성
            // var newFolderName = new Date().formatDate("yyyyMMddhhmmss");
            var newFolderName = identification;
            self.createFolder(userId, droneName, folderType, newFolderName, identification, function(err, bResult, result, parentFolderId) {
                if (err) {
                    callback(err, false, null);
                    return;
                }
                if (bResult) {
                    var newResult = {};
                    newResult.FOLDER_ID = result.folderId;        // callback을 받는 부분에서 참조의 일관성 문제 때문에 추가
                    newResult.FOLDER_NAME = newFolderName;
                    callback(null, true, newResult, parentFolderId);
                } else {
                    callback(null, false, result);
                }
            })
            /*
            self.cloudHis.getFolderId(app.dbConn, droneName, fileTypeName, function(err, bResult, result) {
                if (bResult) {
                    self.createFolderRequest(apiToken, result.folderId, folderName, function(err, bResult1, result1) {
                        if (err) {
                            callback(err, false, null);
                            return;
                        }
                        if (bResult1) {                             // 폴더 생성 성공
                            callback(null, true, result1, result.folderId);
                        } else {
                            if (result1.code == '3002') {           // 폴더 이름 중복 - 여러개의 파일을 1개의 폴더로 올릴 경우에는 폴더 중복 발생할 수 있음
                                callback(null, true, result1, result.folderId);
                            } else {
                                callback(null, false, result1)
                            }
                        }
                    });
                } else {
                    callback(null, false, err);
                }
            })
            */
        }
    });
}

ClouldLib.prototype.createFolder = function createFolder(userId, droneName, folderType, folderName, identification, callback) {
    var self = this;
    // 1:업로드 요청, 2:실시간 스냅샷, 3:실시간 영상
    var fileTypeName;
    if (folderType == 1) {
        fileTypeName = 'UPLOAD';
    } else if (folderType == 2) {
        fileTypeName = 'RT_SNAPSHOT';
    } else {        // 3
        fileTypeName = 'RT_VIDEO';
    }

    var key = {};
    key.SYS_TYPE = '1'
    key.REQ_TYPE = folderType;
    key.DEV_KEY = droneName;
    key.IDENTIFICATION = identification;
    // key.FILE_NAME = fileName;

    self.getApiToken(userId, function(apiToken) {
        if (apiToken) {
            self.cloudHis.getParentFolderId(app.dbConn, droneName, fileTypeName, function(err, bResult, result) {
                if (bResult) {
                    self.createFolderRequest(apiToken, result.folderId, folderName, function(err, bResult1, result1) {
                        if (err) {
                            callback(err, false, null);
                            return;
                        }
                        if (bResult1) {                             // 폴더 생성 성공
                            callback(null, true, result1, result.folderId);
                            var item = {};
                            item.PARENT_FOLDER_ID = result.folderId;
                            item.FOLDER_NAME = folderName;
                            item.FOLDER_ID = result1.folderId;
                            self.cloudHis.updateCreateFolderRes(app.dbConn, key, item, function(sqlResult) {
                                logger.info('updateCreateFolderRes : ', sqlResult)
                            });
                        } else {
                            if (result1.code == '3002') {           // 폴더 이름 중복 - 여러개의 파일을 1개의 폴더로 올릴 경우에는 폴더 중복 발생할 수 있음
                                callback(null, true, result1, result.folderId);
                            } else {
                                callback(null, false, result1)
                            }
                        }
                    });
                } else {
                    callback(err, false, null);
                }
            })
        } else {
            logger.error(userId, fileTypeName, '토큰 발급 실패');
        }
    })
}

ClouldLib.prototype.createDefaultFolder = function createDefaultFolder(droneName, userId, callback) {
    var self = this;
    self.getApiToken(userId, function(apiToken) {
        self.getFoldersListAll(apiToken, '00000', function(err, bResult1, result1) {     // 전체 목록 조회 후 최상위 폴더 ID 획득
            if (bResult1) {
                // 드론 이름 폴더 생성
                self.createFolderRequest(apiToken, result1.currentFolderId, droneName, function(err, bResult2, result2) {
                    logger.info('createFolder :' + droneName, err, bResult2, result2);
                    self.cloudHis.insertFolderId(app.dbConn, 'ROOT', droneName, result2.folderId, function(sqlResult1) {
                        logger.info('insertFolderId : ', sqlResult1, result2.folderId);
                    });

                    if (bResult2 || result2.code == '3002') {     // 폴더 생성 성공 혹은 이미 생성되어 있음
                        // UPLOAD 폴더 생성
                        self.createFolderRequest(apiToken, result2.folderId, 'UPLOAD', function(err, bResult3, result3) {
                            logger.info('createFolder : UPLOAD', err, bResult3, result3);
                            if (bResult3 || result3.code == '3002') {
                                self.cloudHis.insertFolderId(app.dbConn, 'UPLOAD', droneName, result3.folderId, function(sqlResult3) {
                                    logger.info('insertFolderId : ', sqlResult3, result3.folderId);
                                });            
                            }
                        });
                        // RT_VIDEO 폴더 생성
                        self.createFolderRequest(apiToken, result2.folderId, 'RT_VIDEO', function(err, bResult4, result4) {
                            logger.info('createFolder : RT_VIDEO', err, bResult4, result4);
                            if (bResult4 || result4.code == '3002') {
                                self.cloudHis.insertFolderId(app.dbConn, 'RT_VIDEO', droneName, result4.folderId, function(sqlResult4) {
                                    logger.info('insertFolderId : ', sqlResult4, result4.folderId);
                                });            
                            }
                        });
                        // RT_SNAPSHOT 폴더 생성
                        self.createFolderRequest(apiToken, result2.folderId, 'RT_SNAPSHOT', function(err, bResult5, result5) {
                            logger.info('createFolder : RT_SNAPSHOT', err, bResult5, result5);
                            if (bResult5 || result5.code == '3002') {
                                self.cloudHis.insertFolderId(app.dbConn, 'RT_SNAPSHOT', droneName, result5.folderId, function(sqlResult5) {
                                    logger.info('insertFolderId : ', sqlResult5, result5.folderId);
                                });            
                            }
                        });
                    } else {
                        callback(false);
                    }
                });
            } else {
                callback(false);
            }
        });
    });
}

// 수정 필요
ClouldLib.prototype.deleteDefaultFolder = function deleteDefaultFolder(droneName, userId, callback) {
    var self = this;
    self.getApiToken(userId, function(apiToken) {
        if (apiToken) {
            self.findFolderId(apiToken, droneName, 'UPLOAD', function(bResult1, result1, rootFolder) {
                logger.info(bResult1, result1, rootFolder);
                if (bResult1) {
                    // drone 이름의 폴더 삭제 (하위디렉토리 포함)
                    deleteFolders(apiToken, rootFolder.id, function(err, bResult2, result2) {
                        if (bResult2) {
                            callback(true, result2);
                        } else {
                            callback(false, result2);
                        }
                    })
                }
            });
        }
    });
}

ClouldLib.prototype.findFolderId = function findFolderId(apiToken, droneFolderName, fileTypeName, callback) {
    var self = this;
    self.getFoldersListAll(apiToken, '00000', function(err, bResult1, result1) {     // 전체 목록 조회 후 최상위 폴더 ID 획득
        if (bResult1) {
            var rootFolder, findFolder;
            result1.list.forEach(function(element) {
                if (element.name == droneFolderName) {                
                    rootFolder = element;
                    logger.info('rootFolder', rootFolder);
                }
            });

            result1.list.forEach(function(element) {
                if (element.fkind == "D" && element.fullcode.indexOf(rootFolder.id) > 0 && element.name == fileTypeName) {
                    findFolder = element;
                    logger.info('findFolder', findFolder);
                }
            });
            
            if (typeof findFolder != "undefined") {
                callback(true, findFolder, rootFolder);
            } else {
                callback(false, {code:9999, message:'일치하는 폴더를 찾을 수 없습니다.'});
            }
        } else {
            callback(false, result1);
        }
    });
}

ClouldLib.prototype.uploadRequest = function uploadRequest(type, body, fileInfo, callback) {
    logger.info('uploadRequest', type, JSON.stringify(body), JSON.stringify(fileInfo))
    var self = this;

    var key = {};
    key.SYS_TYPE = '1'
    key.REQ_TYPE = body.SEND_TYPE;
    key.DEV_KEY = body.MOBILE_NUM;
    key.IDENTIFICATION = body.IDENTIFICATION;
    key.FILE_NAME = body.FILENAME;                            

    // init 상태
    self.updateReqUploadStatus('init', key, body.USER_ID);

    self.getApiToken(body.USER_ID, function(apiToken, result) {    
        if (apiToken) {
            // 토큰 결과 저장
            self.updateResUploadStatus('api token', key, apiToken);

            // 폴더 이름 생성
            var folderName;
            if (type == "new") {
                folderName = null;
            } else {
                if (fileInfo.folderName == null) {
                    // folderName = new Date().formatDate("yyyyMMddhhmmss");
                    folderName = body.IDENTIFICATION;
                } else {
                    folderName = fileInfo.folderName;
                }    
            }
            // var folderName = new Date().formatDate("yyyyMMddhhmmss");            
            // self.createFolder(apiToken, body.MOBILE_NUM, body.SEND_TYPE, folderName, body.IDENTIFICATION, function(err, bResult1, result1, rootFolder) {        // 폴더 생성
            self.getFolderId(body.USER_ID, body.MOBILE_NUM, body.SEND_TYPE, folderName, body.IDENTIFICATION, function(err, bResult1, result1, parentFolderId) {        // 폴더 생성
                logger.info('0.params', err, bResult1, result1, parentFolderId);
                if (bResult1) {         // 폴더 생성 성공
                    // var folderId = typeof result1.folderId === "undefined" ? result1.currentFolderId : result1.folderId;
                    var folderId = result1.FOLDER_ID;
                    // var parentFolderId = rootFolder;

                    // 폴더 생성 결과
                    var newObject = {};
                    newObject.PARENT_FOLDER_ID = parentFolderId;
                    newObject.FOLDER_ID = folderId;
                    newObject.FOLDER_NAME = result1.FOLDER_NAME;
                    logger.info('newObject', newObject);
                    self.updateResUploadStatus('create folder', key, newObject);

                    var param;
                    if (type == 'new') {
                        param = 'uploadMode=4';
                    } else {                // 'retry'
                        param = 'uploadMode=1&uploadSize=' + fileInfo.uploadSize + '&folderId=' + folderId + '&fileName=' + fileInfo.uploadName;
                    }

                    self.getUploadServerInfo(apiToken, param, function(err, bResult2, result2) {     // 업로드 서버 정보 조회 (신규파일)
                        logger.info('1.params', err, bResult2, result2);

                        if (err) {
                            self.updateResUploadStatus('Error', key, err);
                        } else if (bResult2) {      // 업로드 서버 정보 조회 성공

                            // 업로드 요청 저장
                            self.updateResUploadStatus('upload server', key, result2);
                        
                            var params = {};
                            params.uploadId = result2.uploadId;
                            params.traceId = result2.traceId;
                            params.folderId = folderId.toString();
                            params.uploadName = fileInfo.uploadName;
                            params.uploadSize = fileInfo.uploadSize;
                            if (result2.curFileSize == '0') {
                                params.offset = '0';
                                params.uploadMode = '4';
                            } else {
                                params.offset = Number(result2.curFileSize)+1;
                                params.uploadMode = '1';
                            }                            
                            params.uploadFin = 'Y';
                            params.uploadFile = fileInfo.uploadFile;
                                                
                            self.updateReqUploadStatus('upload file', key, {});
                            self.uploadFiles(apiToken, result2.uploadServerUrl, params, function(err, bResult3, result3) {     // 업로드 요청
                                if (err) {
                                    self.updateResUploadStatus('Error', key, err);
                                    app._io.sockets.emit('UPLOAD_COMPLETE', '');
                                    if (typeof callback === "function") callback(false);
                                    return;
                                }

                                var cloudResult = {};
                                logger.info('uploadFiles', result3);
                                var r = JSON.parse(result3);

                                // 업로드 응답 저장
                                self.updateResUploadStatus('upload file', key, r);
                                app._io.sockets.emit('UPLOAD_COMPLETE', '');
                                if (typeof callback === "function") {
                                    if (r.code == '0000')
                                        callback(true);
                                    else
                                        callback(false);
                                }
                            })
                        } else {
                            // 업로드 서버 정보 조회 실패
                            logger.info('업로드 서버 정보 조회 실패', result2);
                            self.updateResUploadStatus('upload server', key, result2);
                            if (typeof callback === "function") callback(false);
                        }
                    });
                } else {
                    // 폴더 생성 실패
                    logger.info('클라우드 폴더 생성 실패', result1);
                    self.updateResUploadStatus('create folder', key, result1);
                    if (typeof callback === "function") callback(false);
                }
            })
        } else {
            // TOKEN 생성 실패
            logger.info('TOKEN 생성 실패', result);
            self.updateResUploadStatus('init', key, result);
            if (typeof callback === "function") callback(false);
        }
    });
}

ClouldLib.prototype.updateReqUploadStatus = function updateReqUploadStatus(stage, key, param) {
    var self = this;

    var item = {};
    if (stage == 'init') {
        item.UCLOUD_STATUS = '1';
        item.UCLOUD_REQ_USERID = param;
    } else if (stage == 'upload file') {
        // DB에 옵션 추가해야 할까?
        // item.UPLOAD_NAME = param;
        // item.OFFSET = '0';
        // item.UPLOAD_FIN = 'Y';
        // item.UPLOAD_MODE = '4';
        // item.FILE_ID = '';
        // item.ENCODING_YN = '';
        // item.OVER_FLAG = '';
        item.UCLOUD_STATUS = '2';
        item.UCLOUD_UPLOAD_REQ_DATE = new Date();
    } else {
        // item.UCLOUD_UPLOAD_REQ_DATE = new Date();
    }
    
    self.cloudHis.updateUploadReq(app.dbConn, key, item, function(sqlResult) {
        logger.info('updateUploadReq : ', sqlResult)
    });
}

ClouldLib.prototype.updateResUploadStatus = function updateResUploadStatus(stage, key, result) {
    var self = this;

    var item = {};
    logger.info('updateResUploadStatus begin', stage, result, typeof result);

    if (result == null) {
        return;
    }

    if (stage == 'Error') {
        item.UCLOUD_STATUS = '9';
        item.UCLOUD_REASON = result.code;
        item.UCLOUD_DELETE_STATUS = '0';
    // upload file 을 제외하고는 실패 했을 때만 저장하는 항목
    } else if (typeof result.code != 'undefined' && result.code != '0000') {        // 업로드 진행 과정 중 실패 시 코드와 이유 저장
        item.UCLOUD_RESULT_CODE = result.code;
        item.UCLOUD_REASON = result.message;
    } else {
        if (stage == 'api token') {
            item.ACCESS_TOKEN = result;
        } else if (stage == 'create folder') {
            item.PARENT_FOLDER_ID = result.PARENT_FOLDER_ID;
            item.FOLDER_ID = result.FOLDER_ID;
            item.FOLDER_NAME = result.FOLDER_NAME;
        } else if (stage == 'upload server') {
            item.UCLOUD_SERVER_INFO = result.uploadServerUrl;
            item.TRACE_ID = result.traceId;
            item.UPLOAD_ID = result.uploadId;
        } else if (stage == 'upload file') {
            item.FILE_ID = result.fileId;
            item.UCLOUD_DELETE_STATUS = '0';
            item.UPLOAD_CONTINUE_STATUS = '0';
            item.UCLOUD_RESULT_CODE = result.code;
            item.UCLOUD_REASON = '';
        }
    }

    // 최종 상태값 저장
    if (stage == 'upload file') {
        if (result.code == '0000') {                 // 파일 업로드 성공
            item.UCLOUD_STATUS = '3';
        } else {
            if (result.code == '5100') {             // 파일 업로드 실패 (파일 일부가 업로드 되었을 가능성)
                item.UCLOUD_STATUS = '4';
            } else {
                item.UCLOUD_STATUS = '9';
            }
        }
    }

    item.UCLOUD_UPLOAD_RES_DATE = new Date();
    logger.info('updateResUploadStatus end', stage, item)
    self.cloudHis.updateUploadRes(app.dbConn, key, item, function(sqlResult) {
        logger.info('updateUploadRes : ', sqlResult)
    });
}

ClouldLib.prototype.download = function download(req, res, fileInfo, callback) {
    var self = this;
    self.getApiToken(req.session.userid, function(apiToken, result) {
        if (apiToken) {
            getDownloadServerInfo(apiToken, fileInfo.FILE_ID, function(err, bResult1, result1) {
                logger.info('getDownloadServerInfo', err, bResult1, result1);
                var fileSize = Number(fileInfo.FILE_SIZE)-2;

                if (bResult1) {
                    var range = 'bytes=0-' + fileSize;

                    var key = {};
                    key.SYS_TYPE = '1';
                    key.REQ_TYPE = '1'
                    key.USER_ID = req.session.userid;
                    key.FILE_ID = fileInfo.FILE_ID;
                    key.INSERT_DATE = new Date().formatDate("yyyyMMddhhmmss");

                    var input = {};
                    input.FILE_TYPE = fileInfo.FILE_TYPE
                    input.FILE_NAME = fileInfo.FILE_NAME
                    input.FILE_SIZE = fileSize;
                    input.ACCESS_TOKEN = apiToken;
                    input.UCLOUD_SERVER_INFO = result1.downloadServerUrl;
                    input.NONCE = result1.nonce;
                    input.ADJUSTABLE_YN = '';
                    input.SHARE_IMORY_ID = '';
                    input.ENC_TYPE = '';
                    input.STATUS = '0';
                    input.IDENTIFICATION = fileInfo.IDENTIFICATION;
                    input.CUSTOMER_CODE = req.session.code_03;
                
                    self.cloudHis.reqDownloadHistory(app.dbConn, key, input, function(sqlResult1) {
                        logger.info('reqDownloadHistory', sqlResult1);
                    })
                    downloadFiles(apiToken, result1.downloadServerUrl, range, result1.nonce, fileInfo.FILE_ID, res, function(err, bResult2, result2) {
                        logger.info('downloadFiles', err, bResult2);
                        var cloudResult = {};
                        if (err) {
                            cloudResult.STATUS = '9';
                            cloudResult.RESULT_CODE = '0001';
                            cloudResult.REASON = err;
                        } else if (bResult2) {
                            cloudResult.STATUS = '1'
                            cloudResult.RESULT_CODE = '0000'
                            cloudResult.REASON = ''
                        } else {
                            cloudResult.STATUS = '9'
                            cloudResult.RESULT_CODE = result2.code;
                            cloudResult.REASON = result2.message;
                        }                    
                        self.cloudHis.resDownloadHistory(app.dbConn, key, cloudResult, function(sqlResult2) {
                            logger.info('resDownloadHistory', sqlResult2);
                        })    

                        if (bResult2) {
                            callback(true, cloudResult);
                            // callback(true, result2);
                        } else {
                            callback(false, cloudResult);
                            // callback(false, result2.message);
                        }
                    })
                } else {
                    logger.info('result1.message', result1.message)
                    callback(false, result1.message)
                }
            });
        } else {
            callback(false, result);
        }
    });
}

ClouldLib.prototype.delete = function (type, identity, req, callback) {
    var self = this;
    self.getApiToken(identity, function(apiToken) {
        if (apiToken) {
            var key = {};
            key.SYS_TYPE = '1';
            key.REQ_TYPE = type == 'folder' ? '3' : '2';
            key.USER_ID = req.session.userid;
            key.FILE_ID = type == 'folder' ? req.body.folder_id : req.body.file_id;
            key.INSERT_DATE = new Date().formatDate("yyyyMMddhhmmss");

            var input = {};
            input.FILE_TYPE = '';
            input.FILE_NAME = '';
            input.FILE_SIZE = '';
            input.ACCESS_TOKEN = apiToken;
            input.UCLOUD_SERVER_INFO = '';
            input.NONCE = '';
            input.ADJUSTABLE_YN = '';
            input.SHARE_IMORY_ID = '';
            input.ENC_TYPE = '';
            input.STATUS = '0';
            input.CUSTOMER_CODE = req.session.code_03;
            self.cloudHis.reqDownloadHistory(app.dbConn, key, input, function(sqlResult1) {
                logger.info('reqDownloadHistory', sqlResult1);
            });

            if (type == 'folder') {     // folder            
                deleteFolders(apiToken, req.body.folder_id, function(err, bResult, result) {
                    var cloudResult = {};
                    if (bResult) {
                        cloudResult.STATUS = '1';
                        cloudResult.RESULT_CODE = '0000'
                        cloudResult.REASON = '';
                    } else {
                        cloudResult.STATUS = '9';
                        cloudResult.RESULT_CODE = result.code;
                        cloudResult.REASON = result.message;
                    }                    
                    self.cloudHis.resDownloadHistory(app.dbConn, key, cloudResult, function(sqlResult2) {
                        logger.info('resDownloadHistory', sqlResult2);
                    })    

                    if (bResult) {
                        callback(true, result);
                    } else {
                        callback(false, result);
                    }
                })
            } else {                    // file
                deleteFiles(apiToken, req.body.file_id, function(err, bResult, result) {
                    var cloudResult = {};
                    if (bResult) {
                        cloudResult.STATUS = '1';
                        cloudResult.RESULT_CODE = '0000'
                        cloudResult.REASON = '';
                    } else {
                        cloudResult.STATUS = '9';
                        cloudResult.RESULT_CODE = result.code;
                        cloudResult.REASON = result.message;
                    }                    
                    self.cloudHis.resDownloadHistory(app.dbConn, key, cloudResult, function(sqlResult2) {
                        logger.info('resDownloadHistory', sqlResult2);
                    })    

                    if (bResult) {
                        callback(true, result);
                    } else {
                        callback(false, result);
                    }
                })
            }
        }
    });
}

ClouldLib.prototype.getFoldersList = function getFoldersList(identity, folderName, callback) {
    var self = this;
    self.getApiToken(identity, function(apiToken) {
        if (apiToken) {
            self.getFoldersListAll(apiToken, folderName, function(err, bResult, result) {
                if (bResult) {
                    callback(true, result);
                } else {
                    callback(false, result);
                }
            })
        }
    });
}

// 클라우드 스토리지 용량 확인
ClouldLib.prototype.getAvailableUsage = function getAvailableUsage(identity, callback) {
    var self = this;
    self.getApiToken(identity, function(apiToken, result) {
        if (apiToken) {
            getAvailableUsageRequest(apiToken, function(err, bResult1, result1) {
                if (bResult1) {  // 사용량 조회 성공
                    callback(true, result1);
                } else {        // 사용량 조회 실패
                    callback(false, null);
                }
            })
        } else {                // apiToken 발급 실패
            callback(false, null);
        }
    });
}

// 클라우드 스토리지 솔루션 상품 가입
ClouldLib.prototype.joinProduct = function joinProduct(identity, pid, callback) {
    var self = this;
    self.getFKey(identity, pid, function(bResult, result) {      // f_key 생성
        if (bResult) {      // f_key 생성 성공
            self.getApiToken(identity, function(apiToken, result1) {
                if (apiToken) {
                    // joinRequest(apiToken, serverConf.cloud.pid, function(err, bResult, result) {     // 솔루션 상품 가입 요청
                    joinRequest(apiToken, pid, function(err, bResult, result) {     // 솔루션 상품 가입 요청
                        if (bResult) {      // 상품 가입 성공
                            callback(true, result);
                        } else {            // 상품 가입 실패
                            callback(false, result);
                        }
                    });
                } else {
                    callback(false, result1);
                }
            });
        } else {            // f_key 생성 실패
            callback(false, result);
        }
    })
}

function joinRequest(token, pid, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    };

    requestCloud('POST', serverConf.cloudOpenAPI.baseUrl, '/v2/products/'+pid+'/join', headers, {}, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}

// 클라우드 스토리지 솔루션 상품 해지
ClouldLib.prototype.cancelProduct = function cancelProduct(identity, pid, callback) {
    var self = this;
    // self.getFKey(identity, function(bResult, result) {      // f_key 생성
    //     if (bResult) {      // f_key 생성 성공
            self.getApiToken(identity, function(apiToken, result1) {
                if (apiToken) {
                    // cancelRequest(apiToken, serverConf.cloud.pid, function(err, bResult, result) {   // 솔루션 상품 해지 요청
                    cancelRequest(apiToken, pid, function(err, bResult, result) {   // 솔루션 상품 해지 요청
                        if (bResult) {      // 상품 해지 성공
                            callback(true, result);
                        } else {            // 상품 해지 실패
                            callback(false, result);
                        }
                    });
                } else {
                    callback(false, result1);
                }
            });
    //     } else {            // f_key 생성 실패
    //         callback(false, result);
    //     }
    // })
}

function cancelRequest(token, pid, callback) {
    var headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    };

    requestCloud('POST', serverConf.cloudOpenAPI.baseUrl, '/v2/products/'+pid+'/cancel', headers, {}, function(err, status, resBody) {
        if (err) {
            callback(err, null, null);
        } else {
            if (status == 200) {
                callback(null, true, resBody);
            } else {
                callback(null, false, resBody);
            }
        }
    });
}