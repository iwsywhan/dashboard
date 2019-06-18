var logger = require('./logger');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
// var entries = require('object.entries');
var url = require('url');

var DEF_API_MANDANTORY_PARAM = {
    'checkAccount':     ['ID','SVC_ID','LC_CUST_CODE','ID_TYPE','CHECK_ID'],
    'createAccount':    ['ID','SVC_ID','LC_CUST_CODE','LC_ID','LC_PASS','LC_U_NAME','LC_U_CLASS','LC_U_PHONE','UTM_ID'],
    'assignCloudToken': ['ID','SVC_ID','LC_CUST_CODE','ASSIGN_TYPE'],
    'createDevice':     ['ID','SVC_ID','LC_CUST_CODE','D_ID_TYPE','D_ID','D_CTN','D_NAME'],
    'modifyDevice':     ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','D_NAME'],
    'deleteDevice':     ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN'],
    'startRecording':   ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','D_CAM_TYPE','D_RESOLUTION','D_VCODEC','D_FPS'],
    'stopRecording':    ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN'],
    'startSnapshot':    ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','SHOT_COUNT'],
    'upload':           ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','UPLOAD_TYPE'],
    'metaData':         ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN'],
    'searchHistory':    ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','START_DATE','END_DATE'],
    'ObjectNoti':       ['ID','SVC_ID','LC_CUST_CODE','D_ID','D_CTN','DESCRIPTION']
}

module.exports = Result;

util.inherits(Result, EventEmitter);
function Result() {
}

Result.prototype.checkParam = function (req, res) {
    try {
        // 메세지 포맷 오류 검출
        logger.info(JSON.stringify(req.body));
        JSON.parse(JSON.stringify(req.body));
    } catch(err) {
        logger.error(err.message);
        res.send({RESULT_CODE:"1001", RESULT_MESSAGE:"메세지 포맷 오류"});
        return false;
    }

    // url 존재 검증
    var apiName = req.url.substr(req.url.lastIndexOf('/') + 1);
    if (typeof DEF_API_MANDANTORY_PARAM[apiName] === "undefined") {
        res.status(404).send('404 not found');
        return false;
    }

    // 메시지 파라미터 오류 검출
    var findIndexSum = 0;
    var bValidValue = true;
    entries(req.body).forEach(function (key, index) {
        if (typeof key[1] !== 'number' && key[1] == '') {
            bValidValue = false;
        }
        var findIndex = 1 + DEF_API_MANDANTORY_PARAM[apiName].indexOf(key[0]);
        findIndexSum += findIndex;
    })

    if (!bValidValue) {                  // param value 오류
        res.send({RESULT_CODE:"1002", RESULT_MESSAGE:"메시지 파라메터 설정 오류"});
        return false;
    } else {
        var mandatoryCount = DEF_API_MANDANTORY_PARAM[apiName].length;
        // if (findIndexSum != sumOnetoNumber(mandatoryCount)) {     // 필수 옵션 없는 오류
        // 필수 옵션이 파라미터에 모두 존재하는지 체크하는 부분
        // 다 존재한다면 mandatory 배열 index+1 값이 모두 더해진 것과 같다.
        // 다시 말해, 1 ~ N 까지의 자연수의 합. sumOnetoNumber 함수로 만들었다가 계산식으로 변경
        // mandatoryCount * (mandatoryCount + 1) / 2 == sumOnetoNumber(mandatoryCount)
        if (findIndexSum != mandatoryCount * (mandatoryCount + 1) / 2) {
            res.send({RESULT_CODE:"1002", RESULT_MESSAGE:"메시지 파라메터 설정 오류"});
            return false;
        }
    }

    return true;
}

Result.prototype.checkCustomer = function (dbConn, req, res, callback) {
    var query;
    query = util.format("SELECT SV_OP_SV_DR FROM TB_CUSTOMER WHERE CUSTOMER_CODE = '%s'", req.body.LC_CUST_CODE);
    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
            res.send({RESULT_CODE:"1000", RESULT_MESSAGE:error});
            callback(false);
        } else {
            logger.info('DB Success: ', req.body.LC_CUST_CODE);
            if (results.length == 0) {
                res.send({RESULT_CODE:"1011", RESULT_MESSAGE:"서비스 미등록 고객사"});
                callback(false);
            } else {
                if (results[0].SV_OP_SV_DR === 'Y') {
                    callback(true);
                } else {
                    res.send({RESULT_CODE:"1015", RESULT_MESSAGE:"서비스 가입 상태 해지"});
                    callback(false);
                }
            }
        }
    });
}

function sumOnetoNumber(number) {
    var sum = 0;
    for (var i = 1; i <= number; i++) {
        sum += i;
    }
    return sum;
}
