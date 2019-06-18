var net = require('net');
var fs = require('fs');
var crypto = require('crypto');
var logger = require('../libs/logger');
var util = require('util');
var dbConn = require('../db');
var menuConf = JSON.parse(fs.readFileSync("./config/menu.json"));
var app = require('../app');
var jwt = require('jsonwebtoken');
var tokenConfig = require('../config/token');
var g_bEnableSha256 = false;
var utilLib = require('../libs/utilLib');

EnableMysqlSha256();

var login = function(req, res) {
    logger.info('Path change : /login');

    var user_id = req.body.user_id;
    var user_pw = req.body.user_pw;
    var admin = req.body.admin;
    var query = util.format("select concat('&id=',A.admin_id,'&pw=',admin_pw,'&lv=',admin_lv," +
        "'&code_01=',code_01,'&code_02=',code_02,'&code_03=',code_03,'&ctn=',admin_mobile_num" +
        ",'&end') as results  " +
        ",CASE WHEN (SELECT count(*) " +
        " FROM TB_LOGIN_HISTORY B " +
        " WHERE A.ADMIN_ID=B.ADMIN_ID" +
        ") = 0  THEN '00000000000000' ELSE ( select insert_date  from TB_LOGIN_HISTORY B where A.ADMIN_ID=B.ADMIN_ID order by insert_date desc  limit 0,1  )  END results2, LOGIN_TRYCNT, A.UPDATE_DATE " +
        ",C.SV_OP_SV_V,C.SV_OP_SV_DR from TB_ADMIN A LEFT JOIN TB_CUSTOMER C ON A.CODE_03 = C.CUSTOMER_CODE where A.ADMIN_ID='%s'", user_id);
    var did = 'x';
    var dpw = 'x';
    var dlv = '99';
    var dc1 = 't';
    var dc2 = 't';
    var dc3 = 't';
    var ctn = 'c';
    var sdate = '';
    var tryLoginCnt;

    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send({ error: 'DB ' + error });
        } else if (Object.keys(results).length === 0) {
            logger.error('login fail, reason not exist id : ', user_id);
            res.status(400).send({ error: 'login fail, reason not exist id: ' + user_id });
        } else {
            if (results[0].LOGIN_TRYCNT === null) {
                tryLoginCnt = 0;
        } else {
                tryLoginCnt = results[0].LOGIN_TRYCNT;
            }

            if (tryLoginCnt === 5) {
                res.status(500).send({ error: 'login?ErrorCode=003&id' + user_id + '&TryCnt=' + results[0].LOGIN_TRYCNT });
            }

            if (results[0].SV_OP_SV_DR !== 'Y') {
                res.status(404).send({ error: '서비스 이용 권한이 없는 계정입니다.' });
            }

            // 기존 세션 여부 체크
            function checkID(callback) {
                var query = 'select STATUS from TB_ADMIN WHERE ADMIN_ID=\'' + user_id + '\'';

                dbConn.query(query, function(err, rows) {
                    logger.info('Query: ', query);
                    if (err) {
                        logger.error('DB Error: ', err);
                        callback(err, null);
                    } else {
                        callback(null, rows[0].STATUS);
                    }
                });
            }

            var status;
            checkID(function(err, status) {console.log(status, typeof status)
                if (status === '1') { // 1: login , 2: logout
                    //app._io.on('connection', function(socekt) {// status가 1이면 강제로그아웃.
                        app._io.sockets.emit('logout', user_id);// 기존 로그인되어 있는데 동일 아이디로 로그인 시 처음 로그인한 사람 강제로그아웃시킴.
                    //});
                }
            });
            //---------------------------------
            did = HrefVar(JSON.stringify(results[0]), '&id=');
            dpw = HrefVar(JSON.stringify(results[0]), '&pw=');
            dlv = HrefVar(JSON.stringify(results[0]), '&lv=');
            ctn = HrefVar(JSON.stringify(results[0]), '&ctn=');
            dc1 = HrefVar(JSON.stringify(results[0]), '&code_01=');
            dc2 = HrefVar(JSON.stringify(results[0]), '&code_02=');
            dc3 = HrefVar(JSON.stringify(results[0]), '&code_03=');
            sdate = results[0].results2;

            var hash_pw = g_bEnableSha256 ? crypto.createHash('sha256').update(user_pw).digest('hex') : user_pw;
            logger.info('hash_pw : ', hash_pw);

            if (user_id === did && hash_pw === dpw) {
                    req.session.userid = did;
                    // req.session.userpw = dpw;
                    // req.session.code_01 = dc1;
                    // req.session.code_02 = dc2;
                    // req.session.code_03 = dc3;
                    // req.session.userlv = dlv;
                    // req.session.mobile_num = ctn;
                    // req.session.s_date = sdate;
                    // req.session.drone = results[0].SV_OP_SV_DR;
                    // req.session.cookie.path = '/admin';
                    var jvars = JSON.stringify({ userid: did, userpw: dpw, code_01: dc1, code_02: dc2, code_03: dc3, userlv: dlv, mobile_num: ctn, s_date: sdate, drone: results[0].SV_OP_SV_DR, cookie_path: '/admin' });
                    logger.info('jvars---' + jvars);

                    var id = req.body.user_id;
                    var status = '1';
                    var ip = req.headers['x-forwarded-for'] ||
                        req.connection.remoteAddress ||
                        req.socket.remoteAddress ||
                        req.connection.socket.remoteAddress;

                    if (ip === '::1') {
                        ip = '127.0.0.1';
                    }

                    var pattern = /((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})/g;
                    var ipList = ip.match(pattern);
                    var agent = req.headers['user-agent'].indexOf('Chrome') > -1 ? 'Electron': req.headers['user-agent'];
                    req.session.ip = ipList[0];
                    var query3 = 'SELECT * from TB_LOGIN_HISTORY WHERE ADMIN_ID = \'' + user_id + '\' order by INSERT_DATE desc limit 1';

                    dbConn.query(query3, function(error, result) {
                        logger.info('Query: ', query3);
                        if (result.length !== 0 && result[0].STATUS !== '2') {
                            var query1 = 'UPDATE TB_LOGIN_HISTORY SET STATUS="2" , UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE INSERT_DATE = \'' + result[0].INSERT_DATE + '\' ';
                            dbConn.query(query1, function(error, result) {
                                logger.info('Query:', query1);
                            });
                        }
                    });

                    var query = 'INSERT INTO TB_LOGIN_HISTORY (AGENT, IP_ADDR, ADMIN_ID, STATUS, INSERT_DATE, UPDATE_DATE) VALUES (?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';

                    dbConn.query(query, [agent, ipList[0], id, status, '00000000000000'], function(error, result) {
                        logger.info('Query:', query);
                        if (error) {
                            logger.error('DB Error:', error);
                            res.status(500).send({ error: 'DB ' + error });
                        }

                        var query1 = "update TB_ADMIN SET STATUS='1', LOGIN_TRYCNT = 0 WHERE ADMIN_ID = \"" + user_id + "\"";

                        dbConn.query(query1, function(error, result) {
                            logger.info('Query: ', query);
                            if (error) {
                                logger.error('DB Error:', error);
                                res.status(500).send({ error: 'DB ' + error });
                            }
                        });
                        if (admin !== 1) {
                            if (req.session.userslv !== '3') {
                                var accessToken = jwt.sign({ id: user_id, date: Date.now(), ip: ip, userlv: dlv, code_03: dc3, code_02: dc2, code_01: dc1 }, tokenConfig, { expiresIn: 86400000 });// 86400000
                                res.status(200).send({ 
                                    msg: 'success',
                                    accessToken: accessToken,
                                    code01: dc1,
                                    code02: dc2,
                                    userlv: dlv,
                                    userid: user_id
                                });
                            }
                        }
                    });
            } else {
                logger.error('login fail, reason password not', user_pw);
                var updateQuery = util.format('UPDATE TB_ADMIN SET LOGIN_TRYCNT = IFNULL(LOGIN_TRYCNT, 0) + 1 WHERE ADMIN_ID = \'%s\'', user_id);

                dbConn.query(updateQuery, function(error, result) {
                    logger.info('Query: ', updateQuery);
                    if (error) {
                        logger.error('DB Error:', error);
                        res.status(500).send({ error: 'DB ' + error });
                    }
                });
                logger.info('tryLoginCnt : ', Number(tryLoginCnt) + 1);
                if (Number(tryLoginCnt) + 1 === 5) {
                    res.status(400).send({ error: 'login?ErrorCode=003&id=' + user_id });
                } else {
                    res.status(400).send({ error: 'login?ErrorCode=002' + tryLoginCnt });
                }
            }
        }
    });
};

var logout = function(req, res) {
            console.log('logout------------')
            var id = req.param('id');

            if (!id) {
                id = req.session.userid;
            }
            
            var ip = req.headers['x-forwarded-for'] ||
                req.connection.remoteAddress ||
                req.socket.remoteAddress ||
                req.connection.socket.remoteAddress;
        
            if (ip == '::1') {
                ip = '127.0.0.1';
            }
        
            var pattern = /((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})/g;
            var agent = req.headers['user-agent'];
            var query3 = 'SELECT * from TB_LOGIN_HISTORY WHERE ADMIN_ID = \'' + id + '\' order by INSERT_DATE desc limit 1';
            logger.info('Query: ', query3);
            dbConn.query(query3, function(error, result) {
                
                if (result.length !== 0) {
                    var query = 'UPDATE TB_LOGIN_HISTORY SET STATUS="2" , UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE INSERT_DATE = \'' + result[0].INSERT_DATE + '\' and ADMIN_ID = \'' + id + '\' ';
                    dbConn.query(query, function(error, result) {
                        logger.info('Query:', query);
                    });
                }
            });
            var query1 = "update TB_ADMIN SET STATUS='2' WHERE ADMIN_ID = \"" + id + "\"";
            dbConn.query(query1, function(error, result) {
                if (error) {
                    console.log('error logout update table_admin', error)
                }
             
                req.session.destroy(function(err) {
                    logger.error(err);
                    res.clearCookie('ltelcs_b2b_widget');
                   
                    if (agent.indexOf('Electron') === -1) {//웹이면
                        res.redirect('/');
                        
                    } else {
                        res.status(200).send('logout success');// 일렉트론에서 제어창 닫기 위한 응답.
                    }
                });

                // res.status(200).send({ msg: 'logout success' });// 일렉트론에서 제어창 닫기 위한 응답.
            });
            
          
            // app._io.sockets.emit('pcClose', id);// 제어창 외의 서브창들을 닫기 위한 용도로 사용함. 일렉트론에서는 메인창이 닫히면 다 닫히므로 당장 사용할 필요 없음.
};

var logout2 = function(req, res) {
    var id = req.session.userid;
    var status = '2';
    var ip = req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress;

    if (ip == '::1') {
        ip = '127.0.0.1';
    }
    var pattern = /((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})/g;
    var ipList = ip.match(pattern);
    var agent = req.headers['user-agent'];
    var query = 'SELECT * from TB_LOGIN_HISTORY WHERE ADMIN_ID = \'' + id + '\' order by INSERT_DATE desc limit 1';
    // app._io.sockets.emit('B173', 1)
    // res.status(200).send({ msg: 'logout2 success' });
    res.redirect('/');
};

var topstate = function(request, response) {
    // fs.readFile('html/top.html', 'utf8', function(error, data) {    
        var mVoIP, drone;
        var query = util.format('SELECT SV_OP_SV_V, SV_OP_SV_DR FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);
        logger.info('Query:', query);

        dbConn.query(query, function(error, results) {    
            if (error) {
                logger.error('DB Error:', error);
            } else {
                if (Object.keys(results).length > 0) {
                    mVoIP = results[0].SV_OP_SV_V;
                    drone = results[0].SV_OP_SV_DR;
                }

                // response.send(ejs.render(data, {
                response.send({
                    data: {
                        'session': request.session.userid,
                        'session_lv': request.session.userlv,
                        'isEnableLocale': request.session.locale,
                        'mVoIP': mVoIP,
                        'drone': drone,
                        'menu': menuConf
                    }
                });
            }            
        });
    // });
};

/**
 * reverse proxy에서 처리해야할 내용
 * @param {*} a 
 * @param {*} b 
 */
// var tken = function(req, res) {
//     var array;
//     var JWT = decodeJWT(req, res, function(result, jwtToken) {
//         if (result) {
//             console.log(token)
//             var authrizationHeader = req.params.tken || req.headers['authorization'];
//             var token = Array.isArray(authrizationHeader.split(' ')) ? authrizationHeader.split(' ')[1] : authrizationHeader;
//             var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        
//             if (Array.isArray(authrizationHeader.split(' ')) && authrizationHeader.split(' ').length > 2) {
//                 array = authrizationHeader.split(' ');
//             }
            
//             var url = req.url;
//             var redirect;
            
//             req.session.userid = jwtToken.id;
//             req.session.ip = jwtToken.ip;
//             req.session.userlv = jwtToken.userlv;
//             req.session.code_03 = jwtToken.code_03;
//             req.session.code_02 = jwtToken.code_02;
//             req.session.code_01 = jwtToken.code_01;
//             req.session.drone = 'Y';
//             //req.session.cookie.path = '/admin';
//             console.log('tken---------------------', req.session)
//             if (url.includes('drone')) {
//                 redirect = '/drone';
//             } else if (url.includes('serviceMultiPC')) {
//                 redirect = '/serviceMultiPC/ctn?cust=' + array[2]+ '&device=' + array[3] + '&insertdate=' + array[4];
//             } else if (url.includes('serviceMultiMobile')) {
//                 redirect = '/serviceMultiMobile/ctn?cust=' + array[2]+ '&device=' + array[3] + '&insertdate=' + array[4];
//             } else if (url.includes('serviceMultiSTB')) { 
//                 redirect = '/serviceMultiSTB/ctn?cust=' + array[2]+ '&device=' + array[3] + '&insertdate=' + array[4];
//             }
            
//             res.send({
//                 data: {
//                     ttkken: token,
//                     redirect: redirect
//                 }
//             });
//         }
//     });
// };

function HrefVar(a, b) {
    var vara = a.split(b);
    var varb = vara[1].split("&");
    return varb[0];
}

//비번 암호화
function EnableMysqlSha256() {
    var bEnable = true;
    var query = "SELECT version() VERSION";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error: ', error);
            bEnable = false;
        } else {
            var version = results[0].VERSION.split("-")[0];
            var versionArray = version.split(".");
            if (versionArray[0] < '5') {
                bEnable = false;
            } else if (versionArray[0] == 5 && versionArray[1] < '5') {
                bEnable = false;
            }
        }

        logger.info('mysql version : ' + version + ' enable : ' + bEnable);

        if (bEnable) {// g_bEnableSha256가 true이면 암호화함.
            g_bEnableSha256 = true;
        } else {
            g_bEnableSha256 = false;
        }
    });
}

var loginR = function(request, response) {
    logger.info('Path change : /login');

    fs.readFile('html/login.html', 'utf8', function(error, data) {

        //var urlquery = querystring.parse(url.parse(request.url).query);
        //logger.info('request.url : ', request.url);
        //if (typeof urlquery.ErrorCode != 'undefined') {
        //    logger.info('urlquery.ErrorCode : ', urlquery.ErrorCode);
        //}
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8',
                "X-UA-Compatible": "IE=Edge"
            });
            response.end(data);
        }
    });
}

var loginPost = function(request, response) {
    logger.info('Path change : /loginPost');

    var user_id = request.param('user_id');
    var user_pw = request.param('user_pw');
    var admin = request.param('admin');

    var query;
    query = util.format("select concat('&id=',A.admin_id,'&pw=',admin_pw,'&lv=',admin_lv," +
        "'&code_01=',code_01,'&code_02=',code_02,'&code_03=',code_03,'&ctn=',admin_mobile_num" +
        ",'&end') as results  " +
        ",CASE WHEN (SELECT count(*) " +
        " FROM TB_LOGIN_HISTORY B " +
        " WHERE A.ADMIN_ID=B.ADMIN_ID" +
        ") = 0  THEN '00000000000000' ELSE ( select insert_date  from TB_LOGIN_HISTORY B where A.ADMIN_ID=B.ADMIN_ID order by insert_date desc  limit 0,1  )  END results2, LOGIN_TRYCNT, A.UPDATE_DATE " +
        ",C.SV_OP_SV_V,C.SV_OP_SV_DR, SV_OP_SV_LO, ENCRYPT_ONOFF, LOCALE from TB_ADMIN A LEFT JOIN TB_CUSTOMER C ON A.CODE_03 = C.CUSTOMER_CODE where A.ADMIN_ID='%s'", user_id);

    var did = 'x';
    var dpw = 'x';
    var dlv = '99';
    var dc1 = 't';
    var dc2 = 't';
    var dc3 = 't';
    var ctn = 'c';
    var sdate = '';
    var tryLoginCnt;

    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
            response.redirect('/?ErrorCode=001');
        } else if (Object.keys(results).length == 0) {
            logger.error('login fail, reason not exist id : ', user_id);
            response.redirect('/?ErrorCode=002');
        } else {
            if (results[0].LOGIN_TRYCNT == null) tryLoginCnt = 0;
            else tryLoginCnt = results[0].LOGIN_TRYCNT;

            if (tryLoginCnt == 5) {
                //response.redirect('/login?ErrorCode=003&TryCnt=' + results[0].LOGIN_TRYCNT);
                response.redirect('/?ErrorCode=003&id=' + user_id);
                return;
            }

            // 기존 세션 여부 체크
            function checkID(callback) {
                var query = 'select STATUS from TB_ADMIN WHERE ADMIN_ID=\'' + user_id + '\'';
                console.log('Query: ', query);
                dbConn.query(query, function(err, rows) {console.log('login2', user_id, rows[0])
                    if (err) {
                        logger.error('DB Error: ', err);
                        callback(err, null);
                    } else {
                        callback(null, rows[0].STATUS);
                    }
                });
            }

            checkID(function(err, status) {console.log(';;;;;;;;;;;;;;;', status)
            logger.info('checking')
                if (status === '1') { // 1: login , 2: logout
                    logger.info('state = login')
                    // app._io.on('connection', function(socekt) {// status가 1이면 강제로그아웃.
                        app._io.sockets.emit('logout', user_id, 1);// 기존 로그인되어 있는데 동일 아이디로 로그인 시 처음 로그인한 사람 강제로그아웃시킴.
                    // });
                }
                else {
                    logger.info('state = logout')
                }
            });
            // checkID(function(err, content) {
            //     status = content;

            //     if (status == 1) { // 1: login , 2: logout
            //         app._io.sockets.emit('logout', user_id);
            //     }
            // });
            //---------------------------------
            did = HrefVar(JSON.stringify(results[0]), '&id=');
            dpw = HrefVar(JSON.stringify(results[0]), '&pw=');
            dlv = HrefVar(JSON.stringify(results[0]), '&lv=');
            ctn = HrefVar(JSON.stringify(results[0]), '&ctn=');
            dc1 = HrefVar(JSON.stringify(results[0]), '&code_01=');
            dc2 = HrefVar(JSON.stringify(results[0]), '&code_02=');
            dc3 = HrefVar(JSON.stringify(results[0]), '&code_03=');
            sdate = results[0].results2;

            var hash_pw = g_bEnableSha256?crypto.createHash('sha256').update(user_pw).digest('hex') : user_pw;
            logger.info('hash_pw : ', hash_pw);

            if (user_id == did && hash_pw == dpw) {
                request.session.locale = results[0].SV_OP_SV_LO;
                if (results[0].SV_OP_SV_LO == 'Y') {
                    if (results[0].LOCALE == "" || results[0].LOCALE == null) {
                        response.cookie('i18next', request.language);
                    } else {
                        response.cookie('i18next', results[0].LOCALE);
                    }
                }                
                if (results[0].UPDATE_DATE == '00000000000000') {
                    request.session.pass_change = did;
                    response.redirect('/initPwInfo?initType=super');
                    return;
                } else if (utilLib.term(results[0].UPDATE_DATE, utilLib.today()) >= 90) {
                    request.session.pass_change = did;
                    response.redirect('/initPwInfo?initType=pass');
                    return;
                } else {
                    request.session.userid = did;
                    request.session.userpw = dpw;
                    request.session.code_01 = dc1;
                    request.session.code_02 = dc2;
                    request.session.code_03 = dc3;
                    request.session.userlv = dlv;
                    request.session.mobile_num = ctn;
                    request.session.s_date = sdate;
                    request.session.drone = results[0].SV_OP_SV_DR;
                    request.session.encrypt = results[0].ENCRYPT_ONOFF;

                    console.log('session---------------------', request.session)

                    // request.session.cookie.path = '/';
                    var jvars = JSON.stringify(request.session);
                    logger.info('jvars---' + jvars);

                    var id = request.session.userid;
                    var status = '1';

                    var ip = request.headers['x-forwarded-for'] ||
                        request.connection.remoteAddress ||
                        request.socket.remoteAddress ||
                        request.connection.socket.remoteAddress;

                    if (ip == '::1') {
                        ip = '127.0.0.1';
                    }

                    var pattern = /((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})/g;
                    var ipList = ip.match(pattern);

                    var agent = request.headers['user-agent'];

                    request.session.ip = ipList[0];

                    var query3 = 'SELECT * from TB_LOGIN_HISTORY WHERE ADMIN_ID = \'' + user_id + '\' order by INSERT_DATE desc limit 1';

                    dbConn.query(query3, function(error, result) {
                        logger.info('Query: ', query3);

                        //console.log(result.length);

                        if (result.length != 0 && result[0].STATUS != '2') {
                            var query1 = 'UPDATE TB_LOGIN_HISTORY SET STATUS="2" , UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE INSERT_DATE = \'' + result[0].INSERT_DATE + '\' ';

                            dbConn.query(query1, function(error, result) {
                                logger.info('Query:', query1);

                            });
                        }

                    });

                    var query = 'INSERT INTO TB_LOGIN_HISTORY (AGENT, IP_ADDR, ADMIN_ID, STATUS, INSERT_DATE, UPDATE_DATE) VALUES (?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';
                    logger.info('Query:', query);
                    dbConn.query(query, [agent, ipList[0], id, status, '00000000000000'], function(error, result) {
                        if (error) {
                            logger.error('DB Error:', error);
                        } else {
                            //logger.info('DB success');
                        }

                        var query1 = util.format("UPDATE TB_ADMIN SET STATUS = '1', LOGIN_TRYCNT = 0, UPDATE_DATE = %s WHERE ADMIN_ID = '%s'", 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', user_id);
                        logger.info('Query: ', query);
                        dbConn.query(query1, function(error, result) {
                            if (error) {
                                logger.error('DB Error:', error);
                            } else {
                                //logger.info('DB success');
                            }
                        });

                        if (admin !== 1) {
                            if (request.session.userslv !== '3') {
                                // var accessToken = jwt.sign({ id: user_id, date: Date.now(), ip: ip, userlv: dlv, code_03: dc3, code_02: dc2, code_01: dc1 }, tokenConfig, { expiresIn: 86400000 });// 86400000
                                var htmlFile;
                                if (request.session.drone == 'Y') {
                                    response.redirect('/drone')
                                    // htmlFile = 'drone.html';
                                    // fs.readFile('html/' +  htmlFile, 'utf8', function(error, data) {
                                    //     response.send(ejs.render(data, {
    
                                    //     }));
                                    // });
                                } else {
                                    response.redirect('/service/mainPage');
                                    // htmlFile = 'service_status.html';
                                }
                            }
                        }
                    });
                }
            } else {
                logger.error('login fail, reason password not', user_pw);

                var updateQuery = util.format('UPDATE TB_ADMIN SET LOGIN_TRYCNT = IFNULL(LOGIN_TRYCNT, 0) + 1 WHERE ADMIN_ID = \'%s\'', user_id);
                dbConn.query(updateQuery, function(error, result) {
                    logger.info('Query: ', updateQuery);
                    if (error) {
                        logger.error('DB Error:', error);
                    } else {
                        //logger.info('DB success');
                    }
                });
                logger.info('tryLoginCnt : ', Number(tryLoginCnt) + 1);
                if (Number(tryLoginCnt) + 1 == 5)
                    response.redirect('/?ErrorCode=003&id=' + user_id);
                else
                    response.redirect('/?ErrorCode=002');
            }
        }
    });
};

module.exports = {
    login: login,
    logout: logout,
    logout2: logout2,
    topstate: topstate,
    loginR: loginR,
    loginPost: loginPost
};
