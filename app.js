/**
 * Created by iwsywhan on 2015-04-15.
 */
var util = require('util');
var fs = require('fs');
var ejs = require('ejs');
var http = require('http');
var https = require('https');
var express = require('express');
var path = require('path');
var mysql = require('mysql');
var struct = require('./coupledMessage.js');
var Map = require("collections/map");
var url = require('url');
var querystring = require('querystring');
var net = require('net');
var utilLib = require('./public/javascripts/utilLib.js');
var pwValidator = require('./libs/passwordValidate');

// var mime = require('mime');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var builder = require('xmlbuilder');
var parseString = require('xml2js');
var nodeExcel = require('excel-export');
var formidable = require('formidable');
var gcm = require('node-gcm');
var pushServiceAPI = require('./pushServiceAPI.js');
var lcsServiceAPI = require('./lcsServiceAPI.js');
var pcViewerAPI = require('./pcViewerAPI.js');
var rtmpAPI = require('./rtmpAPI.js');
var channelAPI = require('./channelServiceAPI.js');
var winston = require('winston');
var moment = require('moment');
var crypto = require('crypto');
var morgan = require('morgan');
var cors = require('cors');
var aes256cbc = require('./aes256cbc.js');
var logger = require('./libs/logger');
var DroneResult = require('./libs/DroneResult');
var CloudLib = require('./libs/CloudLib');
var dbConn = require('./db');
var helmet = require('helmet');
var indexRouter = require('./routes/index');
var loginRouter = require('./routes/login');
var serviceRouter = require('./routes/service');
var passwordRouter = require('./routes/password');
var manageRouter = require('./routes/manage');
var isRouter = require('./routes/is');
var workRouter = require('./routes/work');
var voiceRouter = require('./routes/voice');
var getRouter = require('./routes/get');
var viewerRouter = require('./routes/viewer');
var viewRouter = require('./routes/view');
var stbRouter = require('./routes/stb');
var cameraRouter = require('./routes/camera')
var chNoticeRouter = require('./routes/chNotice');

var socketClient = require('./socketClient');
var decodeJWT = require('./libs/decodeJWT');

var i18next = require('i18next');
var FilesystemBackend = require('i18next-node-fs-backend');
var i18nextMiddleware = require('i18next-express-middleware');

var java = require('java');
java.classpath.push("./libs/security/security.jar");
var security = java.import("com.iwill.Swan");
security.initSync("./libs/security/VulnerCheckList.xml");


var droneResult = new DroneResult();
var cloudLib = new CloudLib();

var MOBILE = 1;
var STB = 2;
var PC = 3;
var g_bEnableSha256 = true;

var serverConf = JSON.parse(fs.readFileSync('./config/server.json'));
var menuConf = JSON.parse(fs.readFileSync('./config/menu.json'));

var httpsWebServerPort = serverConf.SecureWebPort;
var httpWebServerPort = serverConf.WebPort;

var DB_HOST = '127.0.0.1';
var TOSS_HOST = '172.22.15.78';
var TOSS_PORT = 10200;

var regQueue = [];

megaLoop();

function megaLoop() {
    dbConn.query('SELECT C_KEY, C_VALUE, C_NAME FROM TB_COMMON', function(err, rows) {
        if (err) {
            logger.error('DB Error: ', err);
            handleDisconnect();
        } else {
            logger.info('dummy query success');
        }
    });

    setTimeout(megaLoop, 10 * 60 * 1000);
}

var g_lcsAccUrl, g_lcsAddrIP, g_lcsAccVodPort, g_lcsSVodPort;
var query = "SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = 'DOMAIN' or C_NAME = 'IPADDR' or C_NAME='VOD_PORT' or C_NAME='SVOD_PORT'";
dbConn.query(query, function(error, results) {
    logger.info('Query:', query);
    if (error) {
        logger.error('DB Error: ', error);
    } else {
        
        g_lcsAddrIP = results[0].C_VALUE;
        g_lcsAccUrl = results[1].C_VALUE;
        g_lcsAccVodPort = results[2].C_VALUE;
        g_lcsSVodPort = results[3].C_VALUE;
        //toss_map.set("lcsAccUrl", results[0]);
    }
});

var app = express();
// var router = express.Router();
//---------------------------------------------------------------------------------------------
// Web Server on
//---------------------------------------------------------------------------------------------
var server;
if (serverConf.SecureOnOff) {     // https
    var options = {
        key: fs.readFileSync('./ssl/key.pem'),
        cert: fs.readFileSync('./ssl/cert.pem'),
        requestCert: false,
        passphrase: 'iiotcam2018',
        ca: [ fs.readFileSync('./ssl/SymantecDigiCert-Newchain-sha2.pem')],        
        secureOptions: require('constants').SSL_OP_NO_TLSv1 | require('constants').SSL_OP_NO_TLSv1_1 | require('constants').SSL_OP_NO_SSLv2,
        ciphers: [
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA256",
            "DHE-RSA-AES256-SHA384",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "HIGH",
            "!aNULL",
            "!eNULL",
            "!EXPORT",
            "!DES",
            "!RC4",
            "!MD5",
            "!PSK",
            "!SRP",
            "!CAMELLIA",
            "!RC2",
            "!RC5",
            "!RC6",
            "!MD4",
            "!MD5",
            "!SHA1",
            "!2DES",
            "!3DES",
        ].join(':'),
        honorCipherOrder: true
    };
    server = https.createServer(options, app).listen(httpsWebServerPort, function() {
        logger.info("Https server listening on port " + httpsWebServerPort);
    });
} else {// http
    server = http.createServer(app).listen(httpWebServerPort, function(){
        logger.info("Http server listening on port " + httpWebServerPort);
    });
}

var _io = require('./sockets').initialize(server);

logger.stream = {
    write: function(message, encoding) {
        logger.info(message);
    }
};

app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined', {
    'stream': logger.stream
}));
app.use(helmet({
    noSniff: false
}));

if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

app.use(cookieParser());
app.use(bodyParser.json());
app.use(session({
    secret: 'secret key',
    key: 'ltelcs_b2b_widget',
    cookie: {
        secure: serverConf.SecureOnOff,
        httpOnly: true //,
        // path: '/admin'
        // maxAge: 1000 * 60 * 60 * 24 * 31
    }
}));
app.use(bodyParser.urlencoded({
    extended: false
}));

// http -> https redirect
if (serverConf.HpptRedirect) {
    var redirect_server = http.createServer(app).listen(httpWebServerPort, function(){
        logger.info("Http server listening on port " + httpWebServerPort);
    });
    
    app.use(function https(req, res, next) {
        if (!req.secure) {
            var splitChar = ":";
            return res.redirect('https://' + req.headers.host.split(splitChar)[0] + splitChar + serverConf.SecureWebPort + req.url);
        }
        next();
    });
}

i18next
  .use(FilesystemBackend)
  .use(i18nextMiddleware.LanguageDetector)
  .init({
    backend: {
        loadPath: __dirname + '/public/locales/{{lng}}/{{ns}}.json',
        addPath: __dirname + '/public/locales/{{lng}}/{{ns}}.missing.json'
    },
    fallbackLng: 'ko',
    preload: ['ko', 'en', 'zh', 'vi'],
    saveMissing: true,
    detection: {
        order: ['cookie', 'navigator'],
        lookupCookie: 'i18next',
    }
});
app.use(i18nextMiddleware.handle(i18next));

app.all('*', function(req, res, next) {

    var url_parts;
    if (req.method == 'POST') {
        url_parts = querystring.stringify(req.body);
        var url_parts_nm = url.parse(req.url, true).pathname;
    } else if (req.method == 'GET') {
        url_parts = url.parse(req.url, true);
        var url_parts_nm = url_parts.pathname;
        url_parts = url_parts.search;
        var sub = url_parts.substr(1, 1);
    }
    logger.info("url_parts : " + url_parts);
    logger.info("url_parts_nm : " + url_parts_nm);
    if (typeof url_parts == "undefined" || url_parts.length == 0 || sub == "_" || url_parts_nm == "/alert/") {
        next();
    } else {
        var params = url_parts.substring(url_parts.indexOf('?') + 1, url_parts.length);
        params = params.split("&");
        var params = url_parts.split("&");
        logger.info("params : " + params);
 
        var key, value;
        var weakNum = 0;
        var returnVal;

        for (var i = 0; i < params.length; i++) {
            key = params[i].split("=")[0];
            value = params[i].split("=")[1];
            logger.info("params-key : ", key, "value : ",value)

            if (key.indexOf('fileName') > -1 || key.indexOf('img') > -1) {
                returnVal = security.checkSync(value, 0, "common", "filedown");
            } else {
                returnVal = security.checkSync(value, 0, "forEditor", "xss|sqlinjection");
            }
 
            if (returnVal == "true") {
                logger.info('check url : ' + url_parts_nm + ' check key : ' + key);
                logger.info('weakWord value : ' + decodeURIComponent(value));
                var weakWord = decodeURIComponent(value);
                weakNum = 1;
            }
        }
        if (weakNum == 0) {
            next();
        } else {
            var msg = "금칙어 ["+weakWord+"]가 검출되어 로그아웃 되었습니다."
            logger.info('Security vulnerability ID : ', req.session.userid, msg)
            _io.sockets.emit('logout',req.session.userid,2,msg);
            // res.redirect("/logout");
        }
    }
 });

// dron API router
app.use('/utmapi', function (req, res, next) {
    logger.info('/utmapi', req.url, req.body);
    droneResult.authorization(dbConn, req.body.ID, req.body.LC_CUST_CODE, res, function(bResult) {
        if (bResult) {
            next();
        } else {
            return;
        }
    })
});

app.use(/\/drone|\/cloud\/camera/, function (req, res, next) {
    logger.info('drone|cloud', req.url, req.session.userid, req.url.indexOf('/product/join'), req.url.indexOf('/product/cancel'))
    if (req.url.indexOf('/product/join') >= 0 || req.url.indexOf('/product/cancel') >= 0) {
        next();
    } else {
        if (typeof req.session.userid == 'undefined') {
            logger.info('redirect /');
            res.redirect('/');
            return;
        } else {
            next();
        }
    }
});


app.use('/', indexRouter);
app.use('/login', loginRouter);
app.use('/service', serviceRouter);
app.use('/pw', passwordRouter);
app.use('/manage', manageRouter);
app.use('/is', isRouter);
app.use('/work', workRouter);
app.use('/voice', voiceRouter);
app.use('/get', getRouter);
app.use('/viewer', viewerRouter);
app.use('/view', viewRouter);
app.use('/stb', stbRouter);
app.use('/chNotice', chNoticeRouter)
app.use('/drone', require('./routes/drone'));
app.use('/cameras', cameraRouter);
app.use('/account', require('./routes/account'));
app.use('/cloud', require('./routes/cloud'));
app.use('/livecam', require('./routes/livecam'));
app.use('/utmapi', cameraRouter);



// app.get('/getCountServcing', CheckAuth, function(request, response) {
//     logger.info('Path change : /getCountServcing');

//     var query = 'SELECT count(P_CUST_CTN) as COUNT FROM TB_STB_SERVICE WHERE STATUS = \'2\'';

//     dbConn.query(query, function(error, results) {

//         logger.info('Query:', query);

//         if (error) {
//             logger.error('DB Error:', error);
//         } else {
//             response.send(results[0]);
//         }
//     });
// });

app.get('/serviceStatusView/:id', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceStatusView/', request.param('id'));

    fs.readFile('html/service_status_view.html', 'utf-8', function(error, data) {

        var mVoIP;
        var query = util.format('SELECT SV_OP_SV_V FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
                mVoIP = '';
            } else {
                mVoIP = results[0].SV_OP_SV_V;
            }

            response.send(ejs.render(data, {
                data: {
                    'userid': request.session.userid,
                    'userlevel': request.session.userlv,
                    'code01': request.session.code_01,
                    'code02': request.session.code_02,
                    'code03': request.session.code_03,
                    'mVoIP': mVoIP
                }
            }));
        });
    });
});

// app.get('/refreshService/:id', function(request, response) {

//     logger.info('Path change : refreshService/', request.url);

//     var urlquery = querystring.parse(url.parse(request.url).query);
//     query = util.format('select * from TB_TERMINAL_IMAGE_TRANS where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\' ', request.param('id'), urlquery.device, urlquery.insertdate);
//     dbConn.query(query, function(error, results) {

//         logger.info('Query:', query);
//         if (error) {
//             logger.error('DB Error: ', error);
//         } else {
//             response.send(results[0]);
//         }
//     });

// });

app.get('/serviceMultiVoice/:ctn', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceMultiVoice');

    fs.readFile('html/service_multi_voice.html', 'utf8', function(error, data) {
        var mVoIP;
        var query = util.format('SELECT SV_OP_SV_V FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);
        logger.info('Query:', query);

        dbConn.query(query, function(error, results) {    
            if (error) {
                logger.error('DB Error:', error);
                mVoIP = '';
            } else {
                mVoIP = results[0].SV_OP_SV_V;
            }

            response.send(ejs.render(data, {
                data: {
                    'mVoIP': mVoIP
                }
            }));
        });
    });
});

app.get('/serviceDeleteMultiVoice', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceDeleteMultiVoice');

    fs.readFile('html/service_delete_multi_voice.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/serviceMultiSTB/:ctn', function(request, response) {//checkauth
    logger.info('Path change : /serviceMultiSTB');

    fs.readFile('html/service_multi_stb.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/serviceDeleteMultiSTB', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceDeleteMultiSTB');

    fs.readFile('html/service_delete_multi_stb.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/serviceMultiPC/:ctn', function(request, response) {// checkauth

    logger.info('Path change : /serviceMultiMobile');

    fs.readFile('html/service_multi_pc.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/serviceDeleteMultiPC', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceDeleteMultiPC');

    fs.readFile('html/service_delete_multi_pc.html', 'utf8', function(error, data) {
        response.send(data);
    });
});


app.get('/serviceMultiMobile/:ctn', function(request, response) {// checkauth

    logger.info('Path change : /serviceMultiMobile');

    fs.readFile('html/service_multi_mobile.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/serviceDeleteMultiMobile', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceDeleteMultiMobile');

    fs.readFile('html/service_delete_multi_mobile.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/Dept', function(request, response) {
    logger.info('Path change : /Dept');

    var query = "select GUBUN, CODE, CODE_NM from TB_DEPT_DEPTH WHERE GUBUN = '3'";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/defaultSTBList/:id', CheckAuth, function(request, response) {
    logger.info('Path change : /defaultSTBList/' + request.param('id'));

    var query;
    query = 'SELECT a.STB_MAC_ADDR,a.STB_NM ,a.STB_DEPT_NM,a.SVC_STB_IP,a.STB_DEPT_CODE_01,a.STB_DEPT_CODE_02,a.STB_DEPT_CODE_03,a.STB_LOCATION,a.STB_ADMIN_INFO,a.CTN_SEQ,b.STATUS'
    query += ' FROM TB_STB_INFO a left join ( SELECT STATUS ,STB_MAC_ADDR FROM TB_STB_SERVICE WHERE STATUS < \'3\' ) b'
    query += ' ON a.STB_MAC_ADDR = b.STB_MAC_ADDR';
    query += ' WHERE STB_DEPT_CODE_01 =\'' + request.session.code_01 + '\' and STB_DEPT_CODE_02 = \'' + request.session.code_02 + '\' and STB_DEPT_CODE_03 =\'' + request.session.code_03 + '\' and b.STATUS is null';
    query += ' GROUP BY a.STB_MAC_ADDR ORDER BY a.STB_DEPT_NM, a.STB_NM Limit 1';

    var bOneMore = false;
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (Object.keys(results).length > 0) {

                response.send(results);
            } else {

                query = 'SELECT a.STB_MAC_ADDR,a.STB_NM,a.STB_DEPT_NM,a.SVC_STB_IP,a.STB_DEPT_CODE_01,a.STB_DEPT_CODE_02,a.STB_DEPT_CODE_03';
                query += ',a.STB_LOCATION,a.STB_ADMIN_INFO,a.CTN_SEQ,ifnull(b.STATUS, 3) as STATUS';
                query += ' FROM TB_STB_INFO a left join ( SELECT STATUS,  STB_MAC_ADDR FROM TB_STB_SERVICE )b';
                query += ' ON a.STB_MAC_ADDR = b.STB_MAC_ADDR';
                query += ' WHERE STB_DEPT_CODE_01 = \'' + request.session.code_01 + '\' and STB_DEPT_CODE_02 = \'' + request.session.code_02 + '\' and STB_DEPT_CODE_03 = \'' + request.session.code_03 + '\'';
                query += ' GROUP BY a.STB_MAC_ADDR ORDER BY STB_DEPT_NM, STATUS';

                dbConn.query(query, function(error, results) {
                    logger.info('Query:', query);

                    if (error) {
                        logger.error('DB Error: ', error);
                    } else {
                        
                        response.send(results);
                    }
                });
            }
        }
    });
})

app.get('/autoLinkDefaultSTB', CheckAuth, function(request, response) {
    logger.info('Path change : /autoLinkDefaultSTB');

    var query;
    query = 'SELECT a.STB_MAC_ADDR,a.STB_NM ,a.STB_DEPT_NM,a.SVC_STB_IP,a.STB_DEPT_CODE_01,a.STB_DEPT_CODE_02,a.STB_DEPT_CODE_03,a.STB_LOCATION,a.STB_ADMIN_INFO,a.CTN_SEQ,b.STATUS'
    query += ' FROM TB_STB_INFO a left join ( SELECT STATUS ,STB_MAC_ADDR FROM TB_STB_SERVICE WHERE STATUS < \'3\' ) b'
    query += ' ON a.STB_MAC_ADDR = b.STB_MAC_ADDR';
    query += ' WHERE STB_DEPT_CODE_01 =\'' + request.session.code_01 + '\' and STB_DEPT_CODE_02 = \'' + request.session.code_02 + '\' and STB_DEPT_CODE_03 =\'' + request.session.code_03 + '\' and b.STATUS is null';
    query += ' GROUP BY a.STB_MAC_ADDR ORDER BY a.STB_DEPT_NM, a.STB_NM Limit 1';

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });
})

app.post('/ismVoIP', CheckAuth, function(request, response) {
	logger.info('Path change : /ismVoIP');

	var mVoIP;
	var query = util.format('SELECT SV_OP_SV_V FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);

	dbConn.query(query, function (error, results) {
		logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
            mVoIP = '';
        } else {
			console.log('mVoIP :', results[0].SV_OP_SV_V);
			mVoIP = results[0].SV_OP_SV_V;
		}
        response.send(mVoIP);
    });
});

app.get('/getSvcType', CheckAuth, function(request, response) {
    logger.info('Path change : /getSvcType');

    var query = util.format('SELECT SVC_TYPE FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = \'%s\' and CTN_DEVICE = \'%s\' and INSERT_DATE = \'%s\'', request.param('CUSTCNT'), request.param('CTNDEIVCE'), request.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.get('/MinDept1', function(request, response) {
    logger.info('Path change : /MinDept1');
    var code_03 = request.session.code_03;
    var query = "select min(CODE) as CODE from TB_DEPT_DEPTH WHERE GUBUN = '1' and CODE_03 = '" + code_03 + "'";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });
});

app.get('/optionDept1', function(request, response) {
    logger.info('Path change : /optionDept1');
    //var query = "SELECT GUBUN,CODE,CODE_NM FROM TB_DEPT_DEPTH WHERE GUBUN = '1'";
    var query = util.format("SELECT GUBUN,CODE,CODE_NM FROM TB_DEPT_DEPTH WHERE GUBUN = '1' AND CODE_03 = '%s' order by CODE", request.session.code_03);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }
    });
});

app.get('/optionDept2', function(request, response) {
    logger.info('Path change : /optionDept2');
    var dept_code_01 = request.param('dept_code_01');
    var code1 = dept_code_01.substr(0, 1);
    var query = util.format("SELECT GUBUN,CODE,CODE_NM FROM TB_DEPT_DEPTH WHERE GUBUN = '2' and substring(CODE, 1, 1) = '%s' and CODE_03 = '%s' order by CODE", code1, request.session.code_03);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(200, results);
        }
    });
});

app.get('/optionDept3', function(request, response) {
    logger.info('Path change : /optionDept3');

    var dept_code_01 = request.param('dept_code_01');
    var dept_code_02 = request.param('dept_code_02');

});

app.get('/treeAllOrgan', CheckAuth, function(request, response) {

    logger.info('Path change : /treeAllOrgan');

    var type = request.param('TYPE');
    var userlevel = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code03 = request.session.code_03;

    if (typeof code1 == "undefined") {
        response.send("session log out");
        return;
    }
    var code1_g = code1.substring(0, 1);

    var query;
    if (type == 1) {
        query = 'SELECT tot.CODE_01, tot.CODE_02, tot.CODE_NM1, tot.CODE_NM2 FROM (';
        query += 'SELECT DEPT_CODE_01 as CODE_01, DEPT_CODE_02 as CODE_02,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as CODE_NM1,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as CODE_NM2';
        query += ' FROM TB_ORGANOGRAM a';
        query += ' GROUP BY DEPT_CODE_01, DEPT_CODE_02';
        query += ') tot ';
        query += 'WHERE tot.CODE_NM2 is not null ';
    } else if (type == 3) {
        query = 'SELECT tot.CODE_01, tot.CODE_02, tot.CODE_NM1, tot.CODE_NM2 FROM (';
        query += 'SELECT CODE_01 as CODE_01, CODE_02 as CODE_02,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as CODE_NM1,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as CODE_NM2';
        query += ' FROM TB_ADMIN a';
        query += ' GROUP BY CODE_01, CODE_02';
        query += ') tot WHERE tot.CODE_NM2 is not null ';
    } else if (type == 4) { //mvoip
        query = 'SELECT tot.CODE_01, tot.CODE_02, tot.CODE_NM1, tot.CODE_NM2 FROM (';
        query += 'SELECT CODE_01 as CODE_01, CODE_02 as CODE_02,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as CODE_NM1,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as CODE_NM2';
        query += ' FROM TB_ADMIN a';
        query += ' where CODE_03 = \'' + code03 + '\'';
        query += ' GROUP BY CODE_01, CODE_02';
        query += ') tot WHERE tot.CODE_NM2 is not null ';
    } else {
        query = 'SELECT tot.CODE_01, tot.CODE_02, tot.CODE_NM1, tot.CODE_NM2 FROM (';
        query += 'SELECT STB_DEPT_CODE_01 as CODE_01, STB_DEPT_CODE_02 as CODE_02,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.STB_DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as CODE_NM1,';
        query += ' (select b.CODE_NM from TB_DEPT_DEPTH b where a.STB_DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as CODE_NM2';
        query += ' FROM TB_STB_INFO a';
        query += ' GROUP BY STB_DEPT_CODE_01, STB_DEPT_CODE_02';
        query += ') tot WHERE tot.CODE_NM2 is not null ';
    }

    if (userlevel == 1) { // 슈퍼관리자
    } else {
        if (code1 == code2) {
            query += 'and tot.CODE_01 = tot.CODE_02 or substring(tot.CODE_01,1,1) = \'' + code1_g + '\' ';
        } else {
            query += 'and substring(tot.CODE_01,1,1) = \'' + code1_g + '\'';
        }
    }

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }
    });
});

app.get('/searchDept', function(request, response) {
    logger.info('Path change : /searchDept');
    var code_03 = request.session.code_03;
    var query, selectQuery;
    selectQuery = 'SELECT a.*, b.CTN_DEVICE FROM TB_ORGANOGRAM a ' +
             'LEFT JOIN ( ' +
             '    SELECT CTN_DEVICE ,CUST_CTN ,UPDATE_DATE ' +
             '    FROM TB_CUST_INFO ' +
             '    GROUP BY CUST_CTN ' +
             '    ORDER BY UPDATE_DATE DESC ' +
             ') b ' +
             'ON a.CTN = b.CUST_CTN ';

    if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        //query = 'select * from TB_ORGANOGRAM';
        query = selectQuery;
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        //query = 'select * from TB_ORGANOGRAM where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\"';
        query = selectQuery + 'where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        //query = 'select * from TB_ORGANOGRAM where DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
        query = query = selectQuery + 'where DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') != 'all') {
        //query = 'select * from TB_ORGANOGRAM where DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
        query = query = selectQuery + 'where DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        //query = 'select * from TB_ORGANOGRAM where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
        query = query = selectQuery + 'where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
    } else {
        //query = 'select * from TB_ORGANOGRAM where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\" and DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
        query = query = selectQuery + 'where DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\" and DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    }
    query += ' and DEPT_CODE_03 = \'' + code_03 + '\'';
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/searchPC', function(request, response) {
    logger.info('Path change : /searchPC');
    var code_03 = request.session.code_03;
    var query;
    if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        query = 'select * from TB_ADMIN';
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        query = 'select * from TB_ADMIN where CODE_01 like \"%' + request.param('searchWord') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        query = 'select * from TB_ADMIN where CODE_02 like \"%' + request.param('searchWord2') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') != 'all') {
        query = 'select * from TB_ADMIN where CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        query = 'select *, ADMIN_ID CTN, ADMIN_NM NM, ADMIN_DEPT_NM DEPT_NM, ADMIN_ARANK ARANK from TB_ADMIN ';
        query += 'where CODE_01 like \"%' + request.param('searchWord') + '%\" and CODE_02 like \"%' + request.param('searchWord2') + '%\"';
        /*
        query = 'select a.*, b.CTN as CTN, a.ADMIN_ARANK as ARANK from TB_ADMIN a '
        query+= 'left join( select CTN, ARANK from TB_ORGANOGRAM )b on a.ADMIN_MOBILE_NUM = b.CTN '
        query+= 'where CODE_01 like \"%' + request.param('searchWord') + '%\" and CODE_02 like \"%' + request.param('searchWord2') + '%\"';
        */
    } else {
        query = 'select a.*, b.CTN as CTN, a.ADMIN_ARANK as ARANK from TB_ADMIN a '
        query += 'left join( select CTN, ARANK from TB_ORGANOGRAM )b on a.ADMIN_MOBILE_NUM = b.CTN '
        query += 'where CODE_01 like \"%' + request.param('searchWord') + '%\" and CODE_02 like \"%' + request.param('searchWord2') + '%\" and CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    }
    query += ' and CODE_03 = \'' + code_03 + '\'';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});



app.get('/optionSTB', function(request, response) {
    logger.info('Path change : /optionSTB');

    var query = 'select STB_DEPT_CODE_01 from TB_STB_INFO';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/searchSTB', function(request, response) {
    logger.info('Path change : /searchSTB');
    var code_03 = request.session.code_03;

    // var query1 = 'select a.STB_MAC_ADDR, STB_NM, STB_DEPT_NM, SVC_STB_IP, STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, STB_LOCATION, STB_ADMIN_INFO, CTN_SEQ, IFNULL(c.STATUS, \'3\') as STATUS From' +
    //     ' ((select STB_MAC_ADDR, STB_NM, STB_DEPT_NM, SVC_STB_IP, STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, STB_LOCATION, STB_ADMIN_INFO, CTN_SEQ,' +
    //     ' (select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_03 = b.code_03 AND STB_DEPT_CODE_01 = b.CODE and b.GUBUN = "1") as STB_DEPT_NM1,' +
    //     ' (select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_03 = b.code_03 AND STB_DEPT_CODE_02 = b.CODE and b.GUBUN = "2") as STB_DEPT_NM2,' +
    //     ' (select b.CODE_NM FROM TB_DEPT_DEPTH b where STB_DEPT_CODE_03 = b.code_03 AND STB_DEPT_CODE_03 = b.CODE and b.GUBUN = "3") as STB_DEPT_NM3' +
    //     ' from TB_STB_INFO) a left join (Select max(STATUS) as STATUS, STB_MAC_ADDR From TB_STB_SERVICE where STATUS < \'3\' group by STATUS) c on a.STB_MAC_ADDR = c.STB_MAC_ADDR)';

    var query1 = util.format("" + 
    "SELECT h.STB_MAC_ADDR, STB_NM, STB_DEPT_NM, SVC_STB_IP, STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, STB_LOCATION, STB_ADMIN_INFO,CTN_SEQ, " +
    "IFNULL(h.STATUS, '3') as STATUS, STB_DEPT_NM1, STB_DEPT_NM2,STB_DEPT_NM3 " +
    "FROM ( " +
        " SELECT a.STB_MAC_ADDR, STB_NM, STB_DEPT_NM, SVC_STB_IP, STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, STB_LOCATION, STB_ADMIN_INFO, " +
        "CTN_SEQ, c.STATUS, d.CODE_NM STB_DEPT_NM1, e.CODE_NM STB_DEPT_NM2, f.CODE_NM STB_DEPT_NM3 " + 
        "FROM TB_STB_INFO a " +
        "LEFT JOIN ( " +
            "SELECT max(STATUS) as STATUS, STB_MAC_ADDR " +
            "FROM TB_STB_SERVICE b " +
            "WHERE  STATUS < '3' " +
            "group by b.STATUS " +
            ") c " +
        "on a.STB_MAC_ADDR = c.STB_MAC_ADDR " +
        "LEFT JOIN TB_DEPT_DEPTH d " +
        "on a.STB_DEPT_CODE_01 = d.CODE AND d.GUBUN = '1' AND a.STB_DEPT_CODE_03 = d.CODE_03 " +
        "LEFT JOIN TB_DEPT_DEPTH e " +
        "on a.STB_DEPT_CODE_02 = e.CODE AND e.GUBUN = '2' AND a.STB_DEPT_CODE_03 = e.CODE_03 " +
        "LEFT JOIN TB_DEPT_DEPTH f " +
        "on a.STB_DEPT_CODE_03 = f.CODE AND f.GUBUN = '3' AND a.STB_DEPT_CODE_03 = f.CODE_03 " +
    ") h ");
    if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        var query = query1;
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') == 'all') {
        var query = query1 +
            'where STB_DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        var query = query1 +
            'where STB_DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
    } else if (request.param('searchWord') == 'all' && request.param('searchWord2') == 'all' && request.param('searchWord3') != 'all') {
        var query = query1 +
            'where STB_DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    } else if (request.param('searchWord') != 'all' && request.param('searchWord2') != 'all' && request.param('searchWord3') == 'all') {
        var query = query1 +
            'where STB_DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and STB_DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\"';
    } else {
        var query = query1 +
            'where STB_DEPT_CODE_01 like \"%' + request.param('searchWord') + '%\" and STB_DEPT_CODE_02 like \"%' + request.param('searchWord2') + '%\" and STB_DEPT_CODE_03 like \"%' + request.param('searchWord3') + '%\"';
    }
    query += ' and STB_DEPT_CODE_03 = \'' + code_03 + '\'';

    query += ' order by STB_DEPT_NM, STB_NM';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/voiceCallService', function(request, response) {
    logger.info('Path change : /voiceCallService');
    /*
        var query = util.format('select IFNULL(NM,\'\') as NM, IFNULL(DEPT_NM,\'\') as DEPT_NM, IFNULL(TEAM_NM,\'\') as TEAM_NM,' +
            'IFNULL(CALL_TIME_ST,\'\') as CALL_TIME_ST, IFNULL(CALL_TIME_ED, \'\') as CALL_TIME_ED, CTN, STATUS, INSERT_DATE' +
            ' from TB_VOICE_CALL_SERVICE where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'', request.param('CUSTCNT'), request.param('INSERTDATE'));
    */
    var query = util.format('select IFNULL(b.NM,\'\') as NM ,IFNULL(b.DEPT_NM,\'\') as DEPT_NM ,IFNULL(b.CALL_TIME_ST,\'\') as CALL_TIME_ST' +
        ',IFNULL(b.CALL_TIME_ED,\'\') as CALL_TIME_ED, b.CTN,b.STATUS, b.INSERT_DATE' +
        ' from (select P_CUST_CTN ,P_INSERT_DATE ,CTN ,max(INSERT_DATE) as INSERT_DATE from TB_VOICE_CALL_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'' +
        ' group by P_CUST_CTN ,P_INSERT_DATE,CTN) a left join TB_VOICE_CALL_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.CTN = b.CTN' +
        ' order by b.INSERT_DATE', request.param('CUSTCNT'), request.param('INSERTDATE'));
    logger.info('Query:', query);

    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/voiceCallServicing', function(request, response) {
    logger.info('Path change : /voiceCallServicing');

    var query = util.format('select IFNULL(a.NM,\'\') as NM, a.CTN, IFNULL(a.DEPT_NM,\'\') as DEPT_NM, b.ARANK as ARANK, a.STATUS, a.CALL_TIME_ST, a.CALL_TIME_ED' +
        ' from TB_VOICE_CALL_SERVICE a left join TB_ORGANOGRAM b on a.CTN = b.CTN where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' and a.STATUS < \'3\' and a.STATUS <> \'9\'', request.param('CUSTCNT'), request.param('INSERTDATE'));
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/fullvoiceCallService', function(request, response) {
    // 파일을 읽습니다.
    logger.info('Path change : /fullvoiceCallService');
    var query = util.format("select IFNULL(NM, '') as NM, IFNULL(DEPT_NM, '') as DEPT_NM, IFNULL(TEAM_NM, '') as TEAM_NM, " +
        "IFNULL(CALL_TIME_ST, '') as CALL_TIME_ST, IFNULL(CALL_TIME_ED, '') as CALL_TIME_ED, CTN, STATUS, INSERT_DATE " +
        " from TB_VOICE_CALL_SERVICE where P_CUST_CTN = '%s' and P_INSERT_DATE = '%s' order by INSERT_DATE"
        ,request.param('CUSTCNT'), request.param('INSERTDATE'));
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {            
            response.send(results);
        }
    });
});

app.get('/stbService', function(request, response) {
    logger.info('Path change : /stbService');

    var query = util.format('select b.STB_NM,b.STB_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,IFNULL(b.SVC_STB_IP, \'\') as SVC_STB_IP,IFNULL(b.STB_MAC_ADDR,\'\') as STB_MAC_ADDR,b.STATUS,b.INSERT_DATE,' +
        'IFNULL(b.STB_MODEL,\'\') as STB_MODEL, IFNULL(b.STB_OS,\'\') as STB_OS' +
        ' from ( select P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR, max(INSERT_DATE) as INSERT_DATE from TB_STB_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR) a' +
        ' left join TB_STB_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.STB_MAC_ADDR = b.STB_MAC_ADDR' +
        ' order by b.INSERT_DATE', request.param('CUSTCNT'), request.param('INSERTDATE'));


    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/stbServicing', function(request, response) {
    logger.info('Path change : /stbServicing');
    var query;
    var query = util.format('select IFNULL(a.STB_NM,\'\') as STB_NM, IFNULL(a.STB_DEPT_NM,\'\') as STB_DEPT_NM, a.SVC_TIME_ST, a.SVC_TIME_ED, a.SVC_STB_IP, a.INSERT_DATE,' +
        'b.STB_DEPT_CODE_01 as STB_DEPT_CODE_01, b.STB_DEPT_CODE_02 as STB_DEPT_CODE_02, b.STB_DEPT_CODE_03 as STB_DEPT_CODE_03,' +
        'a.STB_MAC_ADDR as STB_MAC_ADDR, a.STATUS as STATUS, b.STB_ADMIN_INFO as STB_ADMIN_INFO, b.STB_LOCATION as STB_LOCATION' +
        ' from TB_STB_SERVICE a left join TB_STB_INFO b on a.STB_MAC_ADDR = b.STB_MAC_ADDR where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' and a.STATUS < \'3\'', request.param('CUSTCNT'), request.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/fullstbService', function(request, response) {
    // 파일을 읽습니다.
    logger.info('Path change : /fullstbService');

    var q = util.format("SELECT LOCALE from TB_ADMIN WHERE ADMIN_ID = '%s'", request.session.userid);
    dbConn.query(q, function(error, results1) {
        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            var locale;
            if (results1[0].LOCALE == "" || results1[0].LOCALE == null) {
                locale = 'KO';
            } else {
                locale = results1[0].LOCALE.toUpperCase();
            }
            var defect_code = request.param('code');
            var query = util.format("select IFNULL(STB_NM,'') as STB_NM, IFNULL(STB_DEPT_NM,'') as STB_DEPT_NM, IFNULL(SVC_TIME_ST,'') as SVC_TIME_ST " +
            ", IFNULL(SVC_TIME_ED,'') as SVC_TIME_ED, IFNULL(SVC_STB_IP, '') as SVC_STB_IP, a.STB_MAC_ADDR, STATUS, INSERT_DATE, IFNULL(b.STB_MODEL,'') as STB_MODEL " +
            ", IFNULL(b.STB_OS,'') as STB_OS, c.DEFECT_CODE, c.REASON " +
            " from TB_STB_SERVICE a left join (SELECT STB_MAC_ADDR,STB_MODEL,STB_OS FROM TB_STB_INFO) b on a.STB_MAC_ADDR = b.STB_MAC_ADDR " +
            " LEFT JOIN (SELECT REASON_" + locale + " REASON, DEFECT_CODE FROM TB_DEFECT_CODE) c ON a.DEFECT_CODE = c.DEFECT_CODE " +
            " where P_CUST_CTN = '%s' and P_INSERT_DATE = '%s' order by INSERT_DATE"
            ,request.param('CUSTCNT'), request.param('INSERTDATE'));    
            logger.info('Query:', query);
            dbConn.query(query, function(error, results) {
                if (error) {
                    logger.error('DB Error:', error);
                } else {                    
                    response.send(results);
                }
            });    
        }
    });
});

//mobile, pc 통합 (서비스 현황)
// app.get('/viewService', function(request, response) {

//     logger.info('Path change : /viewService');

//     var query = util.format('select b.DEV_NM,b.DEV_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,b.MODEL,b.VERSION,IFNULL(b.SVC_IP, \'\') as SVC_IP,IFNULL(b.DEV_KEY,\'\') as DEV_KEY,b.STATUS,b.VSTATUS,b.INSERT_DATE' +
//         ' from ( select P_CUST_CTN, P_INSERT_DATE, DEV_KEY, max(INSERT_DATE) as INSERT_DATE from TB_VIEW_SERVICE' +
//         ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, DEV_KEY) a' +
//         ' left join TB_VIEW_SERVICE b' +
//         ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.DEV_KEY = b.DEV_KEY' +
//         ' WHERE DEV_TYPE = \'%s\'' +
//         ' order by b.INSERT_DATE', request.param('CUSTCNT'), request.param('INSERTDATE'), request.param('view_type'));


//     dbConn.query(query, function(error, results) {

//         logger.info('Query:', query);

//         if (error) {
//             logger.error('DB Error:', error);
//         } else {
            
//             response.send(results);
//         }
//     });
// });

app.get('/viewServicing', function(request, response) {

    logger.info('Path change : /viewServicing');
    var query;
    var type = request.param('view_type');

    if (type == '1') {
        query = util.format('SELECT DEV_NM ,DEV_KEY, DEV_DEPT_NM, b.ARANK, b.CTN as CTN, SVC_TIME_ST ,SVC_TIME_ED ,SVC_IP ,a.STATUS ,a.INSERT_DATE ,a.UPDATE_DATE FROM TB_VIEW_SERVICE a' +
            ' left join TB_ORGANOGRAM b on a.DEV_KEY = b.CTN' +
            ' WHERE DEV_TYPE = \'%s\' and a.STATUS < \'3\' and P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'', request.param('view_type'), request.param('CUSTCNT'), request.param('INSERTDATE'));

    } else if (type == '3') {
        query = util.format('SELECT DEV_NM ,DEV_KEY, DEV_DEPT_NM, b.ADMIN_ARANK as ARANK, b.ADMIN_MOBILE_NUM as CTN, SVC_TIME_ST ,SVC_TIME_ED ,SVC_IP ,a.STATUS ,a.INSERT_DATE ,a.UPDATE_DATE FROM TB_VIEW_SERVICE a' +
            ' left join TB_ADMIN b on a.DEV_KEY = b.ADMIN_ID' +
            ' WHERE DEV_TYPE = \'%s\' and a.STATUS < \'3\' and P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'', request.param('view_type'), request.param('CUSTCNT'), request.param('INSERTDATE'));
    }


    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }

    });

});

app.get('/fullViewService', function(request, response) {
    // 파일을 읽습니다.
    logger.info('Path change : /fullViewService');

    //  var query = util.format('SELECT a.*, b.* FROM TB_VIEW_SERVICE a LEFT JOIN (SELECT REASON, DEFECT_CODE  FROM TB_DEFECT_CODE) b ' +
    //             'ON a.DEFECT_CODE = b.DEFECT_CODE WHERE DEV_TYPE = \'%s\' and P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' and SVC_TYPE <> \'10\' order by INSERT_DATE'
	// 			, request.param('view_type'), request.param('CUSTCNT'), request.param('INSERTDATE'));

    var q = util.format("SELECT LOCALE from TB_ADMIN WHERE ADMIN_ID = '%s'", request.session.userid);
    dbConn.query(q, function(error, results1) {
        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            var locale;
            if (results1[0].LOCALE == "" || results1[0].LOCALE == null) {
                locale = 'KO';
            } else {
                locale = results1[0].LOCALE.toUpperCase();
            }
            var defect_code = request.param('code');
            var query = util.format("SELECT a.*, b.REASON FROM TB_VIEW_SERVICE a LEFT JOIN (SELECT REASON_" + locale + " REASON, DEFECT_CODE  FROM TB_DEFECT_CODE) b " +
            "ON a.DEFECT_CODE = b.DEFECT_CODE WHERE DEV_TYPE = '%s' and P_CUST_CTN = '%s' and P_INSERT_DATE = '%s' and SVC_TYPE <> '10' order by INSERT_DATE "
            ,request.param('view_type'), request.param('CUSTCNT'), request.param('INSERTDATE'));

            dbConn.query(query, function(error, results) {
                logger.info('Query:', query);
                if (error) {
                    logger.error('Error:', error);
                } else {
                    response.send(results);
                }
            });        
        }
    });
            

    // dbConn.query(query, function(error, results) {

    //     logger.info('Query:', query);

    //     if (error) {
    //         logger.error('DB Error:', error);
    //     } else {
            
    //         response.send(results);
    //     }

    // });
});

app.post('/pushService', function(request, response) {

    logger.info('Path change: /pushService');

    lcsServiceAPI.pushService(dbConn, request.param('custCTN'), request.param('insertDate'), function(results) {

        response.send(results);
    });
});

app.post('/fullPushService', function(request, response) {

    logger.info('Path change: /fullPushService');

    lcsServiceAPI.fullPushService(dbConn, request.param('custCTN'), request.param('insertDate'), function(results) {

        response.send(results);
    });
});



app.get('/voiceServicingCount', function(request, response) {

    logger.info('Path change : /voiceServicingCount');
    var query;
    query = util.format('SELECT count(P_CUST_CTN) FROM TB_VOICE_CALL_SERVICE WHERE P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'', request.param('CUSTCNT'), request.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.get('/totalServicingCount', function(request, response) {
    var cust_ctn = request.param('CUSTCNT');
    var insert_date = request.param('INSERTDATE');

    logger.info('Path change : /totalServicingCount');

    var query;
    query = "select ";
    query += "(SELECT count(P_CUST_CTN) as stb_count FROM TB_STB_SERVICE WHERE STATUS < '3' and P_CUST_CTN = '" + cust_ctn + "' and P_INSERT_DATE = '" + insert_date + "') as stb_count, ";
    query += "(SELECT count(P_CUST_CTN) as mob_count FROM TB_VIEW_SERVICE WHERE STATUS < '3' and DEV_TYPE = '1' and P_CUST_CTN = '" + cust_ctn + "' and P_INSERT_DATE = '" + insert_date + "') as mob_count, ";
    query += "(SELECT count(P_CUST_CTN) as pc_count FROM TB_VIEW_SERVICE WHERE STATUS < '3' and DEV_TYPE = '3' and P_CUST_CTN = '" + cust_ctn + "' and P_INSERT_DATE = '" + insert_date + "') as pc_count ";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.get('/insertVoiceCallService', function(request, response) {
    logger.info('Path change : /insertVoiceCallService');

    var query = util.format('insert into TB_VOICE_CALL_SERVICE (P_CUST_CTN,P_INSERT_DATE,CTN,NM,DEPT_NM,INSERT_DATE, STATUS) ' +
        'values(\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\', \'1\')', request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'),
        request.param('CTN'), request.param('NM'), request.param('DEPT_NM'), request.param('INSERT_DATE'));
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            //response.send(results);
        }
    });
});

app.get('/UpdateVoiceCount', function(request, response) {
    logger.info('Path change : /UpdateVoiceCount');

    var query = util.format('update TB_TERMINAL_IMAGE_TRANS set CTN_CNT=%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\'', request.param('P_COUNT'), request.param('P_CUST_CTN'), request.param('P_CTNDEVICE'), request.param('P_INSERT_DATE'));
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
        }
    });
})

app.get('/insertSTBService', function(request, response) {
    logger.info('Path change : /insertSTBService');

    var query = util.format('insert into TB_STB_SERVICE (P_CUST_CTN,P_INSERT_DATE,STB_MAC_ADDR,STB_NM,STB_DEPT_NM,INSERT_DATE,STATUS) ' +
        'values(\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\', \'1\')', request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'),
        request.param('STB_MAC_ADDR'), request.param('STB_NM'), request.param('STB_DEPT_NM'), request.param('INSERT_DATE'));
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
        }
    });
});

app.get('/UpdateSTBCount', function(request, response) {
    logger.info('Path change : /UpdateSTBCount');

    var query = util.format('update TB_TERMINAL_IMAGE_TRANS set STB_CNT=%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\'', request.param('P_COUNT'), request.param('P_CUST_CTN'), request.param('P_CTNDEVICE'), request.param('P_INSERT_DATE'));
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            //response.send(results);
        }
    });
})


app.get('/loginAdminInfo', function(request, response) {

    logger.info('Path change : /loginAdminInfo');

    var query = util.format('select count(ADMIN_ID) as CNT,CODE_03 from TB_ADMIN where ADMIN_ID = \'%s\'', request.param('P_ADMINID'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });
});

app.get('/voiceCallStatus', function(request, response) {
    logger.info('Path change : /voiceCallStatus');

    var query = util.format('SELECT SVC_TYPE FROM TB_TERMINAL_IMAGE_TRANS WHERE CUST_CTN = \'%s\' and INSERT_DATE = \'%s\' and STATUS < 3', request.param('CUSTCNT'), request.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }
    });
});


app.get('/stbStatus', function(request, response) {

    logger.info('Path change : /stbStatus');

    var query = util.format('select IFNULL(STB_NM,\'\') as STB_NM, IFNULL(STB_DEPT_NM,\'\') as STB_DEPT_NM, IFNULL(SVC_TIME_ST,\'\') as SVC_TIME_ST,' +
        'IFNULL(SVC_TIME_ED,\'\') as SVC_TIME_ED, IFNULL(SVC_STB_IP, \'\') as SVC_STB_IP, STB_MAC_ADDR, STATUS, INSERT_DATE' +
        ' from TB_STB_SERVICE where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' and STATUS < 3', request.param('CUSTCNT'), request.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/commonList', CheckAuth, function(request, response) {

    logger.info('Path change : /commonList');

    var query = "select * from TB_COMMON where C_KEY = '12'";

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

//----------------------------------- 이력조회 -------------------------------------

app.get('/service/report', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /service/report');

    fs.readFile('html/report.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {
                    'session': request.session.userid,
                    'session_pw': request.session.userpw,
                    'drone': request.session.drone
                }
            }));
        }
    });
});

app.get('/reportStatus', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /reportStatus');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var todate = request.param('todate');
    var fromdate = request.param('fromdate');

    fs.readFile('html/report.html', function(error, data) {

        var query = 'select * from TB_TERMINAL_IMAGE_TRANS ' +
            'where status > \'2\' and CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' and CODE_03=\'' + code3 + '\' and ' +
            'INSERT_DATE >= \'' + todate + '\' and INSERT_DATE < \'' + fromdate + '\' order by INSERT_DATE desc';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/reportStatusData', function(request, response) {
    logger.info('Path change : /reportStatusData');

    var CUST_CTN = request.param('CUST_CTN');
    var INSERT_DATE = request.param('INSERT_DATE');
    var code03 = request.session.code_03;

    var query = 'select a.*, b.CODE_01, b.CODE_02, b.CODE_03, b.CODE_ID, b.CTL_NM';
    /*query +=    ' c.LPMS_CLASS, c.LPMS_REQNO , c.LPMS_FACTORY, c.LPMS_TEAM, c.LPMS_GUBUN, c.LPMS_CONTENT, c.LPMS_COMPANY';*/
    query += ' from TB_TERMINAL_IMAGE_TRANS a';
    query += ' LEFT JOIN';
    query += ' (SELECT CODE_01, CODE_02, CODE_03, CODE_ID, CTL_NM';
    query += ' FROM TB_CONTROL';
    query += ' ) b';
    query += ' ON a.CODE_02 = b.CODE_02 AND a.CODE_03 = b.CODE_03 ';
    /*    query +=    ' LEFT JOIN (';
        query +=    '     SELECT';
        query +=    '         LPMS_CLASS';
        query +=    '         ,LPMS_REQNO';
        query +=    '         ,LPMS_FACTORY, LPMS_TEAM, LPMS_GUBUN, LPMS_CONTENT, LPMS_COMPANY';
        query +=    '     FROM';
        query +=    '         TB_LPMS_IFACE_HISTORY';
        query +=    ' ) c';
        query +=    ' ON a.LPMS_REQNO = c.LPMS_REQNO';*/
    query += ' where STATUS > "2" and CUST_CTN=\'' + CUST_CTN + '\' and INSERT_DATE=\'' + INSERT_DATE + '\' and a.CODE_03 = \'' + code03 + '\'';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            //logger.info('DB success');
            response.send(results[0]);
        }
    });
});

app.get('/reportGetData', CheckAuth, function(request, response) {
    response.send({
        'session': request.session.userid,
        'session_pw': request.session.userpw,
        'drone': request.session.drone
    });
});

app.get('/reportStatusView/', CheckAuthCommon, function(request, response) {

    fs.readFile('html/report_view.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            // response.writeHead(200, {
            //     'Content-Type': 'text/html; charset=UTF-8'
            // });

            response.send(ejs.render(data, {
                data: {
                    'session': request.session.userid,
                    'session_pw': request.session.userpw,
                    'drone': request.session.drone
                }
            }));            
            // response.end(data);
        }
    });
});

app.get('/reportStatus/:id', function(request, response) {
    logger.info('Path change : /reportStatus/', request.param('id'));

    var query = util.format('select * from TB_TERMINAL_IMAGE_TRANS where STATUS = \'3\' and CUST_CTN=\'%s\'', request.param('id'));

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.all('/reportList', CheckAuthCommon, function(request, response) {

    logger.info('Path change : /reportList');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var todate = request.param('todate');
    var fromdate = request.param('fromdate');
    var ctn = request.param('ctn');
    var type = request.param('type');
    var userlevel = request.session.userlv;

    if (type == 'excel') {
        fromdate = parseInt(fromdate) + 1;
    }

    fs.readFile('html/report.html', function(error, data) {

        var query;

        //query = 'select a.*, b.CTL_NM from TB_TERMINAL_IMAGE_TRANS a, TB_CONTROL b where a.CODE_02 = b.CODE_02 and status>\'2\' and a.INSERT_DATE >= \''+todate+'\' and a.INSERT_DATE < \''+fromdate+'\'';
        query = 'SELECT ';
        query += ' a.CUST_CTN,a.CUST_NM,f.CTN_NM,f.CTN_OS,a.CUST_DEPT_NM,e.CTL_NM,a.SUBJECT,a.PLAY_TIME,';
        query += ' a.INSERT_DATE, a.UPDATE_DATE, ifnull(d.CTN_CNT, 0) as CTN_CNT, ifnull(c.STB_CNT, 0) as STB_CNT,ifnull(h.MOBILE_CNT, 0) as MOBILE_CNT,ifnull(i.PC_CNT, 0) as PC_CNT,';
        query += ' if(isnull(UPLOAD_FILE_NM), "-", "O") as UPLOAD_FILE, a.UPLOAD_FILE_NM, a.UPLOAD_FILE_SZ,';
        //query +=    ' case when a.STATUS = 3 then "서비스종료" when a.STATUS = 9 then "비정상종료" else "정의되지 않은 상태" end as STATUS,';
        query += ' STATUS,';
        query += ' a.DEFECT_CODE, g.REASON ,a.CTN_DEVICE, a.DEL_FLAG, a.LCS_FLMGNO,';
        query += ' a.TOT_BRIGHT_LVL, a.TOT_BRIGHT_RATE ,a.TOT_DIFF_LVL,a.TOT_DIFF_RATE, a.VCODEC, a.FPS, a.ENC_FLAG ';
        query += ' FROM';
        query += ' TB_TERMINAL_IMAGE_TRANS a';
        query += ' LEFT JOIN';
        query += ' (SELECT P_CUST_CTN,P_INSERT_DATE,count(*) STB_CNT';
        query += ' FROM TB_STB_SERVICE';
        query += ' WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\'';
        query += ' GROUP BY P_CUST_CTN, P_INSERT_DATE';
        query += ' ) c';
        query += ' ON a.CUST_CTN = c.P_CUST_CTN and a.INSERT_DATE = c.P_INSERT_DATE';
        query += ' LEFT JOIN';
        query += ' (SELECT P_CUST_CTN, P_INSERT_DATE, count(*) CTN_CNT';
        query += ' FROM TB_VOICE_CALL_SERVICE';
        query += ' WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\'';
        query += ' GROUP BY P_CUST_CTN,P_INSERT_DATE';
        query += ' ) d';
        query += ' ON a.CUST_CTN = d.P_CUST_CTN and a.INSERT_DATE = d.P_INSERT_DATE';
        query += ' LEFT JOIN';
        query += ' (SELECT CODE_02, CTL_NM';
        query += ' FROM TB_CONTROL';
        query += ' WHERE CODE_03=\'' + code3 + '\'';
        query += ' ) e';
        query += ' ON a.CODE_02 = e.CODE_02';
        query += ' LEFT JOIN';
        query += ' (SELECT CUST_CTN, CTN_DEVICE, CTN_NM, CTN_OS';
        query += ' FROM TB_CUST_INFO';
        query += ' ) f';
        query += ' ON a.CUST_CTN = f.CUST_CTN';
        query += ' and a.CTN_DEVICE = f.CTN_DEVICE';
        query += ' LEFT JOIN';
        query += ' (SELECT REASON, DEFECT_CODE';
        query += ' FROM TB_DEFECT_CODE';
        query += ' ) g';
        query += ' ON a.DEFECT_CODE = g.DEFECT_CODE';
        query += ' LEFT JOIN (';
        query += ' 	SELECT';
        query += ' 		P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += '         ,count(*) as MOBILE_CNT';
        query += '     FROM';
        query += '         TB_VIEW_SERVICE';
        query += '     WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\' and DEV_TYPE="1"';
        query += '     GROUP BY';
        query += '         P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += ' ) h';
        query += ' ON a.CUST_CTN = h.P_CUST_CTN and a.INSERT_DATE = h.P_INSERT_DATE';
        query += ' LEFT JOIN (';
        query += ' 	SELECT';
        query += ' 		P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += '         ,count(*) as PC_CNT';
        query += '     FROM';
        query += '         TB_VIEW_SERVICE';
        query += '     WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\' and DEV_TYPE="3"';
        query += '     GROUP BY';
        query += '         P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += ' ) i';
        query += ' ON a.CUST_CTN = i.P_CUST_CTN and a.INSERT_DATE = i.P_INSERT_DATE';
        query += ' WHERE';
        query += ' status > \'2\' and';
        query += ' (SVC_TYPE > \'1\' or SVC_TYPE is null) and';
        query += ' a.INSERT_DATE >= \'' + todate + '\' and';
        query += ' a.INSERT_DATE < \'' + fromdate + '\' and';
        query += ' (DEL_FLAG = \'0\' or DEL_FLAG is null) ';

        //if (code1 == '900' && code2 == '999') {
        if (userlevel == 1) {
            logger.info('superuser');
            query += ' and a.CODE_03=\'' + code3 + '\'';
        } else {
            query += ' and a.CODE_01=\'' + code1 + '\' and a.CODE_02=\'' + code2 + '\' and a.CODE_03=\'' + code3 + '\'';
        }

        if (ctn == '' || ctn == null) {} else {
            query += ' and a.CUST_CTN like \"%' + ctn + '%\"';
        }

        //query += ' group by CUST_CTN, CTN_DEVICE, INSERT_DATE';
        query += ' order by a.INSERT_DATE desc';

        dbConn.query(query, function(error, results, fields) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                

                var except = [];
                except.push('LCS_FLMGNO');
                except.push('CTN_NM');
                except.push('CTN_OS');
                except.push('CUST_DEPT_NM');
                except.push('SUBJECT');
                except.push('CTN_CNT');
                except.push('STB_CNT');
                except.push('MOBILE_CNT');
                except.push('PC_CNT');
                except.push('DEFECT_CODE');
                except.push('REASON');
                except.push('DEL_FLAG');
                except.push('LCS_FLMGNO');
                except.push('CTN_DEVICE');
                except.push('UPLOAD_FILE_NM');
                except.push('REQUEST_STATUS');

                if (type == 'excel') {

                    var filename = todate + "_" + fromdate + ".xlsx";
                    utilLib.excelExport(request, response, results, fields, filename, except);
                } else {
                    response.send(results);
                }
            }
        });
    });
});

app.get('/reportCTN', CheckAuth, function(request, response) {
    logger.info('Path change : /reportCTN');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var ctn = request.param('ctn');

    fs.readFile('html/report.html', function(error, data) {

        var query = 'select * from TB_TERMINAL_IMAGE_TRANS ' +
            'where status=\'3\' and CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' and CODE_03=\'' + code3 + '\' ' +
            'and CUST_CTN = \'' + ctn + '\' order by INSERT_DATE desc';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});


app.get('/pushServiceReport', CheckAuthControl, function(request, response) {
    logger.info('Path change : /pushServiceReport');

    fs.readFile('html/push_report.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


app.get('/PushReportList', CheckAuth, function(request, response) {
    logger.info('Path change : /PushReportList');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var todate = request.param('todate').replace(/-/g, '');
    var fromdate = request.param('fromdate').replace(/-/g, '');
    var ctn = request.param('ctn');
    var ctl = request.param('ctl');
    var defectcode = request.param('defectcode');
    var type = request.param('type');
    var userlevel = request.session.userlv;

    if (type == 'excel') {
        fromdate = parseInt(fromdate) + 1;
    }

    fs.readFile('html/report.html', function(error, data) {

        var query;

        //query = 'select a.*, b.CTL_NM from TB_TERMINAL_IMAGE_TRANS a, TB_CONTROL b where a.CODE_02 = b.CODE_02 and status>\'2\' and a.INSERT_DATE >= \''+todate+'\' and a.INSERT_DATE < \''+fromdate+'\'';
        query = 'SELECT ';
        query += ' a.CUST_NM,a.CUST_CTN,f.CTN_NM,f.CTN_OS,a.CUST_DEPT_NM,e.CTL_NM,a.SUBJECT,';
        query += ' a.INSERT_DATE, a.UPDATE_DATE, ifnull(d.CTN_CNT, 0) as CTN_CNT, ifnull(c.STB_CNT, 0) as STB_CNT,ifnull(h.VIEW_CNT, 0) as VIEW_CNT,';
        query += ' if(isnull(UPLOAD_FILE_NM), "-", "O") as UPLOAD_FILE_NM,';
        query += ' a.CAMERA_TYPE, a.CAMERA_MODEL, a.CONNECT_TYPE,';
        query += ' a.DEFECT_CODE, g.REASON ,a.CTN_DEVICE,LCS_FLMGNO,a.UPLOAD_FILE_NM as UPLOAD_FILE';
        query += ' a.DEFECT_CODE, g.REASON ,a.CTN_DEVICE,LCS_FLMGNO,a.UPLOAD_FILE_NM as UPLOAD_FILE';
        query += ' FROM';
        query += ' TB_TERMINAL_IMAGE_TRANS a';
        query += ' LEFT JOIN';
        query += ' (SELECT P_CUST_CTN,P_INSERT_DATE,count(*) STB_CNT';
        query += ' FROM TB_STB_SERVICE';
        query += ' WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\'';
        query += ' GROUP BY P_CUST_CTN, P_INSERT_DATE';
        query += ' ) c';
        query += ' ON a.CUST_CTN = c.P_CUST_CTN and a.INSERT_DATE = c.P_INSERT_DATE';
        query += ' LEFT JOIN';
        query += ' (SELECT P_CUST_CTN, P_INSERT_DATE, count(*) CTN_CNT,NM';
        query += ' FROM TB_VOICE_CALL_SERVICE';
        query += ' WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\'';
        query += ' GROUP BY P_CUST_CTN,P_INSERT_DATE';
        query += ' ) d';
        query += ' ON a.CUST_CTN = d.P_CUST_CTN and a.INSERT_DATE = d.P_INSERT_DATE';
        query += ' LEFT JOIN';
        query += ' (SELECT CODE_02, CTL_NM';
        query += ' FROM TB_CONTROL';
        query += ' ) e';
        query += ' ON a.CODE_02 = e.CODE_02';
        query += ' LEFT JOIN';
        query += ' (SELECT CUST_CTN, CTN_DEVICE, CTN_NM, CTN_OS';
        query += ' FROM TB_CUST_INFO';
        query += ' ) f';
        query += ' ON a.CUST_CTN = f.CUST_CTN';
        query += ' and a.CTN_DEVICE = f.CTN_DEVICE';
        query += ' LEFT JOIN';
        query += ' (SELECT REASON, DEFECT_CODE';
        query += ' FROM TB_DEFECT_CODE';
        query += ' ) g';
        query += ' ON a.DEFECT_CODE = g.DEFECT_CODE';
        query += ' LEFT JOIN (';
        query += ' 	SELECT';
        query += ' 		P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += '         ,count(*) as VIEW_CNT';
        query += '     FROM';
        query += '         TB_VIEW_SERVICE';
        query += '     WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\'';
        query += '     GROUP BY';
        query += '         P_CUST_CTN';
        query += '         ,P_INSERT_DATE';
        query += ' ) h';
        query += ' ON a.CUST_CTN = h.P_CUST_CTN and a.INSERT_DATE = h.P_INSERT_DATE';
        query += ' WHERE';
        query += ' status > \'2\' and';
        query += ' (SVC_TYPE > \'1\' or SVC_TYPE is null) and';
        query += ' a.INSERT_DATE >= \'' + todate + '\' and';
        query += ' a.INSERT_DATE < \'' + fromdate + '\'';

        //if (code1 == '900' && code2 == '999') {
        if (userlevel == 1) {
            logger.info('superuser');
        } else {
            query += ' and a.CODE_01=\'' + code1 + '\' and a.CODE_02=\'' + code2 + '\' and a.CODE_03=\'' + code3 + '\'';
        }

        if (ctn == '' || ctn == null) {} else {
            query += ' and a.CUST_CTN = \'' + ctn + '\'';
        }

        if (ctl == '' || ctl == null) {} else {
            query += ' and CTL_NM like \"%' + ctl + '%\"';
        }

        if (defectcode == '' || defectcode == null) {} else {
            query += ' and a.DEFECT_CODE like \"' + defectcode + '%\"';
            //query += ' and a.DEFECT_CODE = \''+defectcode+'\'';
        }


        /*
        if(ctn == '' || ctn == null) {
            if(ctl == '' || ctl == null) {
            }else {
                query += ' and CTL_NM like \"%' + ctl + '%\"';
            }

        }else {
            if(ctl == '' || ctl == null) {
                query += ' and a.CUST_CTN = \''+ctn+'\'';
            }else {
                query += ' and a.CUST_CTN = \''+ctn+'\' and CTL_NM like \"%' + ctl + '%\"';
            }
        }
        */

        query += ' group by CUST_CTN, CTN_DEVICE, INSERT_DATE';
        query += ' order by a.INSERT_DATE desc';

        dbConn.query(query, function(error, results, fields) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                

                if (type == 'excel') {
                    var filename = todate + "_" + fromdate + ".xlsx";
                    utilLib.excelExport(request, response, results, fields, filename);
                } else {
                    response.send(results);
                }

            }
        });
    });
});


app.get('/pushCount', function(request, response) {

    var f_date = request.param("f_date");
    var t_date = request.param("t_date");
    var push_type = request.param('push_type');
    var gcm_result = request.param('gcm_result');
    var push_status = request.param('push_status');
    var ctn = request.param('ctn');
    var p_ctn = request.param('p_ctn');

    var query = ' SELECT tot.*, count(*) as cnt';
    query += ' FROM ';
    query += ' (SELECT P_CUST_CTN, ';
    query += ' P_INSERT_DATE, ';
    query += ' CTN, ';
    query += ' CUST_KEY, ';
    query += ' PUSH_TYPE, ';
    query += ' max(TITLE) as TITLE, ';
    query += ' max(MESSAGE) as MESSAGE, ';
    query += ' max(REQUEST_TIME) as REQUEST_TIME, ';
    query += ' max(RESPONSE_TIME) as RESPONSE_TIME, ';
    query += ' max(MESSAGE_ID) as MESSAGE_ID, ';
    query += ' max(HTTP_CODE) as HTTP_CODE, ';
    query += ' max(GCM_RESULT) as GCM_RESULT, ';
    query += ' max(GCM_ERROR) as GCM_ERROR, ';
    query += ' max(REG_ID) as REG_ID, ';
    query += ' max(CANONICAL_ID) as CANONICAL_ID, ';
    query += ' max(PUSH_STATUS) as PUSH_STATUS, ';
    query += ' max(RECEIVE_TIME) as RECEIVE_TIME, ';
    query += ' max(INSERT_DATE) as INSERT_DATE ';
    query += ' FROM TB_PUSH_HISTORY ';
    query += ' where REQUEST_TIME > \'' + f_date + '\' and REQUEST_TIME < \'' + t_date + '\'';
    query += ' GROUP BY P_CUST_CTN, ';
    query += ' P_INSERT_DATE, ';
    query += ' CTN, ';
    query += ' CUST_KEY, ';
    query += ' PUSH_TYPE ';
    query += ' ) tot ';

    // 'select * from TB_PUSH_HISTORY where INSERT_DATE > \''+f_date+'\' and INSERT_DATE < \''+t_date+'\' ';
    query += 'where 1=1 ';

    if (push_type != "0") {
        query += 'and tot.PUSH_TYPE = \'' + push_type + '\' ';
    }
    if (gcm_result != "0") {
        query += 'and tot.GCM_RESULT = \'' + gcm_result + '\' ';
    }
    if (push_status != "all") {
        query += 'and tot.PUSH_STATUS = \'' + push_status + '\' ';
    }
    if (ctn != '') {
        query += 'and tot.CTN like \"%' + ctn + '%\" ';
    }
    if (p_ctn != '') {
        query += 'and tot.P_CUST_CTN like \"%' + p_ctn + '%\"';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            response.send(results[0]);

        }

    });

});

app.all('/pushPaging', function(request, response) {
    logger.info('Path change : /pushPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var f_date = request.param('f_date');
    var t_date = request.param('t_date');

    var fromdate = f_date.replace(/-/g, '') + '000000';
    var todate = t_date.replace(/-/g, '') + '235959';

    var push_type = request.param('push_type');
    var gcm_result = request.param('gcm_result');
    var push_status = request.param('push_status');
    var ctn = request.param('ctn');
    var p_ctn = request.param('p_ctn');
    var type = request.param('type');

    var query = ' SELECT tot.P_CUST_CTN, tot.P_INSERT_DATE, tot.CTN as RECV_CTN, tot.PUSH_TYPE, tot.TITLE as PUSH_TITLE, tot.MESSAGE as PUSH_MESSAGE, tot.REQUEST_TIME, tot.RESPONSE_TIME, tot.RECEIVE_TIME, tot.HTTP_CODE, ';
    query += ' tot.GCM_RESULT, tot.GCM_ERROR, tot.PUSH_STATUS, tot.CANONICAL_ID, tot.REG_ID';
    query += ' FROM ';
    query += ' (SELECT P_CUST_CTN, ';
    query += ' P_INSERT_DATE, ';
    query += ' CTN, ';
    query += ' CUST_KEY, ';
    query += ' PUSH_TYPE, ';
    query += ' max(TITLE) as TITLE, ';
    query += ' max(MESSAGE) as MESSAGE, ';
    query += ' max(REQUEST_TIME) as REQUEST_TIME, ';
    query += ' max(RESPONSE_TIME) as RESPONSE_TIME, ';
    query += ' max(MESSAGE_ID) as MESSAGE_ID, ';
    query += ' max(HTTP_CODE) as HTTP_CODE, ';
    query += ' max(GCM_RESULT) as GCM_RESULT, ';
    query += ' max(GCM_ERROR) as GCM_ERROR, ';
    query += ' max(REG_ID) as REG_ID, ';
    query += ' max(CANONICAL_ID) as CANONICAL_ID, ';
    query += ' max(PUSH_STATUS) as PUSH_STATUS, ';
    query += ' max(RECEIVE_TIME) as RECEIVE_TIME, ';
    query += ' max(INSERT_DATE) as INSERT_DATE ';
    query += ' FROM TB_PUSH_HISTORY ';
    query += ' where REQUEST_TIME > \'' + fromdate + '\' and REQUEST_TIME < \'' + todate + '\'';
    query += ' GROUP BY P_CUST_CTN, ';
    query += ' P_INSERT_DATE, ';
    query += ' CTN, ';
    query += ' CUST_KEY, ';
    query += ' PUSH_TYPE ';
    query += ' ) tot ';

    // 'select * from TB_PUSH_HISTORY where INSERT_DATE > \''+f_date+'\' and INSERT_DATE < \''+t_date+'\' ';
    query += 'where 1=1 ';

    if (push_type != "0") {
        query += 'and tot.PUSH_TYPE = \'' + push_type + '\' ';
    }
    if (gcm_result != "0") {
        query += 'and tot.GCM_RESULT = \'' + gcm_result + '\' ';
    }
    if (push_status != "all") {
        query += 'and tot.PUSH_STATUS = \'' + push_status + '\' ';
    }
    if (ctn != '') {
        query += 'and tot.CTN like \"%' + ctn + '%\" ';
    }
    if (p_ctn != '') {
        query += 'and tot.P_CUST_CTN like \"%' + p_ctn + '%\"';
    }

    //query += ' order by tot.INSERT_DATE desc limit ' + start + ',' + pageSize + '';
    query += ' order by tot.INSERT_DATE desc';
    if (type != 'excel')
        query += ' limit ' + start + ',' + pageSize;

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {

            var excepts = [];

            if (type == 'excel') {
                var filename = fromdate + "_" + t_date + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename, excepts);
            } else {
                response.send(results);
            }
        }
    });
});

app.all('/pushCeckView', function(request, response) {
    logger.info('Path change : /pushCeckView');

    var valiable = request.param('valiable');

    fs.readFile('push_check_view.html', 'utf8', function(error, data) {

        response.writeHead(200, {
            'Content-Type:': 'text/html'
        });

        response.end(data);
    });

});

app.get('/location', function(request, response) {
    logger.info('Path change : /location : ' + request.param('CUST_CTN'));

    var P_CUST_CTN = request.param('CUST_CTN');
    var P_INSERT_DATE = request.param('INSERT_DATE');
    var query = 'select LOCATION_X, LOCATION_Y from TB_LOCATION_HISTORY where P_CUST_CTN=\'' + P_CUST_CTN + '\' and P_INSERT_DATE=\'' + P_INSERT_DATE + '\' order by INSERT_DATE ';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(decryptArray(results));
            //response.send(results);
        }
    });
});


//지도뷰어 추가  (MAP_STATUS : 1,3) [171023 jhlee] PCVIEW_STATUS :  5(서비스x), 7(서비스중)
app.all('/loc/admin/mapping/insert', function(request, response) {
    logger.info('Path change : /locAdminMappingInsert : ' + request.param('DEV_KEY'));

    var P_CUST_CTN = request.param('P_CUST_CTN');
    var P_INSERT_DATE = request.param('P_INSERT_DATE');
    var DEV_KEY = request.param('DEV_KEY');
    var MAP_STATUS = request.param('MAP_STATUS');

    var query = 'INSERT INTO TB_LOCATION_ADMIN_MAPPING (P_CUST_CTN, P_INSERT_DATE, STATUS, ADMIN_ID, INSERT_DATE ) VALUES (?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"))';
    var queryResult = dbConn.query(query, [P_CUST_CTN, P_INSERT_DATE, MAP_STATUS, DEV_KEY], function(error, result) {
        logger.info('Query:', queryResult.sql);
        if (error) {
            logger.error('DB Error', error);
        } else {
            response.send({"P_CUST_CTN": P_CUST_CTN});
        }
    });
});

//작업 체크박스 수정  (MAP_STATUS : 1,3) [171023 jhlee] PCVIEW_STATUS :  5(서비스x), 7(서비스중)
app.post('/locAdminMappingModify', function(request, response) {
    logger.info('Path change : /locAdminMappingModify : ' + request.param('DEV_KEY'));

    var P_CUST_CTN = request.param('P_CUST_CTN');
    var P_INSERT_DATE = request.param('P_INSERT_DATE');
    var DEV_KEY = request.param('DEV_KEY');
    var MAP_STATUS = request.param('MAP_STATUS');
    var query = 'UPDATE TB_LOCATION_ADMIN_MAPPING SET STATUS=\'' + MAP_STATUS + '\' WHERE P_CUST_CTN=\'' + P_CUST_CTN + '\' AND P_INSERT_DATE=\'' + P_INSERT_DATE + '\' AND ADMIN_ID=\'' + DEV_KEY + '\' '
    if(MAP_STATUS<4){
        query+= ' AND STATUS <4 ORDER BY INSERT_DATE desc limit 1';
    }else{
        query+= ' AND STATUS >4 ORDER BY INSERT_DATE desc limit 1';
    }

    dbConn.query(query,function(error, result) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error', error);
        } else {
            response.send({"P_CUST_CTN": P_CUST_CTN});
        }
    });
});



app.get('/lastlocation', function(request, response) {
    logger.info('Path change : /lastlocation : ' + request.param('CUST_CTN'));

    var P_CUST_CTN = request.param('CUST_CTN');
    var P_INSERT_DATE = request.param('INSERT_DATE');
    var query = 'select LOCATION_X, LOCATION_Y from TB_LOCATION_HISTORY where P_CUST_CTN=\'' + P_CUST_CTN + '\' and P_INSERT_DATE=\'' + P_INSERT_DATE + '\' order by INSERT_DATE desc limit 1';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            results = decryptArray(results);
            response.send(results[0]);
        }
    });
});


app.get('/requestAlarm', CheckAuth, function(request, response) {
    logger.info('Path change : /requestAlarm');

    var code_01 = request.param('CODE_01');
    var code_02 = request.param('CODE_02');
    var code_03 = request.param('CODE_03');
    var query;
    if (request.session.code_01 == '900' && request.session.code_02 == '999') {
        query = 'select count(*) as cnt';
    } else {

        if (code_01 == request.session.code_01 && code_02 == request.session.code_02 && code_03 == request.session.code_03) {
            query = 'select count(*) as cnt';
        } else {
            query = 'select 0 as cnt';
        }
        //query = 'select COUNT(1) as cnt from TB_ADMIN where CODE_01=\'' + code_01 + '\' AND CODE_02=\'' + code_02 + '\' AND CODE_03=\'' + code_03 + '\' AND ADMIN_ID=\'' + request.session.userid + '\' ';
    }

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });
});

app.get('/requestAlarm/:id', CheckAuth, function(request, response) {
    logger.info('Path change : /requestAlarm' + request.param('id'));

    var urlquery = querystring.parse(url.parse(request.url).query);
    var code_01 = urlquery.code_01;
    var code_02 = urlquery.code_02;
    var code_03 = urlquery.code_03;
    var query;
    if (request.session.code_01 == '900' && request.session.code_02 == '999') {
        query = 'select count(*) as cnt';
    } else {

        if (code_01 == request.session.code_01 && code_02 == request.session.code_02 && code_03 == request.session.code_03) {
            query = 'select count(*) as cnt';
        } else {
            query = 'select 0 as cnt';
        }
    }

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.get('/fileDownload', function(request, response) {
    logger.info('Path change : /fileDownload');

    var filename = request.param('fileName');
        //2019.02.13 디렉토리 접근 차단
        // filename = filename.split("../").join("");
        // filename = filename.split("/").join("");
    
    var query = 'SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'UP DIR\''
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (typeof results[0] != 'undefined') {

                var dir = results[0].C_VALUE;
                var file = dir + "/" + filename;
                //logger.info(file);
                response.download(file);
            } else {
                logger.error('cannot find download directory');
            }
        }
    });
});


app.get('/loghistory', CheckAuthControl, function(request, response) {

    logger.info('Path change : /loghistory');
    var code3 = request.session.code_03;
    fs.readFile('html/login_history.html', 'utf8', function(error, data) {
 
        //var query = 'select * from TB_LOGIN_HISTORY';
        var query = util.format('SELECT a.* FROM TB_LOGIN_HISTORY a' +
            ' LEFT JOIN TB_ADMIN b on a.ADMIN_ID = b.ADMIN_ID' +
            ' WHERE b.CODE_03 = \'%s\'', code3);
 
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
 
            response.send(ejs.render(data, {
                data: results
            }));
 
        });
 
    });
 });


app.get('/streaming', CheckAuthControl, function(request, response) {

    logger.info('Path change : /streaming');

    fs.readFile('html/streaming.html', 'utf8', function(error, data) {

        var query = 'select * from TB_VOD_LST';

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);

            response.send(ejs.render(data, {
                data: results
            }));

        });

    });
});

app.get('/streamingPaging', function(request, response) {

    logger.info('Path change : /streaming');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var f_date = request.param('f_date') + '000000';
    var t_date = request.param('t_date') + '235959';

    var query = 'select * ';
    query += 'from TB_VOD_LST where INSERT_DATE > \'' + f_date + '\' and INSERT_DATE < \'' + t_date + '\' order by INSERT_DATE desc ';
    query += 'limit ' + start + ',' + pageSize + '';

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }

    });
});

app.get('/streamingCount', function(request, response) {

    var f_date = request.param('f_date') + '000000';
    var t_date = request.param('t_date') + '235959';

    var query = 'select count(*) as cnt from TB_VOD_LST ';
    query += ' where INSERT_DATE > \'' + f_date + '\' and INSERT_DATE < \'' + t_date + '\'';

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }

    });

});


app.get('/loginList', CheckAuth, function(request, response) {

    fs.readFile('login_history.html', function(error, data) {

        var custCTN = request.param('custCTN');
        var insertDate = [request.param('insertDate')];

        var query = 'select * from TB_LOGIN_HISTORY order by INSERT_DATE desc';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/appDownloadLink', function(request, response) {
    logger.info('Path move : /appDownloadLink', request.param('fileName'));

    var query = 'SELECT * FROM TB_VERSION INNER JOIN TB_COMMON on C_NAME = \'APK DIR\' ORDER BY TYPE ';
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            if (typeof results[0] != 'undefined') {
                var fileName = request.param('fileName'); //1:일반 LTE망용 2:설치방법 3:LTE전용망용
                var file='';
                if (fileName == '1' || typeof fileName == "undefined") {
                    file = results[0].C_VALUE + "/" + results[0].APKNM;
                }else if(fileName ==2){
                    file = results[0].C_VALUE + "/" + request.query.file;
                }else if(fileName ==3) {
                } else if(fileName == '2') {
                    file = results[0].C_VALUE + "/LGU+_LTE_영상중계_서비스_매뉴얼v1.2.pdf"
                } else if(fileName == '3') {
                    file = results[0].C_VALUE + "/" + results[1].APKNM;
                }
                // } else if(fileName == '4') {
                //     file = results[0].C_VALUE + "/" + results[2].APKNM;
                // }

                response.download(file);
            } else {
                logger.error('cannot find download directory');
            }
        }
    });
});

app.get('/liveViewerDownload', function(request, response) {
    logger.info('Path move : /liveViewerDownload');

    var query = "SELECT * FROM TB_VERSION INNER JOIN TB_COMMON on C_NAME = 'APK DIR' WHERE TYPE = '3' ORDER BY TYPE";
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            var file = results[0].C_VALUE + "/" + results[0].APKNM;
            response.download(file);
        }
    });
});

app.get('/searchId', CheckAuth, function(request, response) {

    fs.readFile('login_history.html', function(error, data) {

        var id = request.param('id');

        var query = 'select * from TB_LOGIN_HISTORY where ADMIN_ID= \'' + id + '\' order by INSERT_DATE desc';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/historyCount', function(request, response) {

    dbConn.query('select count(*) as cnt from TB_LOGIN_HISTORY', function(error, results) {

        response.send(results[0]);

    });

});

app.post('/searchCount', function(request, response) {

    var id = request.param('id');
    var f_date = request.param('f_date') + '000000';
    var t_date = request.param('t_date') + '235959';
    var code03 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_LOGIN_HISTORY a left join TB_ADMIN b on a.ADMIN_ID = b.ADMIN_ID ';

    if (id == '' || id == null) {
        query += ' where a.INSERT_DATE > \'' + f_date + '\' and a.INSERT_DATE < \'' + t_date + '\'';
    } else {
        query += ' where a.INSERT_DATE > \'' + f_date + '\' and a.INSERT_DATE < \'' + t_date + '\' and a.ADMIN_ID like \"%' + id + '%\"';
    }
    query += ' and b.CODE_03 = \'' + code03 + '\'';

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }

    });

});

app.get('/historyPaging', function(request, response) {

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var id = request.param('id');
    var f_date = request.param('f_date') + '000000';
    var t_date = request.param('t_date') + '235959';
    var type = request.param('type');
    var code3 = request.session.code_03;

    if (id == null || id == '') {
        var query = 'select a.INSERT_DATE as LOGIN_INSERT_DATE, a.UPDATE_DATE as LOGIN_UPDATE_DATE, a.ADMIN_ID, IP_ADDR, AGENT,';
        query += ' case a.STATUS when "1" then "로그인" when "2" then "로그아웃" end as LOGIN_STATUS, SEQ ';
        query += ' from TB_LOGIN_HISTORY a left join TB_ADMIN b on a.ADMIN_ID = b.ADMIN_ID';
        query += ' where a.INSERT_DATE > \'' + f_date + '\' and a.INSERT_DATE < \'' + t_date + '\' and b.CODE_03 = \'' + code3 + '\' order by a.INSERT_DATE desc ';
        if (type != 'excel') {
            query += 'limit ' + start + ',' + pageSize + '';
        }
    } else {
        var query = 'select a.INSERT_DATE as LOGIN_INSERT_DATE, a.UPDATE_DATE as LOGIN_UPDATE_DATE, a.ADMIN_ID, IP_ADDR, AGENT, ';
        query += ' case a.STATUS when "1" then "로그인" when "2" then "로그아웃" end as LOGIN_STATUS, SEQ ';
        query += ' from TB_LOGIN_HISTORY a left join TB_ADMIN b on a.ADMIN_ID = b.ADMIN_ID';
        query += ' where a.ADMIN_ID like \"%' + id + '%\" and a.INSERT_DATE > \'' + f_date + '\' and a.INSERT_DATE < \'' + t_date + '\' and b.CODE_03 = \'' + code3 + '\' order by a.INSERT_DATE desc ';
        if (type != 'excel') {
            query += 'limit ' + start + ',' + pageSize + '';
        }
    }

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results, fields) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            if (type == 'excel') {
                var filename = "LOGIN_HISTORY.xlsx";
                var excepts = [];
                excepts.push('SEQ');

                utilLib.excelExport(request, response, results, fields, filename, excepts);

            } else {
                console.log(results);
                response.send(results);
            }
        }

    });
});

app.get('/stats', CheckAuth, function(request, response) {
    logger.info('Path change : /stats');

    fs.readFile('html/stats.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/stats_trafic', CheckAuth, function(request, response) {
    logger.info('Path change : /stats');

    fs.readFile('stats_trafic.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/stats_colum00', function(request, response) {
    logger.info('Path change : /stats_colum00');

    var g = request.param('g');
    var t = request.param('type');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var fdate2 = request.param('fdate');
    var tdate2 = request.param('tdate');

    var code03 = request.session.code_03;

    var tableNm, statsNm;
    if (g == "1") {
        tableNm = "TB_STAT_SERVICE_5MIN";
        statsNm = "서비스 5분 통계";
    } else if (g == "2") {
        tableNm = "TB_STAT_VCALL_SERVICE_5MIN";
        statsNm = "VOICE 5분통계";
    } else if (g == "3") {
        tableNm = "TB_STAT_STB_SERVICE_5MIN  ";
        statsNm = "STB 5분통계";
    } else if (g == "4") {
        tableNm = "TB_STAT_SMS_SERVICE_5MIN";
        statsNm = "SMS 5분통계";
    } else if (g == "5") {
        tableNm = "TB_STAT_PUSH_SERVICE_5MIN";
        statsNm = "PUSH 5분통계";
    } else if (g == "6") {
        tableNm = "TB_STAT_VIEW_SERVICE_5MIN"
        statsNm = "PC Viewer 5분통계";
    } else if (g == "7") {
        tableNm = "TB_STAT_VIEW_SERVICE_5MIN"
        statsNm = "MOBILE 5분통계";
    }

    var WHERE = " TM >= '" + fdate2 + "' AND TM <= '" + tdate2 + "' ";

    var query;
    query = 'SELECT';
    if (g == "5") {
        query += ' Tm ,sum(TRIALCNT) as sum_trial, sum(SUCCNT) as sum_suc ,sum(GCM_SUCCNT) as sum_gcm';
    } else {
        query += ' Tm ,sum(TRIALCNT) as sum_trial, sum(SUCCNT) as sum_suc';
    }
    query += ' FROM';
    query += ' (SELECT *';
    query += '     FROM(';
    if (g == "5") {
        query += "         SELECT DATE_FORMAT(STAT_TIME,'%Y-%m-%d') as Tm, TRIALCNT, SUCCNT, GCM_SUCCNT ,CODE_03";
    } else {
        query += "         SELECT DATE_FORMAT(STAT_TIME,'%Y-%m-%d') as Tm, TRIALCNT, SUCCNT ,CODE_03";
    }
    query += '         FROM ' + tableNm;

    if (g == '6') { //pc viewer
        query += ' where DEV_TYPE="3"';
    } else if (g == '7') { //mobile
        query += ' where DEV_TYPE="1"';
    }
    query += '         ) A ';
    query += '     ) B ';
    query += ' WHERE ' + WHERE;
    query += ' and CODE_03 = \'' + code03 + '\'';
    query += ' GROUP BY Tm ORDER BY Tm';

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (t == "excel") {
                var filename = fdate2 + "_" + tdate2 + "_" + statsNm + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {

                response.send(results);
            }
        }
    });
});

app.get('/stats_service_err', CheckAuth, function(request, response) {
    logger.info('Path change : /stats_service_err');
    fs.readFile('html/stats_service_err.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/stats_pc_err', CheckAuth, function(request, response) {
    logger.info('Path change : /stats_pc_err');
    fs.readFile('html/stats_pc_err.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/stats_stb_err', CheckAuth, function(request, response) {
    logger.info('Path change : /stats_stb_err');
    fs.readFile('html/stats_stb_err.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/stats_mobile_err', CheckAuth, function(request, response) {
    logger.info('Path change : /stats_mobile_err');
    fs.readFile('html/stats_mobile_err.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


app.get('/stats_service_err_data', function(request, response) {
    logger.info('Path change : /stats_service_err_data');

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT";
    if (g == 1) { // 관제탑 별
        gubun = 'control';
        if (t == 'EXCEL') {
            //query += " b.CODE_NM as NM";
            query += " b.CTL_NM as NM";
        } else {
            //query += " a.CODE_02, b.CODE_NM as NM";
            query += " a.CODE_02, b.CTL_NM as NM";
        }
    } else if (g == 2) { // 단말 별
        gubun = 'model';
        if (t == 'EXCEL')
            query += " DEV_MODEL";
        else
            query += " DEV_MODEL as NM";
    } else if (g == 3) { // OS 별
        gubun = 'osversion';
        if (t == 'EXCEL')
            query += " DEV_OS";
        else
            query += " DEV_OS as NM";
    } else { // 발신자 별
        gubun = 'caller';
        if (t == 'EXCEL')
            query += " CUST_CTN";
        else
            query += " CUST_CTN as NM";
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // table
    if (g == 1) { // 관제탑 별
        //query += " FROM TB_TERMINAL_IMAGE_TRANS a left join TB_DEPT_DEPTH b on a.CODE_02 = b.CODE";
        query += " FROM TB_TERMINAL_IMAGE_TRANS a left join (SELECT * FROM TB_CONTROL b WHERE CODE_03 = '" + code03 + "') b on a.CODE_02 = b.CODE_02";
    } else { // 단말 별, OS 별, 발신자 별
        query += " FROM TB_TERMINAL_IMAGE_TRANS a";
    }

    // where
    query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "' and DEFECT_CODE is not null";

    // 기업별
    if (g == 1)
        query += ' and a.CODE_03 = \'' + code03 + '\'';
    else
        query += ' and CODE_03 = \'' + code03 + '\'';

    // group by
    if (g == 1) { // 관제탑 별
        query += " GROUP BY CODE_02,CTL_NM";
    } else if (g == 2) { // 단말 모델 별
        query += " GROUP BY DEV_MODEL";
    } else if (g == 3) { // OS 버전 별
        query += " GROUP BY DEV_OS";
    } else { // 발신자 별
        query += " GROUP BY CUST_CTN";
    }

    query += " HAVING ERR_CNT > 0"

    // order by
    query += " ORDER BY ERR_CNT DESC";

    if (t == 'GRAPH') // graph, list
        query += " LIMIT 10";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

// 기간별 통계
app.get('/stats_service_err_period', function(request, response) {
    logger.info('Path change : /stats_service_err_period');

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT Tm";
    if (g == 1) { // control
        query += ",CODE_02, CTL_NM as CODE_NM";
        gubun = 'control';
    } else if (g == 2) {
        query += ",ifnull(DEV_MODEL, '') as DEV_MODEL";
        gubun = 'model';
    } else if (g == 3) {
        query += ",ifnull(DEV_OS, '') as DEV_OS";
        gubun = 'osversion';
    } else {
        query += ",CUST_CTN";
        gubun = 'caller';
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // from
    query += " FROM (";
    if (g == 1) {

        query += " SELECT DATE_FORMAT(a.INSERT_DATE,'%Y-%m-%d') as Tm, DEFECT_CODE, a.CODE_02, CTL_NM ,a.CODE_03";
        query += " FROM TB_TERMINAL_IMAGE_TRANS a left join (SELECT * FROM TB_CONTROL WHERE CODE_03 = '" + code03 + "') b on a.CODE_02 = b.CODE_02";
        query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "'";
        query += " AND a.CODE_03 = '" + code03 + "'";
    } else if (g == 2) {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,DEV_MODEL,DEFECT_CODE ,CODE_03";
        query += " FROM TB_TERMINAL_IMAGE_TRANS";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND CODE_03 = '" + code03 + "'";
    } else if (g == 3) {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,DEV_OS,DEFECT_CODE, CODE_03";
        query += " FROM TB_TERMINAL_IMAGE_TRANS";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND CODE_03 = '" + code03 + "'";
    } else {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,CUST_CTN,DEFECT_CODE, CODE_03";
        query += " FROM TB_TERMINAL_IMAGE_TRANS";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND CODE_03 = '" + code03 + "'";
    }
    query += ") A";

    // group by
    query += " GROUP BY Tm";
    if (g == 1) {
        query += ",CODE_02,CTL_NM";
    } else if (g == 2) {
        query += ",DEV_MODEL";
    } else if (g == 3) {
        query += ",DEV_OS";
    } else {
        query += ",CUST_CTN";
    }

    query += " HAVING ERR_CNT > 0"

    // order by
    query += " ORDER BY Tm desc";

    query += ",ERR_CNT desc";

    if (g == 1) {
        query += ",CODE_02";
    } else if (g == 2) {
        query += ",DEV_MODEL desc";
    } else if (g == 3) {
        query += ",DEV_OS desc";
    } else {
        query += ",CUST_CTN";
    }

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            var excepts = [];
            excepts.push('CODE_02');

            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename, excepts);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_service_err_one', function(request, response) {
    logger.info('Path change : /stats_service_err_one');

    var fdate1 = request.param('curdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('curdate').replace(/-/g, "") + "235959";

    var curdate = request.param('curdate');

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var query = "SELECT a.DEFECT_CODE,c.REASON,count(a.DEFECT_CODE) as ERR_CNT";

    // table
    if (g == 1) {
        query += " FROM TB_TERMINAL_IMAGE_TRANS a left join (SELECT * FROM TB_CONTROL WHERE CODE_03 = '" + code03 + "') b ON a.CODE_02 = b.CODE_02";
    } else {
        query += " FROM TB_TERMINAL_IMAGE_TRANS a";
    }
    query += " left join TB_DEFECT_CODE c on a.DEFECT_CODE = c.DEFECT_CODE";

    // where
    query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "' and a.DEFECT_CODE >= '1000'";
    if (g == 1) { // 관제탑 별
        query += " and a.CODE_03 = '" + code03 + "' and b.CTL_NM = '" + request.param('condition') + "' ";
    } else if (g == 2) { // 단말 모델 별
        query += " and DEV_MODEL = '" + request.param('condition') + "' ";
    } else if (g == 3) { // OS 버전 별
        query += " and DEV_OS = '" + request.param('condition') + "' ";
    } else { // 발신자 별
        query += " and CUST_CTN = '" + request.param('condition') + "' ";
    }

    // 기업별
    query += ' AND a.CODE_03 = \'' + code03 + '\'';

    // group by
    query += " GROUP BY a.DEFECT_CODE";

    // order by
    query += " ORDER BY ERR_CNT DESC";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (t == 'EXCEL') {
                var filename = curdate + "_" + request.param('condition') + ".xlsx";
                //var filename = curdate + "_" + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_stb_err_data', function (request, response) {
	logger.info('Path change : /stats_stb_err_data');

    var fdate1 = request.param('fdate').replace(/-/g, "")+"000000";
    var tdate1 = request.param('tdate').replace(/-/g, "")+"235959";

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var query = "SELECT";
    if (g==2){			// STB MAC 별
    	if (t=='EXCEL')
    		query += " a.STB_MAC_ADDR";
    	else
    		query += " a.STB_MAC_ADDR as NM";
    }else if (g==3){	// STB 모델 별
    	if (t=='EXCEL')
	    	query += " a.STB_MODEL";
	    else
	    	query += " a.STB_MODEL as NM";
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // table
   	query += " FROM TB_STB_SERVICE a LEFT JOIN TB_STB_INFO b ON a.STB_MAC_ADDR = b.STB_MAC_ADDR";

	// where
    query += " WHERE INSERT_DATE >= '"+fdate1+"' AND INSERT_DATE <= '"+tdate1+"' and DEFECT_CODE is not null and STB_DEPT_CODE_03 = '" + code03 + "'";

    // group by
    var gubun;
    if (g==2){			// STB MAC 별
	    gubun = 'stb_mac';
	    query += " GROUP BY a.STB_MAC_ADDR ";
    }else if (g==3){	// STB 모델 별
	    gubun = 'stb_model';
	    query += " GROUP BY a.STB_MODEL";
    }

    query += " HAVING ERR_CNT > 0";

    // order by
    query += " ORDER BY ERR_CNT DESC";

    if (t == 'GRAPH') // graph, list
    	query += " LIMIT 10";

    dbConn.query(query, function (error, results, fields) {

    	logger.info('Query:', query);
        if (error){
        	logger.error('DB Error:', error);
        }else {
            if (t == 'EXCEL'){
            	var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
				utilLib.excelExport(request, response, results, fields, filename);
			} else {
	            response.send(results);
			}
        }
    });
});

// 기간별 통계
app.get('/stats_stb_err_period', function (request, response) {
	logger.info('Path change : /stats_stb_err_period');

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var fdate1 = request.param('fdate').replace(/-/g, "")+"000000";
    var tdate1 = request.param('tdate').replace(/-/g, "")+"235959";

    var g = request.param('g');
    var t = request.param('T');
    //var period = request.param('p');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT Tm";
    if (g == 2){  // control
    	query += ",STB_MAC_ADDR";
    	gubun = 'control';
    }else if (g == 3){
    	query += ",ifnull(STB_MODEL, '') as STB_MODEL";
    	gubun = 'stbmodel';
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // from
    query += " FROM (";
    if (g == 2){

	    query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,DEFECT_CODE,a.STB_MAC_ADDR";
	    query += " FROM TB_STB_SERVICE a LEFT JOIN TB_STB_INFO b ON a.STB_MAC_ADDR = b.STB_MAC_ADDR";
		query += " WHERE INSERT_DATE >= '"+fdate1+"' AND INSERT_DATE <= '"+tdate1+"' AND STB_DEPT_CODE_03 = '" + code03 + "' ";
    }else if (g == 3){

	    query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,a.STB_MODEL,DEFECT_CODE";
	    query += " FROM TB_STB_SERVICE a LEFT JOIN TB_STB_INFO b ON a.STB_MAC_ADDR = b.STB_MAC_ADDR";
		query += " WHERE INSERT_DATE >= '"+fdate1+"' AND INSERT_DATE <= '"+tdate1+"' AND STB_DEPT_CODE_03 = '" + code03 + "' ";
	}
    query += ") A";

    // group by
    query += " GROUP BY Tm";
    if (g == 2){
    	query += ",STB_MAC_ADDR";
    }else if (g == 3){
    	query += ",STB_MODEL";
    }

    query += " HAVING ERR_CNT > 0";

    // order by
    query += " ORDER BY Tm desc ";

    query += ",ERR_CNT desc";

    if (g == 3)
	    query += ",STB_MODEL desc";


    dbConn.query(query, function (error, results, fields) {

    	logger.info('Query:', query);
        if (error){
        	logger.error('DB Error:', error);
        }else {
        	

            if (t == 'EXCEL'){
            	var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
				utilLib.excelExport(request, response, results, fields, filename);
			} else {
	            response.send(results);
			}
        }
    });
});

app.get('/stats_stb_err_one', function(request, response) {
    logger.info('Path change : /stats_stb_err_one');


    var fdate1 = request.param('curdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('curdate').replace(/-/g, "") + "235959";

    var curdate = request.param('curdate');

    var g = request.param('g');
    var t = request.param('T');

    // select
    var query = "SELECT a.DEFECT_CODE,c.REASON,count(a.DEFECT_CODE) as ERR_CNT";

    // table
    query += " FROM TB_STB_SERVICE a left join TB_DEFECT_CODE c on a.DEFECT_CODE = c.DEFECT_CODE";

    // where
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' and a.DEFECT_CODE is not null and a.DEFECT_CODE >= '1000'";
    if (g == 2) { // STB MAC 별
        query += " and STB_MAC_ADDR  = '" + request.param('condition') + "' ";
    } else if (g == 3) { // STB 모델 별
        query += " and STB_MODEL = '" + request.param('condition') + "' ";
    }

    // group by
    query += " GROUP BY a.DEFECT_CODE";

    // order by
    query += " ORDER BY ERR_CNT DESC";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            if (t == 'EXCEL') {
                var filename = curdate + "_" + request.param('condition') + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});


/* PC */
app.get('/stats_pc_err_data', function(request, response) {
    logger.info('Path change : /stats_pc_err_data');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT";
    if (g == 1) { // 관제탑 별
        gubun = '';
        //query += " a.CODE_02, b.CODE_NM as NM";
    } else if (g == 2) { // 계정별
        gubun = 'id';
        if (t == 'EXCEL')
            query += " DEV_KEY";
        else
            query += " DEV_KEY as NM";
    } else if (g == 3) { // pc 브라우저 별
        gubun = 'browser';
        if (t == 'EXCEL')
            query += " MODEL";
        else
            query += " MODEL as NM";
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // table
    query += " FROM TB_VIEW_SERVICE a left join TB_ADMIN b ON a.DEV_KEY = b.ADMIN_ID";

    // where
    query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "' and DEFECT_CODE is not null and DEV_TYPE = '3' and b.CODE_03 = '" + code03 + "'";

    // group by
    if (g == 1) { // 관제탑 별
        //query += " GROUP BY CODE_02";
    } else if (g == 2) { // 계정 별
        query += " GROUP BY DEV_KEY";
    } else if (g == 3) { // PC 브라우저 별
        query += " GROUP BY MODEL";
    } else { // 발신자 별
        query += " GROUP BY DEV_KEY";
    }

    query += " HAVING ERR_CNT > 0"

    // order by
    query += " ORDER BY ERR_CNT DESC";

    if (t == 'GRAPH') // graph, list
        query += " LIMIT 10";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_pc_err_period', function(request, response) {
    logger.info('Path change : /stats_pc_err_period');

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT Tm";
    if (g == 2) { // 계정 별
        query += ",ifnull(DEV_KEY, '') as DEV_KEY";
        gubun = 'id';
    } else if (g == 3) { // PC 브라우저 별
        query += ",ifnull(MODEL, '') as MODEL";
        gubun = 'model';
    }
    /*
    }else if (g == 4){
    	query += ",DEV_KEY";
    	gubun = 'id';
    }
    */
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // from
    query += " FROM (";
    if (g == 2) {

        query += " SELECT DATE_FORMAT(a.INSERT_DATE,'%Y-%m-%d') as Tm,DEV_KEY,DEFECT_CODE";
        query += " FROM TB_VIEW_SERVICE a left join TB_ADMIN b ON a.DEV_KEY = b.ADMIN_ID";
        query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "' AND DEV_TYPE='3'";
        query += " AND b.CODE_03 = '" + code03 + "'";
    } else if (g == 3) {

        query += " SELECT DATE_FORMAT(a.INSERT_DATE,'%Y-%m-%d') as Tm,MODEL,DEFECT_CODE";
        query += " FROM TB_VIEW_SERVICE a left join TB_ADMIN b ON a.DEV_KEY = b.ADMIN_ID";
        query += " WHERE a.INSERT_DATE >= '" + fdate1 + "' AND a.INSERT_DATE <= '" + tdate1 + "' AND DEV_TYPE='3'";
        query += " AND b.CODE_03 = '" + code03 + "'";
    }
    /*
    else if (g == 4){

	    query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,DEV_KEY,DEFECT_CODE";
	    query += " FROM TB_VIEW_SERVICE";
		query += " WHERE INSERT_DATE >= '"+fdate1+"' AND INSERT_DATE <= '"+tdate1+"' AND DEV_TYPE='3'";
	}
	*/
    query += ") A";

    // group by
    query += " GROUP BY Tm";
    if (g == 2) {
        query += ",DEV_KEY";
    } else if (g == 3) {
        query += ",MODEL";
    }
    /*
    else if (g == 4){
    	query += ",DEV_KEY";
	}
	*/

    query += " HAVING ERR_CNT > 0";

    // order by
    query += " ORDER BY Tm desc ";
    query += ",ERR_CNT desc";
    if (g == 2) {
        query += ",DEV_KEY desc";
    } else if (g == 3) {
        query += ",MODEL desc";
    }

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_pc_err_one', function(request, response) {
    logger.info('Path change : /stats_pc_err_one');

    var fdate1 = request.param('curdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('curdate').replace(/-/g, "") + "235959";

    var curdate = request.param('curdate');

    var g = request.param('g');
    var t = request.param('T');

    // select
    var query = "SELECT a.DEFECT_CODE,c.REASON,count(a.DEFECT_CODE) as ERR_CNT";

    // table
    query += " FROM TB_VIEW_SERVICE a left join TB_DEFECT_CODE c on a.DEFECT_CODE = c.DEFECT_CODE";

    // where
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' and a.DEFECT_CODE is not null and a.DEFECT_CODE >= '1000'";
    if (g == 1) { // 관제탑 별
        //query += " and CODE_02 = '"+request.param('condition')+"' ";
    } else if (g == 2) { // 계정 별
        query += " and DEV_KEY = '" + request.param('condition') + "' and DEV_TYPE = '3' ";
    } else if (g == 3) { // PC 브라우저 별
        query += " and MODEL = '" + request.param('condition') + "' and DEV_TYPE = '3' ";
    } else { // 발신자 별
        query += " and DEV_KEY = '" + request.param('condition') + "' and DEV_TYPE = '3' ";
    }

    // group by
    query += " GROUP BY a.DEFECT_CODE";

    // order by
    query += " ORDER BY ERR_CNT DESC";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            if (t == 'EXCEL') {
                var filename = curdate + "_" + request.param('condition') + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});
/* */

app.get('/stats_mobile_err_data', function(request, response) {
    logger.info('Path change : /stats_mobile_err_data');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT";
    if (g == 1) { // 관제탑 별
        gubun = '';
        //query += " a.CODE_02, b.CODE_NM as NM";
    } else if (g == 2) { // 단말 모델 별
        gubun = 'model';
        if (t == 'EXCEL')
            query += " MODEL";
        else
            query += " MODEL as NM";
    } else if (g == 3) { // 단말 OS 별
        gubun = 'osversion';
        if (t == 'EXCEL')
            query += " VERSION";
        else
            query += " VERSION as NM";
    } else { // 수신자 별
        gubun = 'receiver';
        if (t == 'EXCEL')
            query += " DEV_KEY";
        else
            query += " DEV_KEY as NM";
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // table
    query += " FROM TB_VIEW_SERVICE a left join TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN";

    // where
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' and DEFECT_CODE is not null and DEV_TYPE = '1'";
    query += " and b.DEPT_CODE_03 = '" + code03 + "'";
    /*
	if (g==2){
		query += " and MODEL <> ''";
	}else if (g==3){
		query += " and VERSION <> ''";
	}else if (g==4){
		query += " and DEV_KEY <> ''";
	}
	*/

    // group by
    if (g == 1) { // 관제탑 별
        //query += " GROUP BY CODE_02";
    } else if (g == 2) { // 단말 모델 별
        query += " GROUP BY MODEL";
    } else if (g == 3) { // OS 버전 별
        query += " GROUP BY VERSION";
    } else { // 발신자 별
        query += " GROUP BY DEV_KEY";
    }

    query += ' HAVING ERR_CNT > 0';

    // order by
    query += " ORDER BY ERR_CNT DESC";

    if (t == 'GRAPH') // graph, list
        query += " LIMIT 10";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});



// 기간별 통계
app.get('/stats_mobile_err_period', function(request, response) {
    logger.info('Path change : /stats_mobile_err_period');

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var gubun;
    var query = "SELECT Tm";
    if (g == 2) { // 단말모델 별
        query += ",ifnull(MODEL, '') as MODEL";
        gubun = 'MODEL';
    } else if (g == 3) { // 단말OS 별
        query += ",ifnull(VERSION, '') as VERSION";
        gubun = 'VERSION';
    } else if (g == 4) {
        query += ",DEV_KEY"; // 수신자 별
        gubun = 'RECV_CTN';
    }
    query += ",count(DEFECT_CODE) as TRI_CNT, count(if(DEFECT_CODE < '1000', DEFECT_CODE, NULL)) as SUC_CNT, count(if(DEFECT_CODE >= '1000', DEFECT_CODE, NULL)) as ERR_CNT";

    // from
    query += " FROM (";
    if (g == 2) {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,MODEL,DEFECT_CODE";
        query += " FROM TB_VIEW_SERVICE a left join TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' AND DEV_TYPE='1'";
        query += " AND b.DEPT_CODE_03 = '" + code03 + "'";
    } else if (g == 3) {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,VERSION,DEFECT_CODE";
        query += " FROM TB_VIEW_SERVICE a left join TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' AND DEV_TYPE='1'";
        query += " AND b.DEPT_CODE_03 = '" + code03 + "'";
    } else if (g == 4) {

        query += " SELECT DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm,DEV_KEY,DEFECT_CODE";
        query += " FROM TB_VIEW_SERVICE a left join TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN";
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' AND DEV_TYPE='1'";
        query += " AND b.DEPT_CODE_03 = '" + code03 + "'";
    }
    query += ") A";

    // group by
    query += " GROUP BY Tm";
    if (g == 2) {
        query += ",MODEL";
    } else if (g == 3) {
        query += ",VERSION";
    } else if (g == 4) {
        query += ",DEV_KEY";
    }

    query += ' HAVING ERR_CNT > 0';

    // order by
    query += " ORDER BY Tm desc ";
    query += ",ERR_CNT desc";

    if (g == 2) {
        query += ",MODEL desc";
    } else if (g == 3) {
        query += ",VERSION desc";
    }

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (t == 'EXCEL') {
                var filename = fdate + "_" + tdate + "_" + gubun + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_mobile_err_one', function(request, response) {
    logger.info('Path change : /stats_mobile_err_one');

    var fdate1 = request.param('curdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('curdate').replace(/-/g, "") + "235959";

    var curdate = request.param('curdate');

    var g = request.param('g');
    var t = request.param('T');

    var code03 = request.session.code_03;

    // select
    var query = "SELECT a.DEFECT_CODE,c.REASON,count(a.DEFECT_CODE) as ERR_CNT";

    // table
    query += " FROM TB_VIEW_SERVICE a left join TB_DEFECT_CODE c on a.DEFECT_CODE = c.DEFECT_CODE";
    query += " left join TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN"

    // where
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "' and a.DEFECT_CODE is not null and a.DEFECT_CODE >= '1000'";
    if (g == 1) { // 관제탑 별
        //query += " and CODE_02 = '"+request.param('condition')+"' ";
    } else if (g == 2) { // 단말 모델 별
        query += " and MODEL = '" + request.param('condition') + "' and DEV_TYPE = '1'";
    } else if (g == 3) { // OS 버전 별
        query += " and VERSION = '" + request.param('condition') + "' and DEV_TYPE = '1'";
    } else { // 발신자 별
        query += " and DEV_KEY = '" + request.param('condition') + "' and DEV_TYPE = '1'";
    }
    query += " and b.DEPT_CODE_03 = '" + code03 + "'";

    // group by
    query += " GROUP BY a.DEFECT_CODE";

    // order by
    query += " ORDER BY ERR_CNT DESC";

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            if (t == 'EXCEL') {
                var filename = curdate + "_" + request.param('condition') + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/stats_service_defectcode', function(request, response) {
    logger.info('Path change : /stats_service_defectcode');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var dev_type = request.param('TYPE');
    var defect_code1 = request.param('DEFECTCODE1');
    var defect_code2 = request.param('DEFECTCODE2');
    var defect_code3 = request.param('DEFECTCODE3');
    var defect_code4 = request.param('DEFECTCODE4');
    var defect_code5 = request.param('DEFECTCODE5');

    var table, where = '';

    if (dev_type == 'SERVICE') {
        table = " TB_TERMINAL_IMAGE_TRANS";
    } else if (dev_type == 'STB') {
        table = " TB_STB_SERVICE";
    } else if (dev_type == 'MOBILE' || dev_type == 'PC') {
        table = " TB_VIEW_SERVICE";
    }

    if (dev_type == 'MOBILE') {
        where = " AND DEV_TYPE = '1'";
    } else if (dev_type == 'PC') {
        where = " AND DEV_TYPE = '3'";
    }


    // select
    var query = 'SELECT s.Tm, s.TRI_CNT, ifnull(a.DEFECT_CODE1, 0) DEFECT_CODE1';
    if (defect_code2 != '') {
        query += ', ifnull(b.DEFECT_CODE2, 0) DEFECT_CODE2';
    }
    if (defect_code3 != '') {
        query += ', ifnull(c.DEFECT_CODE3, 0) DEFECT_CODE3';
    }
    if (defect_code4 != '') {
        query += ', ifnull(d.DEFECT_CODE4, 0) DEFECT_CODE4';
    }
    if (defect_code5 != '') {
        query += ', ifnull(e.DEFECT_CODE5, 0) DEFECT_CODE5';
    }

    // from
    query += " FROM";
    query += " (SELECT";
    query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as TRI_CNT";
    query += " FROM " + table;
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
    query += where;
    query += " GROUP BY Tm";
    query += " )s";
    query += " LEFT JOIN";
    query += " (SELECT";
    query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as DEFECT_CODE1";
    query += " FROM " + table;
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
    query += " AND DEFECT_CODE = '" + defect_code1 + "'";
    query += where;
    query += " GROUP BY Tm";
    query += " )a";
    query += " on s.Tm = a.Tm";

    if (defect_code2 != '') {
        query += " LEFT JOIN";
        query += " (SELECT";
        query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as DEFECT_CODE2";
        query += " FROM " + table;
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND DEFECT_CODE = '" + defect_code2 + "'";
        query += where;
        query += " GROUP BY Tm";
        query += " )b";
        query += " on s.Tm = b.Tm";
    }
    if (defect_code3 != '') {
        query += " LEFT JOIN";
        query += " (SELECT";
        query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as DEFECT_CODE3";
        query += " FROM " + table;
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND DEFECT_CODE = '" + defect_code3 + "'";
        query += where;
        query += " GROUP BY Tm";
        query += " )c";
        query += " on s.Tm = c.Tm";
    }
    if (defect_code4 != '') {
        query += " LEFT JOIN";
        query += " (SELECT";
        query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as DEFECT_CODE4";
        query += " FROM " + table;
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND DEFECT_CODE = '" + defect_code4 + "'";
        query += where;
        query += " GROUP BY Tm";
        query += " )d";
        query += " on s.Tm = d.Tm";
    }
    if (defect_code5 != '') {
        query += " LEFT JOIN";
        query += " (SELECT";
        query += " DATE_FORMAT(INSERT_DATE, '%Y-%m-%d') as Tm, count(DEFECT_CODE) as DEFECT_CODE5";
        query += " FROM " + table;
        query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
        query += " AND DEFECT_CODE = '" + defect_code5 + "'";
        query += where;
        query += " GROUP BY Tm";
        query += " )e";
        query += " on s.Tm = e.Tm";
    }

    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }
    });
});

app.get('/stats_service_defectcode_list', function(request, response) {
    logger.info('Path change : /stats_service_defectcode_list');

    var fdate1 = request.param('fdate').replace(/-/g, "") + "000000";
    var tdate1 = request.param('tdate').replace(/-/g, "") + "235959";

    var fdate = request.param('fdate');
    var tdate = request.param('tdate');

    var dev_type = request.param('TYPE');
    var excel = request.param('EXCEL');
    logger.info('excel : ', excel);

    var table, where = "";
    if (dev_type == 'SERVICE') {
        table = " TB_TERMINAL_IMAGE_TRANS";
    } else if (dev_type == 'STB') {
        table = " TB_STB_SERVICE";
    } else if (dev_type == 'MOBILE' || dev_type == 'PC') {
        table = " TB_VIEW_SERVICE";
    }

    if (dev_type == 'MOBILE') {
        where = " AND DEV_TYPE = '1'";
    } else if (dev_type == 'PC') {
        where = " AND DEV_TYPE = '3'";
    }

    var query = "SELECT Tm, DEFECT_CODE, ERR_CNT";
    query += " FROM";
    query += " (";
    query += " SELECT";
    query += " DATE_FORMAT(INSERT_DATE,'%Y-%m-%d') as Tm";
    query += " ,DEFECT_CODE";
    query += " ,count(DEFECT_CODE) as TRI_CNT";
    query += " ,count(if (DEFECT_CODE < '1000',DEFECT_CODE, NULL)) as SUC_CNT";
    query += " ,count(if (DEFECT_CODE >= '1000',DEFECT_CODE,NULL)) as ERR_CNT";
    query += " FROM " + table;
    query += " WHERE INSERT_DATE >= '" + fdate1 + "' AND INSERT_DATE <= '" + tdate1 + "'";
    query += where;
    query += " GROUP BY";
    query += " Tm";
    query += " ,DEFECT_CODE";
    query += " ) A";
    query += " HAVING DEFECT_CODE >= '1000'";
    query += ' order by Tm desc, ERR_CNT desc';


    dbConn.query(query, function(error, results, fields) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            if (excel == '1') {
                var filename = fdate + "_" + tdate + "_" + dev_type + "_" + "오류코드" + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }
    });
});

app.get('/tab', CheckAuth, function(request, response) {
    logger.info('Path change : /stats_err');
    fs.readFile('tab.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

//--------------------- SMS ----------------------------------
app.get('/serviceMultiSms', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceMultiVoice');

    fs.readFile('service_multi_sms.html', 'utf8', function(error, data) {

        response.send(data);
    });
});

app.get('/smsSend', CheckAuth, function(request, response) {
    fs.readFile('service_multi_sms.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.get('/adminList', function(request, response) {

    var id = request.session.userid;

    dbConn.query('select * from TB_ADMIN where ADMIN_ID = ?', [id], function(error, results) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results);
        }


    });
});

app.all('/smsSend', function(request, response) {

    var date = request.param('date');
    var id = request.session.userid;
    var nm = request.param('nm');
    var orgaddr = request.param('orgaddr');
    var destaddr = request.param('destaddr');
    var text = request.param('text');
    var sendflag = '1';
    var custCTN = request.param('custCTN');
    var insertDate = request.param('insertDate');

    var query = 'INSERT INTO TB_SMS_SERVICE (P_CUST_CTN, P_INSERT_DATE, CREATE_DATE, ADMIN_ID, ADMIN_NM, ORGADDR, DESTADDR, TEXT, SENDFLAG,ENDCODE) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [custCTN, insertDate, date, id, nm, orgaddr, destaddr, text, sendflag, 0], function(error, result) {
        if (error) {
            logger.error('DB Error', error);
        } else {
            
            response.send(orgaddr);
        }
    });
});

app.get('/sms', CheckAuth, function(request, response) {

    fs.readFile('sms_list.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/smsList', function(request, response) {
    logger.info('Path change : /smsList');

    fs.readFile('sms_list.html', function(error, data) {

        var custCTN = request.param('custCTN');
        var insertDate = [request.param('insertDate')];

        var query = 'select * from TB_SMS_SERVICE where P_CUST_CTN = \'' + custCTN + '\' and P_INSERT_DATE = \'' + insertDate + '\'';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/smsRecord', CheckAuth, function(request, response) {

    fs.readFile('sms_list.html', function(error, data) {

        var todate = request.param('todate');
        var fromdate = request.param('fromdate');

        var query = 'select * from TB_SMS_SERVICE where CREATE_DATE >= \'' + todate + '\' and CREATE_DATE < \'' + fromdate + '\' order by CREATE_DATE';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/smsDate', CheckAuth, function(request, response) {

    fs.readFile('sms_list.html', function(error, data) {

        var todate = request.param('todate');
        var fromdate = request.param('fromdate');
        var num = request.param('num');

        if (num == null || num == '') {
            var query = 'select * from TB_SMS_SERVICE where CREATE_DATE >= \'' + todate + '\' and CREATE_DATE < \'' + fromdate + '\' order by CREATE_DATE desc';
        } else {
            var query = 'select * from TB_SMS_SERVICE where CREATE_DATE >= \'' + todate + '\' and CREATE_DATE < \'' + fromdate + '\' and ORGADDR = \'' + num + '\' order by CREATE_DATE desc';

        }

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});

app.get('/smsNum', CheckAuth, function(request, response) {
    //console.log('/report', request.param('id'));
    logger.info('/smsNum');

    var num = request.param('num');

    fs.readFile('report.html', function(error, data) {

        var query = 'select * from TB_SMS_SERVICE where ORGADDR = \'' + num + '\' order by CREATE_DATE desc';

        dbConn.query(query, function(error, results) {

            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(results);
            }
        });
    });
});


app.get('/join', function(request, response) {
    logger.info('Path change : /join');

    fs.readFile('join.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.post('/manageAdmin', CheckAuthAccount, function(request, response) {
    logger.info('Path change : /manageAdmin');
    fs.readFile('html/manage_admin.html', 'utf8', function(error, data) {
        var session_id = request.session.userid;
        response.send(ejs.render(data, {
            data: {
                'session': session_id
            }
        }));
    });
});

app.get('/manageList', CheckAuth, function(request, response) {
    logger.info('Path change : /manageList');
    fs.readFile('html/manage_admin.html', 'utf8', function(error, data) {

        var query = 'select * from TB_ADMIN';

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);

            if (error) {
                logger.error('DB Error: ', error);
            } else {
                logger.info('DB Success: ', query);

                response.send(results);
            }

        });

    });
});

app.get('/manageAdd', CheckAuth, function(request, response) {
    logger.info('Path change : /manageAdd');
    fs.readFile('html/manage_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.all('/manageAdd', function(request, response) {
    logger.info('Path change : /manageAdd');
    var id = request.param('id');
    var pw = request.param('pw');
    var name = request.param('name');
    var dept = request.param('dept');
    var dept1 = request.param('dept1');
    var dept2 = request.param('dept2');
    var dept3 = request.session.code_03;
    var rank = request.param('rank');
    var lv = request.param('lv');
    var tel = request.param('tel');
    var date = request.param('date');
    var codeid = dept1 + dept2 + dept3;

    var query = util.format('INSERT INTO TB_ADMIN (ADMIN_ID, ADMIN_PW, ADMIN_NM, ADMIN_DEPT_NM, ADMIN_ARANK, ADMIN_LV, ADMIN_MOBILE_NUM, INSERT_DATE, CODE_01, CODE_02, CODE_03, CODE_ID, UPDATE_DATE) VALUES (\'%s\', %s, \'%s\', \'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\')', id, mysqlSha2(pw), name, dept, rank, lv, tel, date, dept1, dept2, dept3, codeid, date);

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send({
                "id": id
            });
        }
    });
});

app.get('/adminModifyList', function(request, response) {
    var id = request.param('id');

    dbConn.query('select ADMIN_LV,CODE_01,CODE_02,CODE_03 from TB_ADMIN where ADMIN_ID = ?', [id], function(error, results) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(results[0]);
        }

    });
});
app.post('/manageModify', function(request, response) {
    logger.info('Path change : /manageModify');
    var key_id = request.param('key_id');
    if (request.session.manageAccountCheck != 'success' || key_id == undefined) {
        response.redirect('/notAccess');
    }else{
    request.session.accountCheck = 'success';
    response.redirect(307, '/adminModifyPage');
    }
});

app.post('/adminModifyPage', CheckAuthAccount, function(request, response) {
    logger.info('Path change : /adminModifyPage');

    fs.readFile('html/admin_modify.html', 'utf8', function(error, data) {

        var key_id = request.param('key_id');
        var id = request.session.userid;
        logger.error('login id', key_id);
        if (key_id != undefined) {
            id = key_id;
        }
        var code03 = request.session.code_03;
        var query = 'select ADMIN_MOBILE_NUM, ADMIN_ARANK, ADMIN_NM, a.ADMIN_ID, CODE_01, CODE_02, CODE_03,c.ADMIN_ID CUSTOMER_ID, ' +
            '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM, ' +
            '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM2, ' +
            '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM3 ' +
            'from TB_ADMIN a LEFT JOIN TB_CUSTOMER c ON a.CODE_03 = c.CUSTOMER_CODE where a.ADMIN_ID = \'' + id + '\'';
        logger.info('Query:', query);
        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                if (error) {
                    logger.error('DB Error: ', error);
                } else {
                    result[0].USER_ID = request.session.userid;
                    response.send(ejs.render(data, {
                        data: result[0]
                    }));
                }
            }
        });
    });
});


app.all('/adminModify', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /adminModify');
    var id = request.param('id');
    var pw = request.param('pw');
    var name = request.param('name');
    var dept = request.param('dept');
    var rank = request.param('rank');
    var lv = request.param('lv');
    var tel = request.param('tel');
    var date = request.param('date');
    var dept1 = request.param('dept1');
    var dept2 = request.param('dept2');
    //var dept3 = request.param('dept3');
    var dept3 = request.session.code_03;
    var codeid = dept1 + dept2 + dept3;

    var query;
    // if (id == request.session.userid) {
    query = 'SELECT count(*) as cnt FROM TB_ADMIN WHERE ADMIN_ID = \'' + id + '\' and ADMIN_PW = ' + mysqlSha2(pw) + ' ';
    // } else {
    //     query = 'SELECT 1 cnt FROM DUAL';
    // }
    
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('Error:', error);
        } else {
            if (results[0].cnt == '1') {
                var query1 = util.format('UPDATE TB_ADMIN SET ADMIN_NM=\'%s\' , ADMIN_DEPT_NM=\'%s\', ADMIN_ARANK=\'%s\', ADMIN_LV=\'%s\', ADMIN_MOBILE_NUM=\'%s\', INSERT_DATE=\'%s\', CODE_01=\'%s\', CODE_02=\'%s\', CODE_03=\'%s\', CODE_ID=\'%s\'WHERE ADMIN_ID =\'%s\'', name, dept, rank, lv, tel, date, dept1, dept2, dept3, codeid, id);
                logger.info('Query:', query1);
                dbConn.query(query1, function(error, result) {
                    if (error) {
                        logger.error('DB Error: ', error);
                    } else {
                        
                        response.send({
                            "id": id
                        });
                    }
                });
            } else {
                logger.error('pw fail');
                response.send({
                    "error": "error_pw"
                });
            }
        }
    });
});

app.all('/isValidId', function(request, response) {
    logger.info('Path change: /isValidId');
    var id = request.param('id');
    dbConn.query('select count(*) as cnt from TB_ADMIN where ADMIN_ID = ?', [id], function(error, results) {

        response.send(results[0]);

    });
});


app.all('/isValidControl', function(request, response) {

    var ctl_tel_num = request.param('ctl_tel_num');

    dbConn.query('select count(*) as cnt from TB_CONTROL where CTL_TEL_NUM = ?', [ctl_tel_num], function(error, results) {

        response.send(results[0]);

    });
});

app.all('/adminPaging', function(request, response) {

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var lv = request.session.userlv;
    var id = request.session.userid;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var name = request.param('name');
    var id = request.param('id');

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');

    var type = request.param('type');

    var query = 'select a.ADMIN_ID, ADMIN_NM, ifnull(b.ADMIN_ID, \'\') CUSTOMER_ID, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_01 = b.CODE and b.GUBUN = "1" and CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_02 = b.CODE and b.GUBUN = "2" and CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_03 = b.CODE and b.GUBUN = "3" and CODE_03 = \'' + code3 + '\') as DEPT_NM3, ' +
        'case ADMIN_LV when "1" then "슈퍼관리자" when "2" then "제어관리자" when "3" then "일반관리자" end as ADMIN_LV, ' +
        'ADMIN_MOBILE_NUM ' +
        'from TB_ADMIN a ' +
        'LEFT JOIN TB_CUSTOMER b ON a.ADMIN_ID = b.ADMIN_ID ';

    query += 'where 1=1 AND CODE_03 = ';
    query += code3;
    query += ' ';

    if (lv == 1) {
        logger.info('super');

        if (code_01 != 'all') {
            query += 'and CODE_01=\'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and CODE_02=\'' + code_02 + '\' ';
        }
        if (name != '') {
            query += 'and a.ADMIN_NM like \"%' + name + '%\" ';
        }
        if (id != '') {
            query += 'and a.ADMIN_ID like \"%' + id + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and a.ADMIN_ID=\'' + id + '\' order by a.ADMIN_ID ';
    }

    if (type != 'excel') {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }


    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            if (type == 'excel') {
                var except = [];
                except.push('DEPT_NM3');

                var filename = "ADMIN.xlsx";
                utilLib.excelExport(request, response, results, fields, filename, except);
            } else {
                response.send(results);
            }

        }

    });
});

app.get('/adminsearchCount', function(request, response) {

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var name = request.param('name');
    var id = request.param('id');
    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_ADMIN ';
    query += ' where CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        logger.info('super');

        if (code_01 != 'all') {
            query += 'and CODE_01=\'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and CODE_02=\'' + code_02 + '\' ';
        }
        if (name != '') {
            query += 'and ADMIN_NM like \"%' + name + '%\" ';
        }
        if (id != '') {
            query += 'and ADMIN_ID like \"%' + id + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and ADMIN_ID=\'' + id + '\' order by ADMIN_ID ';
    }

    dbConn.query(query, function(error, results) {

        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            logger.info('DB Success: ');
            response.send(results[0]);
        }

    });


});

app.get('/adminCount', function(request, response) {

    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_ADMIN';
    query += ' where CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        logger.info('super');
    } else if (lv == 2) {
        query += ' and CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' ';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});


app.get('/manageStb', CheckAuth, function(request, response) {

    fs.readFile('html/manage_stb.html', 'utf8', function(error, data) {
        //var query = 'select * from TB_STB_INFO';
        var query = util.format("select * from TB_STB_INFO where STB_DEPT_CODE_03 = '%s'", request.session.code_03);
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            response.send(ejs.render(data, {
                data: results
            }));
        });
    });
});

app.get('/stbAdd', CheckAuth, function(request, response) {
    fs.readFile('html/stb_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.all('/stbAdd', CheckAuth, function(request, response) {

    var stb_mac_addr = request.param('stb_mac_addr');
    var stb_nm = request.param('stb_nm');
    var stb_dept_nm = request.param('stb_dept_nm');
    var stb_dept_code_01 = request.param('stb_dept_code_01');
    var stb_dept_code_02 = request.param('stb_dept_code_02');
    var stb_dept_code_03 = request.session.code_03;
    var stb_location = request.param('stb_location');
    var stb_admin_info = request.param('stb_admin_info');
    var ctn_seq = request.param('ctn_seq');
    var status = request.param('status');

    var query = 'INSERT INTO TB_STB_INFO (STB_MAC_ADDR, STB_NM, STB_DEPT_NM, STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, STB_LOCATION, STB_ADMIN_INFO, CTN_SEQ, STATUS) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [stb_mac_addr, stb_nm, stb_dept_nm, stb_dept_code_01, stb_dept_code_02, stb_dept_code_03, stb_location, stb_admin_info, ctn_seq, status], function(error, result) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send({
                "stb_mac_addr": stb_mac_addr
            });
        }

    });

});

app.get('/stbModifyList', function(request, response) {
    var stb_mac_addr = request.param('stb_mac_addr');

    dbConn.query('select * from TB_STB_INFO where STB_MAC_ADDR = ?', [stb_mac_addr], function(error, results) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });
});

app.get('/stbModify/:stb_mac_addr', CheckAuth, function(request, response) {

    var stb_mac_addr = request.param('stb_mac_addr');
    var code3 = request.session.code_03;
    var query = 'select *, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3 ' +
        'from TB_STB_INFO a where STB_MAC_ADDR = \'' + stb_mac_addr + '\'';

    fs.readFile('html/stb_modify.html', 'utf8', function(error, data) {

        logger.info('Query: ', query);

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }
        });
    });
});

app.all('/stbModify', CheckAuth, function(request, response) {

    var stb_nm = request.param('stb_nm');
    var stb_mac_addr = request.param('stb_mac_addr');
    var stb_dept_nm = request.param('stb_dept_nm');
    var stb_location = request.param('stb_location');
    var stb_admin_info = request.param('stb_admin_info');
    //var ctn_seq = request.param('ctn_seq');
    var status = request.param('status');
    var dept1 = request.param('stb_dept_code_01');
    var dept2 = request.param('stb_dept_code_02');
    var dept3 = request.session.code_03;

    var query = 'UPDATE TB_STB_INFO SET STB_NM=?, STB_DEPT_NM=?, STB_DEPT_CODE_01=?, STB_DEPT_CODE_02=?, STB_DEPT_CODE_03=?, STB_LOCATION=?, STB_ADMIN_INFO=?, STATUS=? WHERE STB_MAC_ADDR=?';

    logger.info('Query: ', query);
    dbConn.query(query, [stb_nm, stb_dept_nm, dept1, dept2, dept3, stb_location, stb_admin_info, status, stb_mac_addr], function(error, result) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send({
                "stb_mac_addr": stb_mac_addr
            });
        }
    });
});

app.get('/stbDelete/:stb_mac_addr', function(request, response) {

    dbConn.query('delete from TB_STB_INFO where STB_MAC_ADDR = ?', [request.param('stb_mac_addr')], function() {

        response.redirect('/manageStb');

    });

});

app.all('/isValidSTB', function(request, response) {

    var stb_mac_addr = request.param('stb_mac_addr');

    dbConn.query('select count(*) as cnt from TB_STB_INFO where STB_MAC_ADDR = ?', [stb_mac_addr], function(error, results) {

        response.send(results[0]);
    });
});

app.get('/stbsearchCount', function(request, response) {

    logger.info('Path Change : /stbsearchCount');

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var stb_name = request.param('stb_name');
    var stb_mac_addr = request.param('stb_mac_addr');

    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_STB_INFO ';
    query += ' where STB_DEPT_CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        if (code_01 != 'all') {
            query += 'and STB_DEPT_CODE_01=\'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and STB_DEPT_CODE_02=\'' + code_02 + '\' ';
        }
        if (stb_name != '') {
            query += 'and STB_NM like \"%' + stb_name + '%\" ';
        }
        if (stb_mac_addr != '') {
            query += 'and STB_MAC_ADDR like \"%' + stb_mac_addr + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and STB_DEPT_CODE_01=\'' + code1 + '\' and STB_DEPT_CODE_02=\'' + code2 + '\' and STB_DEPT_CODE_03=\'' + code3 + '\' ';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }
    });

});

app.all('/stbPaging', CheckAuth, function(request, response) {

    logger.info('Path change : /stbPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var stb_name = request.param('stb_name');
    var stb_mac_addr = request.param('stb_mac_addr');
    var type = request.param('type');

    var query = 'select STB_NM, STB_MAC_ADDR, STB_DEPT_NM, STB_LOCATION, case STATUS when "Y" then "접속가능" when "N" then "접속불가" end as STB_STATUS, ' +
        'STB_DEPT_CODE_01, STB_DEPT_CODE_02, STB_DEPT_CODE_03, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where STB_DEPT_CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3 ' +
        'from TB_STB_INFO a ';

    query += 'where 1=1 ';
    query += ' and STB_DEPT_CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        if (code_01 != 'all') {
            query += 'and STB_DEPT_CODE_01=\'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and STB_DEPT_CODE_02=\'' + code_02 + '\' ';
        }
        if (stb_name != '') {
            query += 'and STB_NM like \"%' + stb_name + '%\" ';
        }
        if (stb_mac_addr != '') {
            query += 'and STB_MAC_ADDR like \"%' + stb_mac_addr + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and STB_DEPT_CODE_01=\'' + code1 + '\' and STB_DEPT_CODE_02=\'' + code2 + '\' and STB_DEPT_CODE_03=\'' + code3 + '\' ';
    }

    query += 'ORDER BY STB_NM,STB_DEPT_NM ';

    if (type != "excel") {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            if (type == "excel") {
                var filename = "STB.xlsx";

                var excepts = [];
                excepts.push('STB_DEPT_CODE_01');
                excepts.push('STB_DEPT_CODE_02');
                excepts.push('STB_DEPT_CODE_03');
                excepts.push('DEPT_NM');
                excepts.push('DEPT_NM2');
                excepts.push('DEPT_NM3');

                utilLib.excelExport(request, response, results, fields, filename, excepts);
            } else {
                response.send(results);
            }
        }

    });
});

app.get('/stbCount', function(request, response) {

    var stb_nm = request.param('stb_nm');
    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_STB_INFO';
    query += ' where STB_DEPT_CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        logger.info('super');
    } else if (lv == 2) {
        query += ' where STB_DEPT_CODE_01=\'' + code1 + '\' and STB_DEPT_CODE_02=\'' + code2 + '\' and STB_DEPT_CODE_03=\'' + code3 + '\'';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.get('/manageControl', CheckAuth, function(request, response) {
    logger.info('Path change : /manageControl');
    fs.readFile('html/manage_control.html', 'utf8', function(error, data) {
        //var query = 'select * from TB_CONTROL';
        var query = util.format("select * from TB_CONTROL where CODE_03 = '%s'", request.session.code_03);
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            response.send(ejs.render(data, {
                data: results
            }));
        });
    });
});

app.get('/defaultCheck', function(request, response) {

    var code1 = request.param('code1');
    var code2 = request.param('code2');
    var code3 = request.session.code_03;
    var type = request.param('type');

    var table_nm, where;
    if (type == 2) { //stb
        table_nm = 'TB_STB_INFO';
        where = 'STB_DEPT_CODE_01 = \'' + code1 + '\' AND STB_DEPT_CODE_02 = \'' + code2 + '\' AND STB_DEPT_CODE_03 = \'' + code3 + '\' ';
    } else { //pc, mobile
        table_nm = 'TB_DEFAULT_CONNECT_INFO';
        where = 'CODE_01 = \'' + code1 + '\' AND CODE_02 = \'' + code2 + '\' AND CODE_03 = \'' + code3 + '\' and DEV_TYPE = \'' + type + '\'';
    }

    var query = 'select count(*) as cnt from ' + table_nm;
    query += ' where ' + where;

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(result[0]);
        }
    });
});

app.get('/controlCheck', function(request, response) {

    var code1 = request.param('code1');
    var code2 = request.param('code2');
    //var code3 = request.param('code3');
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt, CTL_NM from TB_CONTROL ';
    query += ' where CODE_01 = \'' + code1 + '\' and CODE_02 = \'' + code2 + '\' and CODE_03 = \'' + code3 + '\'';

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(result[0]);
        }
    });

});

app.get('/controlAdd', CheckAuth, function(request, response) {
    fs.readFile('html/control_add.html', 'utf8', function(error, data) {

        var mVoIP;
        var query = util.format('SELECT SV_OP_SV_V, SV_OP_SV_DR FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
                mVoIP = '';
            } else {
                mVoIP = results[0].SV_OP_SV_V;
            }
            /*
	        response.send(ejs.render(data, {
	             data: {'session':session_id, 'session_lv': session_lv, 's_date': s_date, 'mVoIP' : mVoIP}
	        }));
	        */
            response.send(ejs.render(data, {
                data: {
                    'code_03': request.session.code_03,
                    'mVoIP': mVoIP,
                    'drone': results[0].SV_OP_SV_DR
                }
            }));
        });
    });
});

app.all('/controlAdd', CheckAuth, function(request, response) {

    var ctl_nm = request.param('ctl_nm');
    var ctl_admin_nm = request.param('ctl_admin_nm');
    var ctl_tel_num = request.param('ctl_tel_num');
    //var pw = request.param('pw');
    var date = request.param('date');
    var user_yn = request.param('user_yn');
    var device = request.param('device');
    var code_01 = request.param('code_01');
    var code_02 = request.param('code_02');
    //var code_03 = request.param('code_03');
    var code_03 = request.session.code_03;
    var code_id = code_01 + code_02 + code_03;

    var query = 'INSERT INTO TB_CONTROL (CTL_NM, CTL_ADMIN_NM, CTL_TEL_NUM, INSERT_DATE, USER_YN, CODE_01, CODE_02, CODE_03, CODE_ID, DEFAULT_DEVICE) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [ctl_nm, ctl_admin_nm, ctl_tel_num, date, user_yn, code_01, code_02, code_03, code_id, device], function(error, result) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send({
                "ctl_nm": ctl_nm
            });
            /*
            var query2 = 'INSERT INTO TB_IMS_CALL_INFO (CALL_ID, CALL_PW, INSERT_DATE ) VALUES (? , ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s") )';
            //var query2 = 'UPDATE  TB_IMS_CALL_INFO SET CALL_ID = ?, CALL_PW = ?,  INSERT_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE CALL_ID = ?';

            dbConn.query(query2, [ctl_tel_num, pw ], function (error, result) {
            	//response.send(code);

            	response.send(ctl_nm);
            });
            */
        }
    });
});

app.get('/controlModifyList', function(request, response) {
    var seq = request.param('seq');

    dbConn.query('select * from TB_CONTROL where SEQ = ?', [seq], function(error, results) {

        response.send(results[0]);

    });
});

app.get('/controlModify/:seq', CheckAuth, function(request, response) {
    logger.info('Path Change : /controlModify/');

    var seq = request.param('seq');
    var code3 = request.session.code_03;
    var query = 'select *, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3 ' +
        'from TB_CONTROL a where SEQ = \'' + seq + '\'';

    fs.readFile('html/control_modify.html', 'utf8', function(error, data) {

        dbConn.query(query, function(error, result) {

            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                var mVoIP;
                var query = util.format('SELECT SV_OP_SV_V,SV_OP_SV_DR FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'', request.session.code_03);

                dbConn.query(query, function(error, results) {
                    logger.info('Query:', query);
                    if (error) {
                        logger.error('DB Error:', error);
                        mVoIP = '';
                    } else {
                        mVoIP = results[0].SV_OP_SV_V;
                    }

                    result[0].mVoIP = mVoIP;
                    result[0].drone = results[0].SV_OP_SV_DR;
                    response.send(ejs.render(data, {
                        data: result[0]
                    }));
                });
            }
        });
    });
});

app.all('/controlModify', CheckAuth, function(request, response) {

    var seq = request.param('seq');
    var ctl_nm = request.param('ctl_nm');
    var ctl_admin_nm = request.param('ctl_admin_nm');
    var ctl_tel_num = request.param('ctl_tel_num');
    var ctl_tel_num_old = request.param('ctl_tel_num_old');
    var date = request.param('date');
    var pw = request.param('pw');
    var user_yn = request.param('user_yn');
    var code_01 = request.param('code_01');
    var code_02 = request.param('code_02');
    var code_03 = request.session.code_03;
    var code_id = code_01 + code_02 + code_03;
    var device = request.param('device');
    var callId = request.param('callId');

    var query = 'UPDATE TB_CONTROL SET CTL_NM=?, CTL_ADMIN_NM=?, CTL_TEL_NUM=?, INSERT_DATE=?, USER_YN=?, CODE_01=?, CODE_02=?, CODE_03=?, CODE_ID=?, DEFAULT_DEVICE=?, CALL_ID=? WHERE SEQ=?';

    dbConn.query(query, [ctl_nm, ctl_admin_nm, ctl_tel_num, date, user_yn, code_01, code_02, code_03, code_id, device, callId, seq], function(error, result) {

        //var query2 = 'INSERT INTO TB_IMS_CALL_INFO (CALL_ID, CALL_PW, INSERT_DATE ) VALUES ("2", ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s") )';
        //var query2 = 'UPDATE  TB_IMS_CALL_INFO SET CALL_ID = ?, CALL_PW = ?,  INSERT_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE CALL_ID = ?';

        //dbConn.query(query2, [ctl_tel_num, pw, ctl_tel_num_old], function (error, result) {
        //response.send(code);
        //	response.send(seq);
        //});
        response.send({
            "ctl_nm": ctl_nm
        });
    });
});

app.get('/control', function(request, response) {
    logger.info('Path change : /control');

    var query = 'select SEQ, CTL_NM from TB_CONTROL group by CTL_NM';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/controlCount', function(request, response) {

    logger.info('Path Change : /controlCount');

    var stb_nm = request.param('stb_nm');
    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_CONTROL';

    if (lv == 1) {
        logger.info('super');
        query += ' where CODE_03 = \'' + code3 + '\'';
    } else if (lv == 2) {
        query += ' where CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' and CODE_03=\'' + code3 + '\'';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.get('/controlsearchCount', function(request, response) {

    logger.info('Path Change : /controlsearchCount');

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var ctl_nm = request.param('ctl_nm');
    var de_device = request.param('de_device');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var lv = request.session.userlv;

    var query = 'select count(*) as cnt from TB_CONTROL ';

    query += 'where 1=1 ';
    query += ' and CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        if (code_01 != 'all') {
            query += 'and CODE_01 = \'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and CODE_02 = \'' + code_02 + '\' ';
        }
        if (ctl_nm != '') {
            query += 'and CTL_NM like \"%' + ctl_nm + '%\" ';
        }
        if (de_device != 'all') {
            query += 'and DEFAULT_DEVICE = ' + de_device + ' ';
        }

    }

    if (lv == 2) {
        query += 'and CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' and CODE_03=\'' + code3 + '\' ';
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
            logger.info('Path Change : /controlsearchCount4');
        } else {
            
            response.send(results[0]);
        }

    });

});

app.all('/controlPaging', function(request, response) {

    logger.info('Path change : /controlPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var ctl_nm = request.param('ctl_nm');
    var de_device = request.param('de_device');
    var type = request.param('type');

    logger.info('type : ', type);

    //var query = 'select * from TB_CONTROL ';
    var query = 'select CTL_NM, CTL_ADMIN_NM, CTL_TEL_NUM, case DEFAULT_DEVICE when "1" then "MOBILE" when "2" then "STB" when "3" then "PC" end as DEFAULT_DEVICE, ' +
        'case USER_YN when "Y" then "사용가능" when "N" then "사용불가" end as USER_YN, SEQ , CODE_01, CODE_02, CODE_03, CODE_ID,  ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3 ' +
        'from TB_CONTROL a ';

    query += 'where 1=1 ';
    query += ' and CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        if (code_01 != 'all') {
            query += 'and CODE_01 = \'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and CODE_02 = \'' + code_02 + '\' ';
        }
        if (ctl_nm != '') {
            query += 'and CTL_NM like \"%' + ctl_nm + '%\" ';
        }
        if (de_device != 'all') {
            query += 'and DEFAULT_DEVICE = ' + de_device + ' ';
        }
    }

    if (lv == 2) {
        query += 'and CODE_01=\'' + code1 + '\' and CODE_02=\'' + code2 + '\' and CODE_03=\'' + code3 + '\' ';
    }

    query += 'order by CTL_NM ';

    if (type != 'excel') {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            if (type == 'excel') {
                var filename = "CONTROL.xlsx";

                var excepts = [];
                excepts.push('SEQ');
                excepts.push('CODE_01');
                excepts.push('CODE_02');
                excepts.push('CODE_03');
                excepts.push('DEPT_NM');
                excepts.push('DEPT_NM2');
                excepts.push('DEPT_NM3');
                excepts.push('CODE_ID');

                utilLib.excelExport(request, response, results, fields, filename, excepts);
            } else {
                response.send(results);
            }
        }

    });
});


app.get('/manageCommon', CheckAuthControl, function(request, response) {
    logger.info('Path change : /manageCommon');

    fs.readFile('html/manage_common.html', 'utf8', function(error, data) {

        var query = "select replace(C_VALUE,'\n','<br>') as C_VALUE,C_NAME, C_KEY from TB_COMMON ORDER BY C_NAME";

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);

            response.send(ejs.render(data, {
                data: results
            }));

        });
    });
});

app.all('/commonPaging', function(request, response) {

    logger.info('Path change : /commonPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var type = request.param('type');

    logger.info('type : ', type);

    //var query = 'select * from TB_CONTROL ';
    var query = "select C_NAME, replace(C_VALUE,'\n','<br>') as C_VALUE, C_KEY from TB_COMMON ORDER BY C_NAME ";

    if (type != 'excel') {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            if (type == 'excel') {
                var filename = "COMMON.xlsx";

                var excepts = [];
                excepts.push('C_KEY');

                utilLib.excelExport(request, response, results, fields, filename, excepts);
            } else {
                response.send(results);
            }
        }

    });
});

app.get('/commonCount', function(request, response) {

    var query = 'select count(*) as cnt from TB_COMMON';

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});


app.get('/commonAdd', CheckAuthControl, function(request, response) {
    fs.readFile('html/common_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.all('/commonAdd', CheckAuth, function(request, response) {

    var c_value = request.param('c_value');
    var c_name = request.param('c_name');

    var query = 'INSERT INTO TB_COMMON (C_VALUE, C_NAME) VALUES (?, ?)';

    dbConn.query(query, [c_value, c_name], function(error, result) {

        response.send({
            "c_name": c_name
        });

    });

});


app.get('/commonModifyList', function(request, response) {
    var c_key = request.param('c_key');

    dbConn.query('select * from TB_COMMON where C_KEY = ?', [c_key], function(error, results) {

        response.send(results[0]);

    });
});

app.get('/commonModify/:c_key', CheckAuthControl, function(request, response) {

    fs.readFile('html/common_modify.html', 'utf8', function(error, data) {

        dbConn.query('select * from TB_COMMON where C_KEY = ?', [request.param('c_key')], function(error, result) {

            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }

        });
    });
});

app.all('/commonModify', CheckAuth, function(request, response) {

    var c_key = request.param('c_key');
    var c_name = request.param('c_name');
    var c_value = request.param('c_value');


    var query = 'UPDATE TB_COMMON SET C_NAME=?, C_VALUE=? WHERE C_KEY=?';

    dbConn.query(query, [c_name, c_value, c_key], function(error, result) {

        response.send({
            "c_key": c_key
        });

    });

});

app.all('/commonDelete', function(request, response) {

    var c_key = request.param('c_key')

    dbConn.query('delete from TB_COMMON where C_KEY = ?', [c_key], function() {

        response.send({
            "c_key": c_key
        });

    });

});

app.get('/manageUserList', CheckAuth, function(request, response) {
    logger.info('Path change : /manageUserList');
    fs.readFile('html/manage_user_list.html', 'utf8', function(error, data) {
        //var query = 'select * from TB_ORGANOGRAM';
        var query = util.format("select * from TB_ORGANOGRAM where DEPT_CODE_03 = '%s'", request.session.code_03);
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            response.send(ejs.render(data, {
                data: results
            }));
        });
    });
});

app.all('/checkTel', CheckAuth, function(request, response) {

    logger.info('Path Change: /checkTel' + request.param('ctn'));

    var ctn = request.param('ctn');

    var query = 'select COUNT(*) as cnt from TB_ORGANOGRAM where CTN=\'' + ctn + '\'';

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);

        response.send(result[0]);
    });

});

app.get('/userlistAdd', CheckAuth, function(request, response) {
    fs.readFile('html/userlist_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

app.all('/userlistAdd', CheckAuth, function(request, response) {

    var nm = request.param('nm');
    var dept_code_01 = request.param('dept_code_01');
    var dept_code_02 = request.param('dept_code_02');
    var dept_code_03 = request.session.code_03;
    var dept_nm = request.param('dept_nm');
    var arank = request.param('arank');
    var ctn = request.param('ctn');
    var status = request.param('status');
    var id = request.param('id');
    var pw = request.param('pw');

    //var query = 'INSERT INTO TB_ORGANOGRAM (CTN, NM, DEPT_CODE_01, DEPT_CODE_02, DEPT_CODE_03, DEPT_NM, ARANK, STATUS ,VPN_ID ,VPN_PW ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    var query = 'INSERT INTO TB_ORGANOGRAM (CTN, NM, DEPT_CODE_01, DEPT_CODE_02, DEPT_CODE_03, DEPT_NM, ARANK, STATUS) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [ctn, nm, dept_code_01, dept_code_02, dept_code_03, dept_nm, arank, status], function(error, result) {

        response.send({
            "nm": nm
        });
    });
});

app.all('/isUserlistId', function(request, response) {

    var id = request.param('id');

    dbConn.query('select count(*) as cnt from TB_ORGANOGRAM where VPN_ID = ?', [id], function(error, results) {

        response.send(results[0]);

    });
});


app.get('/userlistModifyList', function(request, response) {
    var ctn = request.param('ctn');

    dbConn.query('select * from TB_ORGANOGRAM where CTN = ?', [ctn], function(error, results) {

        response.send(results[0]);

    });
});

app.get('/userlistModify/:ctn', CheckAuth, function(request, response) {

    var ctn = request.param('ctn');
    var code03 = request.session.code_03;
    var query = 'select *, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code03 + '\') as DEPT_NM3 ' +
        'from TB_ORGANOGRAM a where CTN = \'' + ctn + '\'';

    logger.info('Query: ', query);

    fs.readFile('html/userlist_modify.html', 'utf8', function(error, data) {

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]
                }));
            }
        });
    });
});

app.all('/userlistModify', CheckAuth, function(request, response) {
    logger.info('Path change : /userlistModify');

    var ctn = request.param('ctn');
    var nm = request.param('nm');
    var dept_code_01 = request.param('dept_code_01');
    var dept_code_02 = request.param('dept_code_02');
    var dept_code_03 = request.session.code_03;
    var arank = request.param('arank');
    var status = request.param('status');
    var dept_nm = request.param('dept_nm');
    var id = request.param('id');
    var pw = request.param('pw'); //,VPN_ID ,VPN_PW

    var query = 'UPDATE TB_ORGANOGRAM SET DEPT_CODE_01=?, DEPT_CODE_02=?, DEPT_CODE_03=?, DEPT_NM=?, ARANK=?, STATUS=? WHERE CTN=?';

    dbConn.query(query, [dept_code_01, dept_code_02, dept_code_03, dept_nm, arank, status, ctn], function(error, result) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send({
                "nm": nm
            });
        }
    });
});

app.all('/userlistDelete', function(request, response) {

    var ctn = request.param('ctn');
    dbConn.query('delete from TB_ORGANOGRAM where CTN = ?', [ctn], function(error, result) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send({
                "ctn": ctn
            });
            dbConn.query('delete from TB_CONTROL_SETUP_INFO where CUST_CTN = ?', [ctn], function(error, result) {

                if (error) {
                    logger.error('DB Error:', error);
                } else {
                    //response.send(ctn);
                }
            });

            dbConn.query('delete from TB_CUST_INFO where CUST_CTN = ?', [ctn], function(error, result) {

                if (error) {
                    logger.error('DB Error:', error);
                } else {
                    //response.send(ctn);
                }
            });
        }
    });
});
/*
app.post('/deleteControlSetup', function (request, response) {

    dbConn.query('delete from TB_CONTROL_SETUP_INFO where CUST_CTN = ?', [ctn], function (error, result) {

		if (error) {
        	logger.error('DB Error:', error);
		} else {
	        //response.send(ctn);
		}
    });
});
*/
app.get('/userlistsearchCount', function(request, response) {

    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var name = request.param('name');
    var tel = request.param('tel');

    var query = 'select count(*) as cnt from TB_ORGANOGRAM ';

    query += 'where 1=1 and DEPT_CODE_03 = \'' + code3 + '\' ';

    if (lv == 1) {
        logger.info('super');

        if (code_01 != 'all') {
            query += 'and DEPT_CODE_01 = \'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and DEPT_CODE_02 = \'' + code_02 + '\' ';
        }
        if (name != '') {
            query += 'and NM like \"%' + name + '%\" ';
        }
        if (tel != '') {
            query += 'and CTN like \"%' + tel + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and DEPT_CODE_01=\'' + code1 + '\' and DEPT_CODE_02=\'' + code2 + '\' ';
        if (name != '') {
            query += 'and NM like \"%' + name + '%\" ';
        }
        if (tel != '') {
            query += 'and CTN like \"%' + tel + '%\" ';
        }
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.all('/userlistPaging', function(request, response) {

    logger.info('Path change : /userlistPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');

    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var name = request.param('name');
    var tel = request.param('tel');
    var type = request.param('type');

    var query = 'select NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_01 = b.CODE and b.GUBUN = "1" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_02 = b.CODE and b.GUBUN = "2" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM2, ' +
        '(select b.CODE_NM from TB_DEPT_DEPTH b where DEPT_CODE_03 = b.CODE and b.GUBUN = "3" and b.CODE_03 = \'' + code3 + '\') as DEPT_NM3,  ' +
        ' ARANK, CTN, BLOCK_FLAG ' +
        'from TB_ORGANOGRAM a ';

    query += 'where 1=1 ';
    query += ' and DEPT_CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        logger.info('super');

        if (code_01 != 'all') {
            query += 'and DEPT_CODE_01 = \'' + code_01 + '\' ';
        }
        if (code_02 != 'all') {
            query += 'and DEPT_CODE_02 = \'' + code_02 + '\' ';
        }
        if (name != '') {
            query += 'and NM like \"%' + name + '%\" ';
        }
        if (tel != '') {
            query += 'and CTN like \"%' + tel + '%\" ';
        }

    } else if (lv == 2) {
        query += 'and DEPT_CODE_01=\'' + code1 + '\' and DEPT_CODE_02=\'' + code2 + '\' and DEPT_CODE_03=\'' + code3 + '\' ';
        if (name != '') {
            query += 'and NM like \"%' + name + '%\" ';
        }
        if (tel != '') {
            query += 'and CTN like \"%' + tel + '%\" ';
        }
    }

    query += 'ORDER BY DEPT_NM, DEPT_NM2,NM  ';

    if (type != 'excel') {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query)
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            if (type == 'excel') {
                var except = [];
                except.push('DEPT_NM3');

                var filename = "ORGANOGRAM.xlsx";

                utilLib.excelExport(request, response, results, fields, filename, except);
            } else {
                response.send(results);
            }
        }

    });
});

app.get('/userlistCount', function(request, response) {

    var lv = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var query = 'select count(*) as cnt from TB_ORGANOGRAM';
    query += ' where DEPT_CODE_03 = \'' + code3 + '\'';

    if (lv == 1) {
        logger.info('super');
    } else if (lv == 2) {
        query += ' and DEPT_CODE_01=\'' + code1 + '\' and DEPT_CODE_02=\'' + code2 + '\' and DEPT_CODE_03=\'' + code3 + '\'';
    }

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error', error);
        } else {
            response.send(results[0]);
        }

    });

});

app.get('/manageDept', CheckAuthControl, function(request, response) {
    logger.info('Path change : /manageDept');
    fs.readFile('html/manage_dept.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/manageDeptCount', function(request, response) {

    var stb_nm = request.param('stb_nm');
    var code1 = request.param('code1');
    var code2 = request.param('code2');

    var query = 'select count(*) as cnt from TB_DEPT_DEPTH where code_03 = ';
    query += '\'' + request.session.code_03 + '\'';
    query += 'and GUBUN in ("1","2")'

    dbConn.query(query, function(error, results) {

        response.send(results[0]);

    });

});

app.get('/deptSearchCount', function(request, response) {

    logger.info('Path Change: /deptSearchCount');

    var code1 = request.param('code1');
    var code2 = request.param('code2');

    var query = 'select count(*) as cnt from TB_DEPT_DEPTH ';
    query += 'where 1=1 ';

    if (code1 == 'all' && code2 == 'all') {
        query += 'and GUBUN in ("1","2")';
    }

    if (code1 != 'all') {
        query += 'and GUBUN="2" AND CODE like \'' + code1 + '%\''
    }
    if (code2 != 'all') {
        query += 'and GUBUN="2" AND CODE = \'' + code2 + '\''
    }

    /*if(code1 != 'all' && code2 != 'all') {
    	query += 'where GUBUN="2" AND CODE = \''+code2+'\' ';
    }else if(code1 != 'all' && code2 == 'all'){
    	query += 'where GUBUN="2" AND CODE like \''+code1+'%\' ';
    }*/
    query += 'and CODE_03 = \'' + request.session.code_03 + '\' ';


    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }

    });

});

app.get('/manageDeptPaging', function(request, response) {

    logger.info('Path change : /manageDeptPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var code1 = request.param('code1');
    var code2 = request.param('code2');
    var type = request.param('type');

    if (code1 != 'all') {
        code1 = code1.substring(0, 1);
    }

    //var query = 'select GUBUN, CODE, CODE_NM from TB_DEPT_DEPTH a ';
    var query = 'select GUBUN, CODE, CODE_NM from TB_DEPT_DEPTH where code_03 = ';
    query += '\'' + request.session.code_03 + '\'';

    if (code1 != 'all' && code2 != 'all') {
        //query += 'where GUBUN="2" AND CODE = \''+code2+'\' ';
        query += ' and GUBUN="2" AND CODE = \'' + code2 + '\' ';
    } else if (code1 != 'all' && code2 == 'all') {
        //query += 'where GUBUN="2" AND CODE like \''+code1+'%\' ';
        query += ' and GUBUN="2" AND CODE like \'' + code1 + '%\' ';
    }

    query += 'order by GUBUN,CODE ,CODE_NM ';

    if (type != 'excel') {
        query += 'limit ' + start + ',' + pageSize + ' ';
    }

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            if (type == 'excel') {
                var filename = "Dept.xlsx";
                utilLib.excelExport(request, response, results, fields, filename);
            } else {
                response.send(results);
            }
        }

    });
});

app.get('/manageDeptModify', CheckAuthControl, function(request, response) {

    var code = request.param('code');
    var gubun = request.param('gubun');
    var code3 = request.session.code_03;

    fs.readFile('html/manage_dept_modify.html', 'utf8', function(error, data) {

        var query = 'select * from TB_DEPT_DEPTH where CODE =  \'' + code + '\' and GUBUN =  \'' + gubun + '\' and CODE_03 = \'' + code3 + '\'';

        dbConn.query(query, function(error, result) {

            logger.info('Query:', query);

            if (result.length == 0) {
                response.send(ejs.render(data, {
                    data: {
                        'GUBUN': '',
                        'CODE': '',
                        'CODE_NM': ''
                    }

                }));
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }

        });
    });
});
app.all('/manageDeptModify', CheckAuth, function(request, response) {

    var gubun = request.param('gubun');
    var code = request.param('code');
    var code_nm = request.param('code_nm');

    var query = 'UPDATE TB_DEPT_DEPTH SET CODE_NM=? WHERE CODE=? AND GUBUN=?';

    dbConn.query(query, [code_nm, code, gubun], function(error, result) {

        response.send(code);

    });

});

app.all('/manageDeptAdd', CheckAuth, function(request, response) {

    logger.info('Path change : /manageDeptAdd');

    var code = request.param('code');
    var code_nm = request.param('code_nm');
    var gubun = request.param('gubun');
    var code3 = request.session.code_03;

    var query = 'INSERT INTO TB_DEPT_DEPTH (GUBUN, CODE, CODE_NM, CODE_03) VALUES (?, ?, ?, ?)';

    dbConn.query(query, [gubun, code, code_nm, code3], function(error, result) {
        /*
        if(gubun == 1) {
        	var query2 = 'INSERT INTO TB_DEPT_DEPTH (GUBUN, CODE, CODE_NM, CODE_03) VALUES ("2", ?, ?, ?)';

        	dbConn.query(query2, [code, code_nm, code3], function (error, result) {
        		response.send(code);
        	});
        }else {
            response.send(code);
        }
        */
        response.send(code);
    });

});

app.all('/manageDeptCodeSearch', function(request, response) {

    var code = request.param('code');
    var gubun = request.param('gubun');
    var code3 = request.session.code_03;
    var query = 'select count(*) as cnt from TB_DEPT_DEPTH  where code = ? and gubun = ? and code_03 = ?';

    dbConn.query(query, [code, gubun, code3], function(error, results) {

        response.send(results[0]);

    });

});

app.all('/manageDeptDelete', function(request, response) {
    logger.info('/manageDeptDelete');

    var code = request.param('code');
    var gubun = request.param('gubun');
    var code3 = request.session.code_03;
    dbConn.query('delete from TB_DEPT_DEPTH where code = ? and gubun = ? and code_03 = ?', [code, gubun, code3], function() {
        logger.info('Query:', query);
        logger.info('delete dept request id : ', request.session.userid);
        response.send(code);
    });
});

app.get('/notice', CheckAuthControl, function(request, response) {
    logger.info('/notice');

    fs.readFile('html/notice.html', 'utf8', function(error, data) {

        var query = 'select * from TB_NOTICE_POPUP order by N_INSERTDATE desc';

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);

            response.send(ejs.render(data, {
                data: results
            }));

            //console.log("admin"+results);
        });
    });
});

app.get('/noticeAdd', CheckAuthControl, function(request, response) {
    fs.readFile('html/notice_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});


app.all('/noticeAdd',CheckAuth,function (request, response) {
    logger.info('/noticeAdd');

    var title = request.param('title');
    var datepicker = request.param('datepicker');
    var datepicker2 = request.param('datepicker2');
    var date1 = datepicker.replace(/-/g,'');
    var date2 = datepicker2.replace(/-/g,'');
    var n_width = request.param('n_width');
    var n_height = request.param('n_height');
    var n_left = request.param('n_left');
    var n_top = request.param('n_top');
    var content = request.param('content');
    var id = request.session.userid;
    var status = '1';

    var query = 'INSERT INTO TB_NOTICE_POPUP ' +
        '(N_WIDTH, N_HEIGHT, N_LEFT, N_TOP, N_F_DATE, N_T_DATE, N_TITLE, N_CONTENT, N_STATUS, N_INSERTDATE, N_UPDATEDATE, N_ADMIN, N_SENDDATE) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?, ?)';

    dbConn.query(query, [n_width, n_height, n_left, n_top, date1, date2, title, content, status, id, ""], function (error, result) {

        if (error){
        	logger.error('DB Error:', error);
        }else {
            
            query = "SELECT SEQ FROM TB_NOTICE_POPUP WHERE N_ADMIN = '" + id + "' ORDER BY SEQ DESC LIMIT 1";
            dbConn.query(query, function (error, results) {
                logger.info('Query: ', query);
                if(error) {
                    logger.error('DB Error:', error);
                }else {
                    response.send(results[0]);
                }
            });
        }
    });
});


app.all('/noticeDelete', function(request, response) {

    var seq = request.param('seq');

    dbConn.query('delete from TB_NOTICE_POPUP where SEQ = ?', [seq], function() {

        response.send(seq);

    });

});


app.get('/noticeModify/:seq', CheckAuthControl, function(request, response) {

    fs.readFile('html/notice_modify.html', 'utf8', function(error, data) {

        var seq = request.param('seq');

        //var query = 'select * from TB_ADMIN where ADMIN_ID =  \''+id+'\'';

        var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]
                }));
            }
        });
    });
});

app.all('/noticeModify',CheckAuth,function (request, response) {

        var seq = request.param('seq');
        var title = request.param('title');
        var datepicker = request.param('datepicker');
        var datepicker2 = request.param('datepicker2');
        var date1 = datepicker.replace(/-/g,'');
        var date2 = datepicker2.replace(/-/g,'');
        var n_width = request.param('n_width');
        var n_height = request.param('n_height');
        var n_left = request.param('n_left');
        var n_top = request.param('n_top');
        var content = request.param('content');
        var status = '1';

        var query = 'UPDATE TB_NOTICE_POPUP SET N_TITLE=?, N_WIDTH=?, N_HEIGHT=?, N_LEFT=?, N_TOP=?, N_F_DATE=?, N_T_DATE=?, N_CONTENT=?, N_STATUS=?, N_UPDATEDATE=DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE SEQ=?';

        logger.info('Query: ',query);
        dbConn.query(query, [title, n_width, n_height, n_left, n_top, date1, date2, content, status, seq], function (error, result) {
            //response.send(seq);
            var query2 = "UPDATE TB_TN_SERVICE SET N_READ_FLAG = '0' WHERE P_CUST_CTN = '" + seq + "'";
            dbConn.query(query2, function (error, results) {

                logger.info('Query:', query2);
                if (error){
                    logger.error('DB Error:', error);
                }else {
                    logger.info('DB success');
                    response.send(seq);
            }
        });
    });
});


app.get('/detail/:seq', CheckAuth, function(request, response) {

    var seq = request.param('seq');

    fs.readFile('html/notice_detail.html', 'utf8', function(error, data) {

        var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }
        });
    });
});

app.all('/manageDelete', function(request, response) {

    var id = request.param('id');
    dbConn.query('delete from TB_ADMIN where ADMIN_ID = ?', [id], function() {

        response.send({
            "id": id
        });
    });

});

app.all('/stbDelete', function(request, response) {

    var stb_mac_addr = request.param('stb_mac_addr');
    dbConn.query('delete from TB_STB_INFO where STB_MAC_ADDR = ?', [stb_mac_addr], function() {

        response.send({
            "stb_mac_addr": stb_mac_addr
        });
    });
});


app.all('/controlDelete', function(request, response) {

    var seq = request.param('seq');
    var tel = request.param('tel');


    dbConn.query('delete from TB_CONTROL where SEQ = ?', [seq], function() {

        var query2 = 'delete from TB_IMS_CALL_INFO WHERE CALL_ID = ? ';
        //var query2 = 'UPDATE  TB_IMS_CALL_INFO SET CALL_ID = ?, CALL_PW = ?,  INSERT_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE CALL_ID = ?';

        dbConn.query(query2, [tel], function(error, result) {
            //response.send(code);
            response.send(seq);

        });

    });
});

// app.all('/userlistDelete', function(request, response) {

//     var nm = request.param('nm');
//     dbConn.query('delete from TB_ORGANOGRAM where NM = ?', [nm], function() {

//         response.send(nm);
//     });
// });


app.get('/notice', CheckAuth, function(request, response) {
    logger.info('Path change : /notice');

    fs.readFile('html/notice.html', 'utf8', function(error, data) {

        var query = "select a.*, ";
        query += "case when N_F_DATE < DATE_FORMAT(now(),'%Y%m%d%H%i%s') AND N_T_DATE > DATE_FORMAT(now(),'%Y%m%d%H%i%s') then '1' ";
        query += "else '2' end as ddd ";
        query += "from TB_NOTICE_POPUP a";

        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);

            response.send(ejs.render(data, {
                data: results
            }));

        });
    });
});

/* 중복
app.get('/noticeAdd', CheckAuth, function(request, response) {
    fs.readFile('html/notice_add.html', 'utf8', function(error, data) {
        response.send(data);
    });
});


app.all('/noticeAdd', function(request, response) {

    var title = request.param('title');
    var datepicker = request.param('datepicker');
    var datepicker2 = request.param('datepicker2');
    var date1 = datepicker.replace(/-/g, '');
    var date2 = datepicker2.replace(/-/g, '');
    var n_width = request.param('n_width');
    var n_height = request.param('n_height');
    var n_left = request.param('n_left');
    var n_top = request.param('n_top');
    var content = request.param('content');
    var id = request.session.userid;
    var status = '1';

    var query = 'INSERT INTO TB_NOTICE_POPUP ' +
        '(N_WIDTH, N_HEIGHT, N_LEFT, N_TOP, N_F_DATE, N_T_DATE, N_TITLE, N_CONTENT, N_STATUS, N_INSERTDATE, N_UPDATEDATE, N_ADMIN) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';

    dbConn.query(query, [n_width, n_height, n_left, n_top, date1, date2, title, content, status, id], function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(id);
        }
    });
});
*/

app.get('/noticeDelete/:seq', CheckAuth, function(request, response) {

    dbConn.query('delete from TB_NOTICE_POPUP where SEQ = ?', [request.param('seq')], function() {

        response.redirect('/notice');

    });

});

app.get('/noticeModify/:seq', CheckAuth, function(request, response) {

    fs.readFile('html/notice_modify.html', 'utf8', function(error, data) {

        var seq = request.param('seq');

        var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }

        });
    });

});

app.all('/noticeModify', function(request, response) {

    var seq = request.param('seq');
    var datepicker = request.param('datepicker');
    var datepicker2 = request.param('datepicker2');
    var date1 = datepicker.replace(/-/g, '');
    var date2 = datepicker2.replace(/-/g, '');
    var n_width = request.param('n_width');
    var n_height = request.param('n_height');
    var n_left = request.param('n_left');
    var n_top = request.param('n_top');
    var content = request.param('content');
    var status = '1';

    var query = 'UPDATE TB_NOTICE_POPUP SET N_WIDTH=?, N_HEIGHT=?, N_LEFT=?, N_TOP=?, N_F_DATE=?, N_T_DATE=?, N_CONTENT=?, N_STATUS=?, N_UPDATEDATE=DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE SEQ=?';

    dbConn.query(query, [n_width, n_height, n_left, n_top, date1, date2, content, status, seq], function(error, result) {

        response.send(seq);

    });

    logger.info('Query: ', query);
});


app.get('/detail/:seq', CheckAuth, function(request, response) {

    var seq = request.param('seq')

    fs.readFile('html/notice_detail.html', 'utf8', function(error, data) {

        var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

        dbConn.query(query, function(error, result) {
            if (result[0] == 'undefined' || result[0] == undefined) {
                response.redirect('/notaccess');
            } else {
                response.send(ejs.render(data, {
                    data: result[0]

                }));
            }
        });
    });
});


app.get('/noticeView/:seq', function(request, response) {

    fs.readFile('html/notice_view.html', 'utf8', function(error, data) {

        var seq = request.param('seq');

        //var query = 'select * from TB_ADMIN where ADMIN_ID =  \''+id+'\'';

        var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

        dbConn.query(query, function(error, result) {
            response.send(ejs.render(data, {
                data: result[0]
            }));
        });
    });

});


app.get('/noticeView2', function(request, response) {

    /*fs.readFile('html/notice_view2.html', 'utf8', function (error, data) {

        //var query = 'select * from TB_ADMIN where ADMIN_ID =  \''+id+'\'';

        var query = 'select * from TB_NOTICE_POPUP';

        dbConn.query(query, function (error, result) {
            response.send(ejs.render(data, {
                data: result[0]

            }));

        });
    });*/

    fs.readFile('html/notice_view2.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });

});

app.get('/noticeViewList', function(request, response) {

    var seq = request.param('seq');

    var query = 'select * from TB_NOTICE_POPUP where SEQ = \'' + seq + '\'';

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }

    });


});

app.get('/noticePopupList', function(request, response) {

    var now = request.param('now');

    var query = 'select * from TB_NOTICE_POPUP where N_F_DATE < \'' + now + '\' and N_T_DATE > \'' + now + '\'';

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results);
        }

    });


});

app.get('/noticeCount', function(request, response) {

    var now = request.param('now');

    var query = 'select count(*) as cnt from TB_NOTICE_POPUP';

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }

    });


});

app.get('/noticeSearchCount', function(request, response) {

    var f_date = request.param("f_date");
    var t_date = request.param("t_date");
    var code03 = request.session.code_03;
    var query = 'select count(*) as cnt from TB_NOTICE_POPUP a left join TB_ADMIN b on a.N_ADMIN = b.ADMIN_ID where N_F_DATE > \'' + f_date + '\' and N_T_DATE < \'' + t_date + '\' ';
    // query += ' and b.CODE_03 = \'' + code03 + '\''

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });


});


app.get('/noticePaging', function(request, response) {
    logger.info('Path change : /noticePaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');

    var f_date = request.param("f_date");
    var t_date = request.param("t_date");
    var type = request.param('type');
    var code3 = request.session.code_03;
    var query = "select a.*, ";
    query += " case when N_F_DATE < DATE_FORMAT(now(),'%Y%m%d%H%i%s') AND N_T_DATE > DATE_FORMAT(now(),'%Y%m%d%H%i%s') then '1' ";
    query += " else '2' end as ddd ";
    query += " from TB_NOTICE_POPUP a left join TB_ADMIN b on a.N_ADMIN = b.ADMIN_ID";
    //query += " where N_F_DATE> \"" + f_date + "\" and N_T_DATE < \"" + t_date + "\" and b.CODE_03 = \"" + code3 + "\" ";
    query += " where N_F_DATE> \"" + f_date + "\" and N_T_DATE < \"" + t_date + "\" ";
    query += " order by N_INSERTDATE desc limit " + start + "," + pageSize + " ";

    logger.info('Query: ', query);

    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            logger.info('Success');

            response.send(results);
        }

    });
});


app.get('/couple', function(request, response) {
    fs.readFile('couple_test.html', 'utf8', function(error, data) {
        response.send(data);
    });
});

// defect code
app.all('/defectCode', function(request, response) {

    var q = util.format("SELECT LOCALE from TB_ADMIN WHERE ADMIN_ID = '%s'", request.session.userid);
    logger.info('Query:', q);
    dbConn.query(q, function(error, results1) {
        if (error) {
            logger.error('Error:', error);
        } else {
            var locale;
            if (results1[0].LOCALE == "" || results1[0].LOCALE == null) {
                locale = 'KO';
            } else {
                locale = results1[0].LOCALE.toUpperCase();
            }
            var defect_code = request.param('code');
            var query = 'SELECT REASON_' + locale + ' REASON, DEFECT_CODE from TB_DEFECT_CODE where DEFECT_CODE = \'' + defect_code + '\'';
            logger.info('Query:', query);
            dbConn.query(query, function(error, results) {
                if (error) {
                    logger.error('Error:', error);
                } else {
                    response.send(results[0]);
                }
            });        
        }
    });
});

app.post('/getDefectCode', function(request, response) {

    logger.info('Path change : /getDefectCode');

    var query = 'select * from TB_DEFECT_CODE';
    var flag = request.param('type');

    if (flag == 'SERVICE') {
        query += ' where SVC_FLAG = 1';
    } else if (flag == 'STB') {
        query += ' where STB_FLAG = 1';
    } else if (flag == 'MOBILE') {
        query += ' where MOB_FLAG = 1';
    } else if (flag == 'PC') {
        query += ' where PC_FLAG = 1';
    }
    query += " and DEFECT_CODE >= '1000'";
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(results);
        }
    });
});

//default device
app.get('/connectmanage', CheckAuth, function(request, response) {
    logger.info('Path change : /connectmanage');
    var type = request.param('type');

    fs.readFile('html/connect_manage.html', 'utf8', function(error, data) {

        response.send(ejs.render(data, {
            data: {
                'TYPE': type
            }
        }));
        //response.send(data);
    });
});

app.get('/connectlist', function(request, response) {
    logger.info('Path change : /connectlist');

    var query = 'select * from TB_ORGANOGRAM';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});


app.post('/IsExistRegid', CheckAuth, function(request, response) {

    logger.info('Path change : /IsExistRegid');

    pushServiceAPI.IsExistRegid(dbConn, request.param('dev_key'), request.param('dev_type'), function(results) {

        logger.info('IsExistRegid result : ', results);

        response.send(results[0]);
    });
});


app.all('/insertDefault', CheckAuth, function(request, response) {

    var dev_key = request.param('dev_key');
    var dev_type = request.param('dev_type');
    var dev_name = request.param('dev_name');
    var dev_dept_nm = request.param('dev_dept_nm');
    var code_01 = request.param('code1');
    var code_02 = request.param('code2');
    var code_03 = request.session.code_03;
    var id = request.session.userid;

    var query = 'INSERT INTO TB_DEFAULT_CONNECT_INFO (DEV_KEY, DEV_TYPE, DEV_NM, DEV_DEPT_NM, CODE_01, CODE_02, CODE_03, INSERT_DATE, UPDATE_DATE, ADMIN_ID) VALUES (?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"),DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';

    dbConn.query(query, [dev_key, dev_type, dev_name, dev_dept_nm, code_01, code_02, code_03, id], function(error, result) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send({
                "dev_key": dev_key
            });
        }

    });
});

app.get('/defaultDevice', function(request, response) {
    logger.info('Path change : /defaultDevice');

    var code1 = request.param('code1');
    var code2 = request.param('code2');
    //var code3 = request.param('code3');
    var code3 = request.session.code_03;
    var type = request.param('type');

    var query = 'select * from TB_DEFAULT_CONNECT_INFO where CODE_01 = \'' + code1 + '\' and CODE_02 = \'' + code2 + '\' and CODE_03 = \'' + code3 + '\' and DEV_TYPE= \'' + type + '\'';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.all('/defaultDelete', function(request, response) {

    var dev_key = request.param('dev_key');
    var code1 = request.param('code1');
    var code2 = request.param('code2');
    var code3 = request.session.code_03;

    dbConn.query('delete from TB_DEFAULT_CONNECT_INFO where DEV_KEY = ? and CODE_01 = ? and CODE_02 = ? and CODE_03 = ?', [dev_key, code1, code2, code3], function() {
        response.send({
            "dev_key": dev_key
        });
    });
});

app.all('/deviceDelete', function(request, response) {

    logger.info('Path Change : /deviceDelete');

    var code1 = request.param('code1');
    var code2 = request.param('code2');

    var query = 'delete from TB_DEFAULT_CONNECT_INFO where CODE_01 = \'' + code1 + '\' and CODE_02 = \'' + code2 + '\' ';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(code1);
        }
    });

});

//----------------------------  PC Viewer ----------------------------------
app.get('/openVODViewer/:ctn', CheckAuthCommon, function (request, response) {

    logger.info('Path move : /openVODViewer');

    fs.readFile('html/PCViewer_VOD.html', 'utf-8', function (error, data) {

        response.send(ejs.render(data, {
            data: {
                'session' : request.session.userid, 'userlv' : request.session.userlv, 'url' : g_lcsAddrIP, 'vod_port' : g_lcsAccVodPort, 'svod_port' : g_lcsSVodPort,
                'video_encrypt': request.session.encrypt
            }
        }));
    });
});

app.get('/openPCViewerN', CheckAuthCommon, function (request, response) {

    logger.info('Path move : /openPCViewerN_pb');

    if (request.session.drone !== 'Y') {

        fs.readFile('html/PCViewerN_pb.html', 'utf-8', function (error, data) {


            var query;
            // query =	util.format('SELECT SV_OP_SV_V, SV_OP_SV_AR, b.DEV_KEY, c.ADMIN_NM, c.ADMIN_DEPT_NM, c.ADMIN_ARANK, c.VIEWER_DEBUG ' +
            //                     'FROM TB_CUSTOMER a ' +
            //                     'left join ( ' +
            //                         'SELECT DEV_KEY, CODE_03 ' +
            //                         'FROM TB_DEFAULT_CONNECT_INFO ' +
            //                         'WHERE CODE_01 = \'%s\' and CODE_02 = \'%s\' and CODE_03 = \'%s\' ' +
            //                         'and DEV_TYPE = (SELECT DEFAULT_DEVICE FROM TB_CONTROL where CODE_01 = \'%s\' and CODE_02 = \'%s\' and CODE_03 = \'%s\') ' +
            //                         ') b ' +
            //                     'ON a.CUSTOMER_CODE = b.CODE_03 ' +
            //                     'left join ( SELECT ADMIN_NM, ADMIN_DEPT_NM, ADMIN_ARANK, CODE_03, VIEWER_DEBUG FROM TB_ADMIN WHERE ADMIN_ID = \'%s\') c ' +
            //                     'ON a.CUSTOMER_CODE = c.CODE_03 ' +
            //                     'WHERE CUSTOMER_CODE = \'%s\'',request.session.code_01, request.session.code_02, request.session.code_03, request.session.code_01
            //                     ,request.session.code_02, request.session.code_03, request.session.userid, request.session.code_03);

            query =	util.format('SELECT SV_OP_SV_V, SV_OP_SV_AR, a.ADMIN_NM, a.ADMIN_DEPT_NM, a.ADMIN_ARANK, a.VIEWER_DEBUG FROM ' +
                                'TB_ADMIN a LEFT JOIN TB_CUSTOMER b ' +
                                'ON a.CODE_03 = b.CUSTOMER_CODE ' +
                                'WHERE a.ADMIN_ID = \'%s\' ', request.session.userid);

            var mVoIP;
            dbConn.query(query, function (error, results) {
                logger.info('Query:', query);
                if (error){
                    logger.error('DB Error:', error);
                    mVoIP = '';
                }else {
                    mVoIP = results[0].SV_OP_SV_V;
                }

                // var default_control = 0;
                // if (results[0].DEV_KEY == request.session.userid) default_control = 1

                response.send(ejs.render(data, {
                    data: {
                        'session' : request.session.userid, 'userlv' : request.session.userlv, 'mVoIP' : mVoIP, 'ARMemo' : results[0].SV_OP_SV_AR, 'userpw' : request.session.userpw,
                        'name': results[0].ADMIN_NM , 'dept_name': results[0].ADMIN_DEPT_NM, 'arank': results[0].ADMIN_ARANK, 'debug' : results[0].VIEWER_DEBUG, 'url' : g_lcsAddrIP,
                        'video_encrypt': request.session.encrypt
                    }
                }));
            });
        });
    } else {
        response.redirect('/notaccess');
    }
});

app.get('/openPCViewerN_pb', CheckAuthCommon, function (request, response) {

    // logger.info('Path move : /openPCViewerN_pb');

    // fs.readFile('html/PCViewerN_pb.html', 'utf-8', function (error, data) {

    //     var mVoIP;

    //     var query;
    //     query =	util.format('SELECT SV_OP_SV_V, SV_OP_SV_AR, b.DEV_KEY, c.ADMIN_NM, c.ADMIN_DEPT_NM, c.ADMIN_ARANK ' +
    //                         'FROM TB_CUSTOMER a ' +
    //                         'left join ( ' +
    //                             'SELECT DEV_KEY, CODE_03 ' +
    //                             'FROM TB_DEFAULT_CONNECT_INFO ' +
    //                             'WHERE CODE_01 = \'%s\' and CODE_02 = \'%s\' and CODE_03 = \'%s\' ' +
    //                             'and DEV_TYPE = (SELECT DEFAULT_DEVICE FROM TB_CONTROL where CODE_01 = \'%s\' and CODE_02 = \'%s\' and CODE_03 = \'%s\') ' +
    //                             ') b ' +
    //                         'ON a.CUSTOMER_CODE = b.CODE_03 ' +
    //                         'left join ( SELECT ADMIN_NM, ADMIN_DEPT_NM, ADMIN_ARANK, CODE_03 FROM TB_ADMIN WHERE ADMIN_ID = \'%s\') c ' +
    //                         'ON a.CUSTOMER_CODE = c.CODE_03 ' +
    //                         'WHERE CUSTOMER_CODE = \'%s\'',request.session.code_01, request.session.code_02, request.session.code_03, request.session.code_01
    //                         ,request.session.code_02, request.session.code_03, request.session.userid, request.session.code_03);

    //     dbConn.query(query, function (error, results) {
    //         logger.info('Query:', query);
    //         if (error){
    //             logger.error('DB Error:', error);
    //             mVoIP = '';
    //         }else {
    //             mVoIP = results[0].SV_OP_SV_V;
    //         }

    //         var default_control = 0;
    //         if (results[0].DEV_KEY == request.session.userid) default_control = 1

    //         response.send(ejs.render(data, {
    //             data: {'session' : request.session.userid, 'userlv' : request.session.userlv, 'mVoIP' : mVoIP, 'ARMemo' : results[0].SV_OP_SV_AR, 'userpw' : request.session.userpw, 'default_control': default_control,
    //                     'name': results[0].ADMIN_NM , 'dept_name': results[0].ADMIN_DEPT_NM, 'arank': results[0].ADMIN_ARANK}
    //         }));
    //     });
    // });
});

app.get('/openPCViewerPopup', CheckAuthCommon, function(request, response) {

    logger.info('Path move : /openPCViewerPopup');

    if (request.session.drone !== 'Y') {
        fs.readFile('PCViewerPopup.html', 'utf-8', function(error, data) {

            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        });
    } else {
        response.redirect('/notaccess');
    }    
});

app.post('/pcList', function(request, response) {

    logger.info('Path change: /pcList');

    pcViewerAPI.GetPCViewerList(dbConn, request.param('devKey'), request.param('devType'), function(results) {

        response.send(results);
    });
});

//mVoIP
app.post('/playCountPCViewerOfAccount', function(request, response) {
    logger.info('Path change: /playCountPCViewerOfAccount');

    pcViewerAPI.playCountPCViewerOfAccount(dbConn, request.param('devKey'), request.param('devType'), function(results) {

        response.send(results);
    });
});

app.get('/vodList', function(request, response) {

    logger.info('Path change: /vodList');

    pcViewerAPI.GetVodList(dbConn, request.param('CUST_CTN'), request.param('INSERT_DATE'), function(results) {

        response.send(results);
    });
});


app.post('/getViewerIndex', function(request, response) {

    logger.info('Path change: /getViewerIndex');

    pcViewerAPI.GetViewerIndex(dbConn, request.param('DEV_KEY'), request.param('DEV_TYPE'), function(results) {

        logger.info('getViewerIndex callback :', results);
        response.send(results);
    });
});

app.post('/getViewerIndex3', function(request, response) {

    logger.info('Path change: /getViewerIndex3');

    pcViewerAPI.GetViewerIndex3(dbConn, request.param('P_CUST_CTN'), request.param('P_INSERT_DATE'), request.param('DEV_KEY'), request.param('DEV_TYPE'), function(results) {

        logger.info('getViewerIndex3 callback :', results);
        response.send(results);
    });
});

app.post('/getServiceClassPCViewer', function(request, response) {
    logger.info('Path change: /getServiceClassPCViewer');

    pcViewerAPI.GetServiceClassPCViewer(dbConn, request.session.code_03, function(results) {
        logger.info('getServiceClassPCViewer callback :', results);
        response.send(results);
    });
});

app.post('/isAuthorityWriteNotice', CheckAuth, function (request, response) {
    logger.info('Path change: /isAuthorityWriteNotice');

    pcViewerAPI.isAuthorityWriteNotice(dbConn, request, response);
});

app.get('/OpenVideo', CheckAuth, function(request, response) {
    logger.info('Path move : /OpenVideo');

    var fileName = request.param('fileName');

    fs.readFile('open_video.html', 'utf-8', function(error, data) {

        response.send(ejs.render(data, {
            data: {
                'fileName': fileName
            }
        }));

    });
});
//---------------------------------------------------------------------------

function HrefVar(a, b) {
    var vara = a.split(b);
    var varb = vara[1].split("&");
    return varb[0]
}

function adminAuth(a, b, response) { //id, lv
    var auth = false;
    if (b == 1 || b == 2 || b == 3) {
        auth = true;
    }
    if (!auth) {
        //response.redirect('/login');
        return auth;
    }
    return auth;
}
//계정관리 page 인증

function CheckAuth(request, response, next) {
    if (typeof request.session.userid == 'undefined' || request.session.userlv == '3') {
        logger.info('CheckAuth:', request.session.userid)
        response.redirect('/');
    } else {
        next();
    }
}

function CheckAuthControl(request, response, next) {
    if (typeof request.session.userid == 'undefined' || request.session.userlv != '1') {
        logger.info('CheckAuth:', request.session.userid)
        response.redirect('/');
    } else {
        next();
    }
}

function CheckAuthCommon(request, response, next) {
    if (typeof request.session.userid == 'undefined') {
        logger.info('CheckAuth:', request.session.userid)
        response.redirect('/');
    } else {
        next();
    }
}

function CheckPwCommon(request, response, next) {
    if (typeof request.session.pass_change == 'undefined') {
        logger.info('CheckAuth:', request.session.pass_change)
        response.redirect('/');
    } else {
        next();
    }
}
function CheckAuthAccount(request, response, next) {
    if (typeof request.session.userid == 'undefined') {
        logger.info('CheckAuth:', request.session.userid);
        response.redirect('/');
    }else if(request.session.accountCheck != 'success') {
        logger.info('CheckAuth:', request.session.accountCheck);
        response.redirect('/notaccess');
    }
    else {
        request.session.accountCheck=null;
        next();
    }
} //계정관리 page 인증

function decryptArray(results) {
    if (Object.keys(results).length > 0) {
        for (var i = 0; i < results.length; i++) {

            //var keys = Object.keys;
            //for (var j in keys) {
            //if (keys[j] == "LOCATION_X" || keys[j] == "LOCATION_Y"){
            results[i].LOCATION_X = aes256cbc.decrypt(results[i].LOCATION_X);
            results[i].LOCATION_Y = aes256cbc.decrypt(results[i].LOCATION_Y);
            //}
            //}
        }
    }
    return results;
}
//---------------------------------------------------------------------------------------------
// App Server
//---------------------------------------------------------------------------------------------

// if (serverConf.StreamConnect) {
//     var appServerIP = '127.0.0.1';
//     var appServerPort = 12345;
//     var client;

//     var retryInterval = 3000;
//     var retriedTimes = 0;
//     var maxRetries = 10;

//     var socket = new net.Socket();

//     (function connect() {

//         function reconnect() {
//             if (retriedTimes >= maxRetries) {
//                 throw new Error('retriedTimes > maxRetries');
//             }

//             retriedTimes += 1;
//             setTimeout(connect, retryInterval);
//         }
//         var svip = {
//             port: appServerPort,
//             host: appServerIP,
//             localAddress: appServerIP,
//             localPort: 30000
//         };
//         //client = socket.connect(appServerPort, appServerIP, function() {
//         client = socket.connect(svip, function() {
//             logger.info('App Server tcp connected success');
//         });

//         client.on('connect', function() {

//             retriedTimes = 0;
//             logger.info('connect event emit');
//         });

//         var recvData = '';
//         client.on('data', function(data) {
//             logger.info('Noti message ocurred!');

//             parsingMessage(data);
//         });

//         client.on('close', function() {
//             logger.crit('Connection closed');

//             reconnect();
//         });

//         client.on('error', function(err) {
//             logger.crit('connect error', err);
//         });

//         //process.stdin.pipe(client, {end: false});
//     }());
// } //AppServer

// function parsingMessage(data) {

//     //logger.info('function : parsingMessage');
//     struct.parsingBodyData(data, function(error, header, body, unProcessedBuf) {
//         //    struct.parsingBodyData(data, function(error, header, body) {

//         if (error) {
//             logger.crit(error);
//         } else {
//             // if (header.resultCode != '0000') {
//             //     io.sockets.emit('B999', body);
//             // } else {
//                 switch (header.command) {
//                     case 'B100':
//                     case 'B102': // TOSS 기본 연결

//                         var resBody = 'MOBILE_NUM=' + body.MOBILE_NUM + '&CTN_DEVICE=' + body.CTN_DEVICE;
//                         var packet = struct.makeData(header.command, resBody);
//                         client.write(packet);
//                         io.sockets.emit(header.command, body);
//                         break;
//                     case 'B602':
//                     case 'B603':

//                         var lcsAccsUrl = 'http://' + g_lcsAccUrl + ':8080/toss/?CUST_CTN=' + body.MOBILE_NUM + '&amp;INSERT_DATE=' + body.P_INSERT_DATE + '&amp;LCS_FLMGNO=' + body.LCS_FLMGNO;

//                         var xml;
//                         xml = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:q0="http://lguplus/u3/esb" xmlns:q1="java:lguplus.u3.esb.osc115" xmlns:q2="java:lguplus.u3.esb.common" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n';
//                         xml += '<soapenv:Body>\n';
//                         xml += '<q0:Oscpc115>\n';
//                         xml += '<q0:RequestRecord>\n';
//                         xml += '<q1:ESBHeader>\n';
//                         xml += '<q2:ServiceID>OSC115</q2:ServiceID>\n';
//                         xml += '<q2:TransactionID>' + body.LCS_FLMGNO + '</q2:TransactionID>\n';
//                         xml += '<q2:SystemID>LCS000</q2:SystemID>\n';
//                         xml += '<q2:ErrCode></q2:ErrCode>\n';
//                         xml += '<q2:ErrMsg></q2:ErrMsg>\n';
//                         xml += '<q2:Reserved></q2:Reserved>\n';
//                         xml += '</q1:ESBHeader>\n';
//                         xml += '<q1:RequestBody>\n';
//                         xml += '<q1:Oscpc115RequestInVO>\n';
//                         xml += '<q1:lcsFlmgNo>' + body.LCS_FLMGNO + '</q1:lcsFlmgNo>\n';
//                         xml += '<q1:lcsFlmgDvCd>' + body.LCS_FLMGDV_CD + '</q1:lcsFlmgDvCd>\n';
//                         xml += '<q1:consNo>' + body.CONS_NO + '</q1:consNo>\n';
//                         xml += '<q1:consReqNo>' + body.CONS_REQNO + '</q1:consReqNo>\n';
//                         xml += '<q1:lcsUseBizIdntNo>' + body.LCS_USE_BIZIDNTNO + '</q1:lcsUseBizIdntNo>\n';
//                         xml += '<q1:lcsAccsUrl>' + lcsAccsUrl + '</q1:lcsAccsUrl>\n';
//                         xml += '<q1:prpsCoByPtyId>' + body.PRPSCOBYPTY_ID + '</q1:prpsCoByPtyId>\n';
//                         xml += '</q1:Oscpc115RequestInVO>\n';
//                         xml += '</q1:RequestBody>\n';
//                         xml += '</q0:RequestRecord>\n';
//                         xml += '</q0:Oscpc115>\n';
//                         xml += '</soapenv:Body>\n';
//                         xml += '</soapenv:Envelope>\n';
//                         var bodyString = xml;

//                         logger.info('toss bodyString:', bodyString);

//                         var headers = {
//                             'Content-Type': 'text/xml;charset=UTF-8',
//                             'Content-Length': bodyString.length,
//                             'soapAction': ''
//                         };

//                         // toss direct 접속
//                         var options = {
//                             host: TOSS_HOST,
//                             port: TOSS_PORT,
//                             //host: 'toss.lguplus.co.kr',

//                             //시험서버
//                             //host: '172.22.14.79',
//                             //host: 'test.toss.lguplus.co.kr',
//                             //port: 15011,
//                             path: '/CSSI/OSC/Oscpc115',
//                             method: 'POST',
//                             headers: headers
//                         };

//                         var callback = function(response) {
//                             //logger.info('callback1::: ');
//                             response.on('data', function(data) {

//                                 logger.info('toss response: ', data.toString());

//                                 var xmlparse = data;
//                                 var succYn;
//                                 var msg;
//                                 var transactionID;

//                                 parseString(xmlparse, function(err, result) {
//                                     //json 값 가져오기
//                                     if (err)
//                                         logger.crit('toss parse err:', err);

//                                     transactionID = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc115Response'][0]['ns3:ResponseRecord'][0]['q1:ESBHeader'][0]['q2:TransactionID'];
//                                     succYn = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc115Response'][0]['ns3:ResponseRecord'][0]['ResponseBody'][0]['Oscpc115ResponseOutVO'][0]['succYn'];
//                                     msg = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc115Response'][0]['ns3:ResponseRecord'][0]['ResponseBody'][0]['Oscpc115ResponseOutVO'][0]['msg'];
//                                     logger.info('toss transactionID:', transactionID);
//                                     logger.info('toss succYn:', succYn);
//                                     logger.info('toss msg:', msg);
//                                 });

//                                 //update : value
//                                 var query = 'UPDATE TB_TOSS_HISTORY SET RESULT=?, MESSAGE=?, RESPONSE_TIME = DATE_FORMAT(now(),"%Y%m%d%H%i%s")' +
//                                     ' WHERE LCS_FLMGNO=? AND DEL_FLAG=?';

//                                 //dbConn.query(query,[succYn, msg, body.MOBILE_NUM, body.P_INSERT_DATE,toss_map.get("lcsFlmgNo")], function (error, results) {
//                                 dbConn.query(query, [succYn, msg, transactionID, '0'], function(error, results) {
//                                     logger.info('Query:', query);

//                                     if (error) {
//                                         logger.error('DB Error:', error);
//                                     } else {
                                        
//                                     }
//                                 });
//                             });

//                             //the whole response has been recieved, so we just print it out here
//                             response.on('end', function() {
//                                 logger.info('end');
//                                 //console.log(succYn + '' + msg);
//                             });
//                         };

//                         //insert: body data (TB_TOSS_HISTORY)

//                         http.request(options, callback).write(bodyString);

//                         //var lcsAccsUrl = 'http://'+ g_lcsAccUrl + ':8080/toss/?CUST_CTN='+body.MOBILE_NUM + '&INSERT_DATE=' + body.P_INSERT_DATE + '&LCS_FLMGNO=' + toss_map.get("lcsFlmgNo");
//                         var lcsAccsUrl = 'http://' + g_lcsAccUrl + ':8080/toss/?CUST_CTN=' + body.MOBILE_NUM + '&INSERT_DATE=' + body.P_INSERT_DATE + '&LCS_FLMGNO=' + body.LCS_FLMGNO;

//                         var result = '';
//                         var query = 'INSERT INTO TB_TOSS_HISTORY ' +
//                             '(P_CUST_CTN, P_INSERT_DATE, LCS_FLMGNO, TOSS_TYPE, LCS_FLMGDV_CD, CONS_NO, CONS_REQNO, LCS_USE_BIZIDNTNO, LCS_ACCURL, PRPSCOBYPTY_ID, REQUEST_TIME, RESULT, DEL_FLAG) ' +
//                             'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?, ?)';

//                         //dbConn.query(query,[body.MOBILE_NUM, body.P_INSERT_DATE, toss_map.get("lcsFlmgNo"),toss_map.get("lcsFlmgDvCd"),toss_map.get("consNo"),toss_map.get("consReqNo"), lcsAccsUrl, toss_map.get("prpsCoByPtyId"),result], function (error, results) {
//                         dbConn.query(query, [body.MOBILE_NUM, body.P_INSERT_DATE, body.LCS_FLMGNO, '1', body.LCS_FLMGDV_CD, body.CONS_NO, body.CONS_REQNO, body.LCS_USE_BIZIDNTNO, lcsAccsUrl, body.PRPSCOBYPTY_ID, result, '0'], function(error, results) {
//                             logger.info('Query:', query);

//                             if (error) {
//                                 logger.error('DB Error:', error);
//                             } else {
                                
//                             }
//                         });
//                         break;
//                     case 'B410':
//                         body.LOCATION_X = aes256cbc.decrypt(body.LOCATION_X);
//                         body.LOCATION_Y = aes256cbc.decrypt(body.LOCATION_Y);
//                         io.sockets.emit(header.command, body);
//                         break
//                     case 'B400':
//                     case 'B500': // STB Status Message (noti)
//                     case 'B501': // Mobile Viewer Status Message (noti)
//                     case 'B600':
//                     case 'B601': // 단말 수신측 종료에 의한 Mobile 서비스 종료
//                     case 'B900': // PC Viewer 비정상 종료
//                     case 'B801': // PC Viewer 단말 송신측 종료 (noti)
//                     case 'B902': // PC Viewer
//                     case 'B231': // 공지사항 작성 배포
//                         io.sockets.emit(header.command, body);
//                         break;
//                         //#1 Start [2015.07.23] by ywhan
//                     case 'D002': // member join
//                         var resBody = 'MOBILE_NUM=' + body.MOBILE_NUM + '&CTN_DEVICE=' + body.CTN_DEVICE;
//                         var packet = struct.makeData(header.command, resBody);
//                         client.write(packet);

//                         var code_01 = body.CONTROL_ID.substring(0, 3);
//                         var code_02 = body.CONTROL_ID.substring(3, 6);
//                         var code_03 = body.CONTROL_ID.substring(6, 9);

//                         var query = util.format('SELECT CTN,NM,DEPT_NM,ARANK FROM TB_ORGANOGRAM WHERE CTN = \'%s\' and DEPT_CODE_01 = \'%s\' and DEPT_CODE_02 = \'%s\' and DEPT_CODE_03 = \'%s\'', body.MOBILE_NUM, code_01, code_02, code_03);

//                         dbConn.query(query, function(error, results) {
//                             logger.info('Query:', query);

//                             if (error) {
//                                 logger.error('DB Error:', error);
//                             } else {
                                

//                                 var voiceInfo;
//                                 if (Object.keys(results).length > 0) {
//                                     voiceInfo = merge(results[0], body);
//                                     logger.info('results + body merge');
//                                 } else {
//                                     logger.info('results emtpy');

//                                     var unknown = {
//                                         NM: body.MOBILE_NUM,
//                                         CTN: body.MOBILE_NUM,
//                                         DEPT_NM: "-",
//                                         ARANK: "-"
//                                     };
//                                     voiceInfo = merge(unknown, body);
//                                 }

//                                 logger.info('make D200');
//                                 var jsonData = struct.makeJsonTypeAddVoice(voiceInfo);
//                                 packet = struct.makeData('D200', jsonData);
//                                 client.write(packet);
//                             }
//                         });
//                         //#1 End
//                     case 'D001': // room create
//                         //io.sockets.emit(header.command, body);
//                     case 'B101': // Quick connect
//                     case 'D003': // member stb send request
//                     case 'B103': // TOSS Quick connect
//                     case 'B104': // Multi control

//                         if (header.resultCode != '0000') {
//                             io.sockets.emit('B998', body);
//                         } else {
//                             var query;
//                             var code_01 = body.CONTROL_ID.substring(0, 3);
//                             var code_02 = body.CONTROL_ID.substring(3, 6);
//                             var code_03 = body.CONTROL_ID.substring(6, 9);

//                             function fetchID(callback) {
//                                 var query1 = 'SELECT DEFAULT_DEVICE FROM TB_CONTROL ';
//                                 query1 += 'WHERE CODE_01 = \'' + code_01 + '\' AND CODE_02 = \'' + code_02 + '\' AND CODE_03 = \'' + code_03 + '\'';
//                                 dbConn.query(query1, function(err, rows) {
//                                     logger.info('Query: ', query1);
//                                     if (err) {
//                                         logger.error('DB Error: ', err);
//                                         callback(err, null);
//                                     } else {
//                                         if (Object.keys(rows).length > 0) {
//                                             callback(null, rows[0].DEFAULT_DEVICE);
//                                         } else {
//                                             callback(err, null);
//                                         }
//                                     }
//                                 });
//                             }

//                             var device, isService;
//                             fetchID(function(err, content) {
//                                 device = content;

//                                 if (device == STB) {

//                                     query = 'SELECT a.STB_MAC_ADDR,a.STB_NM ,a.STB_DEPT_NM,a.SVC_STB_IP,a.STB_DEPT_CODE_01,a.STB_DEPT_CODE_02,a.STB_DEPT_CODE_03,a.STB_LOCATION,a.STB_ADMIN_INFO,a.CTN_SEQ,b.STATUS';
//                                     query += ' FROM TB_STB_INFO a left join ( SELECT STATUS ,STB_MAC_ADDR FROM TB_STB_SERVICE WHERE STATUS < \'3\' ) b';
//                                     query += ' ON a.STB_MAC_ADDR = b.STB_MAC_ADDR';
//                                     query += ' WHERE STB_DEPT_CODE_01 =\'' + code_01 + '\' and STB_DEPT_CODE_02 = \'' + code_02 + '\' and STB_DEPT_CODE_03 =\'' + code_03 + '\' and b.STATUS is null';
//                                     query += ' GROUP BY a.STB_MAC_ADDR ORDER BY a.STB_DEPT_NM, a.STB_NM Limit 1';

//                                     dbConn.query(query, function(error, results) {
//                                         logger.info('Query:', query);

//                                         if (error) {
//                                             logger.error('DB Error:', error);
//                                         } else {
                                            

//                                             var jsonData;
//                                             if (Object.keys(results).length > 0) {
//                                                 logger.info('body:', body);
//                                                 var stbInfo = merge(results[0], body);
//                                                 jsonData = struct.makeJsonTypeAddSTB(stbInfo);
//                                                 isService = 'Y';
//                                             } else {
//                                                 isService = 'N';
//                                                 jsonData = struct.makeJsonTypeFullUse(body);
//                                             }


//                                             packet = struct.makeData(header.command, body, isService);
//                                             client.write(packet);


//                                             if (header.command == 'B101' || header.command == 'B103' || header.command == 'B104')
//                                                 packet = struct.makeData('B300', jsonData);
//                                             else
//                                                 packet = struct.makeData('D300', jsonData);
//                                             client.write(packet);
//                                         }
//                                     });

//                                 } else if (device == MOBILE || device == PC) {

//                                     query = 'SELECT DEV_KEY, DEV_NM, DEV_DEPT_NM';
//                                     query += ' FROM TB_DEFAULT_CONNECT_INFO';
//                                     query += ' WHERE CODE_01 =\'' + code_01 + '\' and CODE_02 = \'' + code_02 + '\' and CODE_03 =\'' + code_03 + '\' and DEV_TYPE = \'' + device + '\'';
//                                     query += ' ORDER BY DEV_DEPT_NM, DEV_NM';

//                                     dbConn.query(query, function(error, results) {
//                                         logger.info('Query:', query);

//                                         if (error) {
//                                             logger.error('DB Error:', error);
//                                         } else {
                                            

//                                             var jsonData;
//                                             if (Object.keys(results).length > 0) {
//                                                 logger.info('body:', body);

//                                                 isService = 'Y';
//                                                 packet = struct.makeData(header.command, body, isService);
//                                                 client.write(packet);

//                                                 var mobileArray = new Array();
//                                                 for (var i = 0; i < results.length; i++) {

//                                                     if (device == MOBILE) {
//                                                         var mobileInfo = new Object();

//                                                         mobileInfo.name = results[i].DEV_NM;
//                                                         mobileInfo.dept = 'iwsys'; //results[i].DEV_DEPT_NM;
//                                                         mobileInfo.ctn = results[i].DEV_KEY;
//                                                         mobileInfo.index = '0';
//                                                         mobileArray.push(mobileInfo);

//                                                         logger.info('mobileArrary push :', mobileInfo);

//                                                         // 결과값을 다 받으면 한번에 전송
//                                                         if (mobileArray.length == results.length) {
//                                                             var mobileInfoList = {};
//                                                             mobileInfoList.COMMAND = 'B302';
//                                                             mobileInfoList.CTN_DEVICE = body.CTN_DEVICE;
//                                                             mobileInfoList.MOBILE_NUM = body.MOBILE_NUM;
//                                                             mobileInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                                             mobileInfoList.VIEW_TYPE = device;
//                                                             mobileInfoList.mobileList = mobileArray;
//                                                             packet = struct.makeData(mobileInfoList.COMMAND, mobileInfoList);
//                                                             client.write(packet);
//                                                         }
//                                                     } else {
//                                                         pcViewerAPI.GetViewerIndex2(dbConn, results[i], device, function(obj, viewInfo) {
//                                                             logger.info('getViewerIndex callback :', obj[0].VIEW_INDEX);

//                                                             viewInfo.index = obj[0].VIEW_INDEX;

//                                                             var mobileInfo = new Object();
//                                                             mobileInfo.name = viewInfo.DEV_NM;
//                                                             mobileInfo.dept = viewInfo.DEV_DEPT_NM;
//                                                             mobileInfo.ctn = viewInfo.DEV_KEY;
//                                                             mobileInfo.index = viewInfo.index;
//                                                             mobileArray.push(mobileInfo);
//                                                             logger.info('mobileArrary push :', mobileInfo);

//                                                             // 결과값을 다 받으면 한번에 전송
//                                                             if (mobileArray.length == results.length) {
//                                                                 var mobileInfoList = {};
//                                                                 mobileInfoList.COMMAND = 'B302';
//                                                                 mobileInfoList.CTN_DEVICE = body.CTN_DEVICE;
//                                                                 mobileInfoList.MOBILE_NUM = body.MOBILE_NUM;
//                                                                 mobileInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                                                 mobileInfoList.VIEW_TYPE = device;
//                                                                 mobileInfoList.mobileList = mobileArray;
//                                                                 packet = struct.makeData(mobileInfoList.COMMAND, mobileInfoList);
//                                                                 client.write(packet);
//                                                             }
//                                                         });
//                                                     }
//                                                 }
//                                             } else {
//                                                 isService = 'N';
//                                                 packet = struct.makeData(header.command, body, isService);
//                                                 client.write(packet);

//                                                 jsonData = struct.makeJsonTypeFullUse(body);
//                                                 packet = struct.makeData('B302', jsonData);
//                                                 client.write(packet);
//                                             }
//                                         }
//                                     });
//                                 }
//                             });

//                             io.sockets.emit(header.command, body);
//                         }
//                         break;
//                     case 'B105' :
//                         var voiceArray = [];

//                         var fav_key = body.FAV_KEY;
//                         lcsServiceAPI.getBookMarkList(dbConn, fav_key, function (nestResult) {
//                             if (Object.keys(nestResult).length > 0) {

//                                 for (var i = 0; i < nestResult.length; i++) {
//                                     if (nestResult[i].DEV_TYPE == MOBILE) {

//                                         var viewArray = [];
//                                         var viewInfo = {};
//                                         viewInfo.name = nestResult[i].DEV_NM;
//                                         viewInfo.dept = nestResult[i].DEV_DEPT_NM;
//                                         viewInfo.ctn  = nestResult[i].DEV_KEY;
//                                         viewInfo.index = '0';
//                                         viewArray.push(viewInfo);

//                                         var viewInfoList = {};
//                                         viewInfoList.COMMAND = 'B302';
//                                         viewInfoList.CTN_DEVICE  = body.CTN_DEVICE;
//                                         viewInfoList.MOBILE_NUM  = body.MOBILE_NUM;
//                                         viewInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                         viewInfoList.VIEW_TYPE   = MOBILE;
//                                         viewInfoList.mobileList  = viewArray;

//                                         packet = struct.makeData('B302', viewInfoList);
//                                         client.write(packet);
//                                     } else if (nestResult[i].DEV_TYPE == STB) {

//                                         var stbArray = [];
//                                         var stbInfo = {};
//                                         stbInfo.name = nestResult[i].DEV_NM;
//                                         stbInfo.dept = nestResult[i].DEV_DEPT_NM;
//                                         stbInfo.mac  = nestResult[i].DEV_KEY;
//                                         stbArray.push(stbInfo);

//                                         var stbInfoList = {};
//                                         stbInfoList.COMMAND = 'B300';
//                                         stbInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                         stbInfoList.CTN_DEVICE = body.CTN_DEVICE;
//                                         stbInfoList.MOBILE_NUM = body.MOBILE_NUM;
//                                         stbInfoList.stbList = stbArray;

//                                         packet = struct.makeData('B300', stbInfoList);
//                                         client.write(packet);
//                                     } else if (nestResult[i].DEV_TYPE == PC){

//                                         pcViewerAPI.GetViewerIndex2(dbConn, nestResult[i], PC, function (obj, viewInfo) {
//                                             logger.info('getViewerIndex callback :', obj[0].VIEW_INDEX);

//                                             var pcArray = [];
//                                             var pcInfo = {};
//                                             pcInfo.name = viewInfo.DEV_NM;
//                                             pcInfo.dept = viewInfo.DEV_DEPT_NM;
//                                             pcInfo.ctn  = viewInfo.DEV_KEY;
//                                             pcInfo.index = obj[0].VIEW_INDEX;
//                                             pcArray.push(pcInfo);
//                                             logger.info('pcArray push :', pcInfo);

//                                             var viewInfoList = {};
//                                             viewInfoList.COMMAND = 'B302';
//                                             viewInfoList.CTN_DEVICE  = body.CTN_DEVICE;
//                                             viewInfoList.MOBILE_NUM  = body.MOBILE_NUM;
//                                             viewInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                             viewInfoList.VIEW_TYPE   = PC;
//                                             viewInfoList.mobileList  = pcArray;
//                                             packet = struct.makeData('B302', viewInfoList);
//                                             client.write(packet);
//                                         });
//                                     } else { // VOICE
//                                         //if (body.TEL_YN == 'Y') {
//                                             var voiceInfo = {};
//                                             voiceInfo.name = nestResult[i].DEV_NM;
//                                             voiceInfo.dept = nestResult[i].DEV_DEPT_NM;
//                                             voiceInfo.ctn  = nestResult[i].DEV_KEY;
//                                             voiceInfo.arank = '-';
//                                             voiceArray.push(voiceInfo);
//                                             logger.info('voiceArray push :', voiceInfo);
//                                         //}
//                                     }
//                                 }
//                             }
//                         });

//                         if (body.TEL_YN == 'Y') {

//                             var code_01 = body.CONTROL_ID.substring(0,3);
//                             var code_02 = body.CONTROL_ID.substring(3,6);
//                             var code_03 = body.CONTROL_ID.substring(6,9);

//                             lcsServiceAPI.getPhoneNumberOfControl(dbConn, code_01, code_02, code_03, function (obj) {
//                                 logger.info('getPhoneNumberOfControl:', obj[0].CTL_TEL_NUM);

//                                 var voiceInfo2 = {};
//                                 voiceInfo2.name = obj[0].CTL_NM;
//                                 voiceInfo2.dept = obj[0].CTL_ADMIN_NM;
//                                 voiceInfo2.ctn  = obj[0].CTL_TEL_NUM;
//                                 voiceInfo2.arank = '-';
//                                 voiceArray.push(voiceInfo2);

//                                 var voiceInfoList = {};
//                                 voiceInfoList.COMMAND = 'B200';
//                                 voiceInfoList.CTN_DEVICE  = body.CTN_DEVICE;
//                                 voiceInfoList.MOBILE_NUM  = body.MOBILE_NUM;
//                                 voiceInfoList.INSERT_DATE = body.P_INSERT_DATE;
//                                 voiceInfoList.voiceList  = voiceArray;

//                                 packet = struct.makeData('B200', voiceInfoList);
//                                 logger.info('B105 packet send');
//                                 client.write(packet);
//                             });
//                         }
//                         break;
//                     case 'B202': // 영상 서비스 중 mVoIP통화 연결을 하면 푸시

//                         var code_01 = body.CONTROL_ID.substring(0, 3);
//                         var code_02 = body.CONTROL_ID.substring(3, 6);
//                         var code_03 = body.CONTROL_ID.substring(6, 9);

//                         // 관제센터 디폴트가 mobile이 아니고 mVoIP 연결계정이 있을 경우 푸시 메세지 전송
//                         logger.info('getCallId callback');

//                         function getCallId(callback) {
//                             var query3 = 'SELECT *, b.SV_OP_SV_V,c.DEV_KEY FROM TB_CONTROL a left join TB_CUSTOMER b ON a.CODE_03 = b.CUSTOMER_CODE';
//                             query3 += ' left join (SELECT * FROM TB_DEFAULT_CONNECT_INFO WHERE DEV_TYPE = \'1\') c ';
//                             query3 += ' ON a.CODE_01 = c.CODE_01 and a.CODE_02 = c.CODE_02 and a.CODE_03 = c.CODE_03 AND a.DEFAULT_DEVICE = c.DEV_TYPE'
//                             query3 += ' WHERE a.CODE_01 = \'' + code_01 + '\' AND a.CODE_02 = \'' + code_02 + '\' AND a.CODE_03 = \'' + code_03 + '\'';
//                             dbConn.query(query3, function(err, rows) {
//                                 logger.info('Query: ', query3);
//                                 if (err) {
//                                     logger.error('DB Error: ', err);
//                                     callback(err, null);
//                                 } else {
//                                     if (Object.keys(rows).length > 0) {
//                                         callback(null, rows[0]);
//                                     } else {
//                                         callback(err, null);
//                                     }
//                                 }
//                             });
//                         }

//                         getCallId(function(err, content) {
//                             if (content == null) {
//                                 logger.info('control is null');
//                                 return;
//                             }
//                             logger.info('CALL_ID : ', content.CALL_ID);
//                             //if (content.SV_OP_SV_V == 'Y' && body.CALL_TYPE == 'M' && body.F_CALL_TYPE == '1') {
//                             if (content.SV_OP_SV_V == 'Y' && body.CALL_TYPE == 'M') {
//                                 //if(content.DEFAULT_DEVICE != MOBILE || content != '-') {
//                                 if (body.F_CALL_TYPE == '1') { // mobile 일 경우  gcm push
//                                     logger.info('DEV_KEY : ' + content.DEV_KEY + '	F_MOBILE_NUM : ' + body.F_MOBILE_NUM);
//                                     // 디폴트가 모바일이고 관제탑 전화번호와 디폴트 모바일 전화번호가 다를 경우 관제탑 전화로  mVoIP로 연결하기 위해 푸시
//                                     if (body.F_MOBILE_NUM != content.DEV_KEY) {
//                                         var voiceInfo = {};
//                                         voiceInfo.name = content.CTL_NM;
//                                         voiceInfo.device_id = content.
//                                         //voiceInfo.ctn = content.CTL_TEL_NUM;
//                                         voiceInfo.ctn = body.F_MOBILE_NUM;
//                                         voiceInfo.view_ctn_device = body.VIEW_CTN_DEVICE;
//                                         voiceInfo.dept = content.CTL_ADMIN_NM;
//                                         voiceInfo.arank = '';

//                                         var voiceArray = [];
//                                         voiceArray.push(voiceInfo);

//                                         var push_data = {};
//                                         push_data.INSERT_DATE = body.P_INSERT_DATE;
//                                         push_data.CTN_DEVICE = body.CTN_DEVICE;
//                                         push_data.MOBILE_NUM = body.MOBILE_NUM;
//                                         push_data.CALL_TYPE = '1';
//                                         push_data.mobileList = voiceArray;

//                                         push_gcm(push_data);
//                                     }
//                                 } else { // 3 : pc 일 경우
//                                     io.sockets.emit(header.command, body);
//                                 }
//                             }
//                         })
//                         break;
//                     case 'D099': // room destroy
//                         var packet = struct.makeData(header.command, body);
//                         client.write(packet);
//                         io.sockets.emit(header.command, body);
//                         break;
//                     case 'B200': // Voice 추가 응답
//                     case 'B300': // STB 추가 응답
//                     case 'B302': // Viewer 추가 응답
//                     case 'B303': // Viewer 삭제 응답

//                         // error 응답 처리
//                         if (header.resultCode != '0000') {
//                             io.sockets.emit('B999', body);
//                         } else {

//                             // Mobile이고 추가 했을 경우는 PUSH 메세지 전송
//                             if (header.command == 'B302' && body.VIEW_TYPE == MOBILE) {

//                                 //add mobile 응답 확인 후에 PUSH MESSAGE 전송을 해야 함
//                                 var mobileArray = new Array();

//                                 var mobileInfo = new Object();
//                                 mobileInfo.ctn = body.VIEW_NUM;
//                                 mobileInfo.view_ctn_device = body.VIEW_CTN_DEVICE;
//                                 mobileArray.push(mobileInfo);

//                                 var mobileInfoList = new Object();
//                                 mobileInfoList.INSERT_DATE = body.LAST_DATE;
//                                 mobileInfoList.MOBILE_NUM = body.MOBILE_NUM;
//                                 mobileInfoList.DEV_NM = body.DEV_NM;
//                                 mobileInfoList.DEV_DEPT_NM = body.DEV_DEPT_NM;
//                                 mobileInfoList.mobileList = mobileArray;

//                                 var default_flag = body.DEFAULT_FLAG;
//                                 if (default_flag == '1') { // 기본연결이고 관제탑 전화번호와 수신 단말의 전화번호가 같을 경우 5초 딜레이
//                                     setTimeout(function() { push_gcm(mobileInfoList); }, 5000);
//                                 } else {
//                                     push_gcm(mobileInfoList);
//                                 }
//                             }else if(header.command == 'B302' && body.VIEW_TYPE == PC) {
//                                 var query = 'INSERT INTO TB_LOCATION_ADMIN_MAPPING ' +
//                                     '(P_CUST_CTN, P_INSERT_DATE, STATUS, ADMIN_ID, INSERT_DATE ) VALUES (\'' + body.MOBILE_NUM + '\', \'' + body.LAST_DATE + '\',7,\'' + body.VIEW_NUM + '\',DATE_FORMAT(now(),"%Y%m%d%H%i%s") ) ';
//                                 dbConn.query(query, function(error, result) {
//                                     logger.info('Query:', query);
//                                     if (error) {
//                                         logger.error('DB Error', error);
//                                     } else {
                                        
//                                     }
//                                 });
//                             }

//                             io.sockets.emit(header.command, body);
//                         }
//                         break;
//                     case 'B304': // 영상 서비스 수신 시작
//                     case 'B305': // 영상 서비스 수신 종료
//                         // error 응답 처리
//                         if (header.resultCode == '0009') {
//                             io.sockets.emit('B998', body);
//                         } else if (header.resultCode == '0099') {
//                             io.sockets.emit('B997', body);
//                         } else {
//                             io.sockets.emit(header.command, body);
//                         }
//                         break;
//                     case 'B001': // reg id 등록 /수정

//                         pushServiceAPI.checkValidRegID(dbConn, body, function(error, results) {

//                             var date = new Date().formatDate("yyyyMMddhhmmss");
//                             if (Object.keys(results).length == 0) { // regId 최초등록

//                                 var query = util.format('INSERT INTO TB_PUSH_REG_INFO (DEV_KEY, DEV_TYPE, REG_ID, REG_STATUS, INSERT_DATE, UPDATE_DATE) VALUES' +
//                                     '( \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\')', body.MOBILE_NUM, '1', body.REG_ID, '1', date, date);
//                             } else { // update

//                                 var query = util.format('UPDATE TB_PUSH_REG_INFO SET REG_ID = \'%s\', UPDATE_DATE = \'%s\' WHERE DEV_KEY = \'%s\' and DEV_TYPE = \'%s\'', body.REG_ID, date, body.MOBILE_NUM, '1');

//                             }

//                             var responseValue;
//                             dbConn.query(query, function(error, result) {

//                                 logger.info('Query:', query);

//                                 if (error) {
//                                     responseValue = '1';
//                                     logger.error('DB Error:', error);
//                                 } else {
                                    
//                                     responseValue = '0';
//                                 }

//                                 var resBody = 'REG_RST=' + responseValue + '&MOBILE_NUM=' + body.MOBILE_NUM;
//                                 var packet = struct.makeData(header.command, resBody);
//                                 client.write(packet);
//                             });
//                         });
//                         break;
//                     case 'B003':
//                         pushServiceAPI.insertPushResponseHistory(dbConn, body, function() {

//                             logger.info('insertPushResponseHistory end');

//                             var packet = struct.makeData(header.command, '');
//                             client.write(packet);

//                             io.sockets.emit(header.command, body);
//                         });
//                         break;
//                     case 'B216' :
//                         if (header.reqType == 1) io.sockets.emit(header.command, body);
//                             break;
//                     // drone message
//                     case 'B207' :
//                         var resData = {};
//                         resData.header = header;
//                         resData.body = body;
//                         droneResult.emit('startRecording', resData);
//                         break;
//                     case 'B903' :
//                         var resData = {};
//                         resData.header = header;
//                         resData.body = body;
//                         droneResult.emit('stopRecording', resData);
//                         break;
//                     case 'B170' :
//                         var resData = {};
//                         resData.header = header;
//                         resData.body = body;
//                         droneResult.emit('startSnapshot', resData);
//                         if (body.JUST_UPLOAD_FLAG == '1') { // 실시간 업로드 요청일 경우에만 폴더 생성
//                             var folderName = new Date().formatDate("yyyyMMddhhmmss");
//                             cloudLib.createFolder(body.USER_ID, body.MOBILE_NUM, '2', folderName, body.IDENTIFICATION, function(err, bResult, result) {
//                                 logger.info(err, bResult, result);
//                             });
//                         }
//                         break;
//                     case 'B171' :
//                         var resData = {};
//                         resData.header = header;
//                         resData.body = body;
//                         droneResult.emit('upload', resData);
//                         var folderName = new Date().formatDate("yyyyMMddhhmmss");
//                         cloudLib.createFolder(body.USER_ID, body.MOBILE_NUM, '1', folderName, body.IDENTIFICATION, function(err, bResult, result) {
//                             logger.info(err, bResult, result);
//                         });
//                         break;
//                     case 'B172':    // 파일 전체 업로드 완료
//                         io.sockets.emit(header.command, body);
//                         break;
//                     case 'B173' :   // 파일 [드론 클라이언트] -> [중계서버] 업로드 완료
//                         // [중계서버] -> [유클라우드] 업로도 수행
//                         if (body.USER_ID != "undefined") {      // 웹서버 재부팅으로 세션이 없을 때는 처리 안하도록
//                             var fileInfo = {};
//                             fileInfo.uploadName = body.FILENAME;
//                             fileInfo.uploadSize = body.FILESIZE;
//                             fileInfo.uploadFile = body.PATH + '/' + body.FILENAME;
//                             // cloudLib.uploadRequest(body, fileInfo);
//                             this.setTimeout(function() { 
//                                 cloudLib.uploadRequest('new', body, fileInfo); 
//                             }, 2000);
//                             // cloudLib.uploadRequest('new', body, fileInfo);
//                             io.sockets.emit(header.command, body);
//                         } else {
//                             io.sockets.emit('serverdown');
//                         }                        
//                         break;
//                     default:
//                         var protocolMsg = merge(header, body);
//                         io.sockets.emit(header.command, protocolMsg);
//                         break;
//                 }
//             //}

//             logger.info('Noti message emit:', header.command);

//             if (unProcessedBuf.length > 0) {
//                 logger.info('recursive coupled massage data  <== ', unProcessedBuf.toString());
//                 parsingMessage(unProcessedBuf);
//             }
//         }
//     });
// }


//---------------------------------------------------------------------------------------------
// client socket.io
//---------------------------------------------------------------------------------------------
var packet;
// var io = require('socket.io').listen(server);
// io.sockets.on('connection', function (socket) {
//     id = socket.id;

//     logger.info("socket.io connection:", id);
//     socket.on('addVoice', function(data) {
//     	logger.info('Add Voice Event occurred.');
//     	//logger.info('Receive Data:', data);

//         packet = struct.makeData(data.COMMAND, data);

//         //logger.info('packet:', packet);
//         var retVal = client.write(packet, function(){
//             if (retVal){
//             	logger.info('packet write success');
//                 //io.sockets.connected[id].emit('insertVoiceList', data);
//                 logger.info('socket emit msgEvent / id:', id);

//                 // 관제센터 영상 추가 시 푸시 메세지
//                 if(data.mVoIP == 'Y' && data.CALL_TYPE == '1') {
//                 	data.mobileList = data.voiceList;
//                 	push_gcm(data);
//                 }
//             } else{
//             	logger.info('packet write fail');
//             }
//         });
//     });

//     socket.on('retryVoice', function(data) {
//     	logger.info('retryVoice Event occurred.');

//         packet = struct.makeData(data.COMMAND, data);

//         var retVal = client.write(packet, function(){
//             if (retVal){
//             	logger.info('packet write success');
//                 var query = util.format('update TB_TERMINAL_IMAGE_TRANS set CTN_CNT=IFNULL(CTN_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
//                     ,data.voiceList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
//                 dbConn.query(query, function (error, results) {

//                 	logger.info('Query:', query);

//                     if (error){
//                     	logger.error('DB Error:', error);
//                     }else {
                    	
//                     }
//                 });
//             } else{
//             	logger.error('packet write fail');
//             }
//         });
//     });

//     socket.on('addSTB', function(data) {
//     	logger.info('Add STB event occurred');
    
//         packet = struct.makeData(data.COMMAND, data);

//         var retVal = client.write(packet, function(){
//             if (retVal){
//             	logger.info('packet write success');

//                 var query = util.format('update TB_TERMINAL_IMAGE_TRANS set STB_CNT=IFNULL(STB_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
//                     ,data.stbList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
//                 dbConn.query(query, function (error, results) {

//                 	logger.info('Query:', query);

//                     if (error){
//                     	logger.error('DB Error:', error);
//                     }else {
                    	
//                         //response.send(results);
//                     }
//                 });

//                 logger.info('socket emit msgEvent / id:', id);
//             } else{
//             	logger.error('packet write fail');
//             }
//         });
//     });

//     socket.on('retrySTB', function(data) {
//     	logger.info('retrySTB event occurred');
//     	//logger.info('Receive Data:', data);
//         packet = struct.makeData(data.COMMAND, data);

//         //logger.info('packet:', packet);
//         var retVal = client.write(packet, function(){
//             if (retVal){
//             	logger.info('packet write success');

//                 var query = util.format('update TB_TERMINAL_IMAGE_TRANS set STB_CNT=IFNULL(STB_CNT, 0)+%d where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\''
//                     ,data.stbList.length, data.MOBILE_NUM, data.CTN_DEVICE, data.INSERT_DATE);
//                 dbConn.query(query, function (error, results) {

//                 	logger.info('Query:', query);

//                     if (error){
//                     	logger.error('DB Error:', error);
//                     }else {
                    	
//                         //response.send(results);
//                     }
//                 });

//             } else{
//             	logger.error('packet write fail');
//             }
//         });
//     });

//     socket.on('deleteSTB', function(data) {
//     	logger.info('Delete STB event occurred', data);
//     	//logger.info('Receive Data:', data);
//         packet = struct.makeData(data.COMMAND, data);
//         //logger.info('packet:', packet);

//         var retVal = client.write(packet, function(){
//         });

//     });

// 	socket.on('addMobile', function(data) {
// 		logger.info('addMobile event occurred');
// 		packet = struct.makeData(data.COMMAND, data);

// 		var retVal = client.write(packet, function() {
// 			logger.info('addMobile packet was sent to Application Server');
// 		});
// 	});

// 	socket.on('deleteMobile', function(data) {
// 		logger.info('deleteMobile event occurred');
// 		//logger.info('Receive Data:', data);
// 		packet = struct.makeData(data.COMMAND, data);
// 		//logger.info('packet:', packet);

// 		var retVal = client.write(packet, function() {
// 			logger.info('deleteMobile packet was sent to Application Server');
// 		});
// 	});
// 	//#2 End

//     socket.on('changeSetupEvent', function(data) {

//     	logger.info('changeSetupEvent occured');

//         if (data.COMMAND == "B708")
//             packet = struct.makeData(data.COMMAND, data);
//         else
//             packet = struct.makeData(data, '');

//         logger.info('make changeSetupEvent message');
//         var retVal = client.write(packet, function() {
//             if (retVal) {
//             	logger.info('changeSetupEvent to AppServer was sent');
//             }
//         });
//     });


// 	socket.on('socketControl', function(data) {
// 		logger.info('socketControl event occurred');
// 		packet = struct.makeData(data.COMMAND, data);

// 		var retVal = client.write(packet, function() {
// 			logger.info('socketControl packet was sent to Application Server');
// 		});
// 	});


//     socket.on('service_close', function(data) {

//     	logger.info('service_close occured');

//         var resBody = 'MOBILE_NUM='+data.MOBILE_NUM+'&CTN_DEVICE='+data.CTN_DEVICE+'&INSERT_DATE='+data.INSERT_DATE;
//         packet = struct.makeData(data.COMMAND, resBody);

//         logger.info('make service_close message');
//         var retVal = client.write(packet, function() {
//             if (retVal) {
//             	logger.info('service_close to AppServer was sent');
//             }
//         });
//     });

//     socket.on('startStream', function (data) {

//         logger.info('startStream event occured!');
//         packet = struct.makeData(data.COMMAND, data);

//         var retVal = client.write(packet, function () {
//             if (retVal) {
//                 logger.info('startStream event to AppServer was sent');
//             }
//         });
//     });

//     socket.on('EndStream', function (data) {

//         logger.info('endStream event occured!');
//         packet = struct.makeData(data.COMMAND, data);

//         var retVal = client.write(packet, function () {
//             if (retVal) {
//                 logger.info('endStream event to AppServer was sent');
//             }
//         });
//     });

//     socket.on('Abnormal', function (data) {

//         logger.info('Abnormal event occured!');
//         packet = struct.makeData(data.COMMAND, data);

//         var retVal = client.write(packet, function () {
//             if (retVal) {
//                 logger.info('Abnormal event to AppServer was sent');
//             }
//         });
//     });

//     //# start 20170828 by ywhan
//     // VOD Play range
//     socket.on('B306', function (data) {
// 		logger.info('B306 event occured');
// 		packet = struct.makeData(data.COMMAND, data);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B306 event to AppServer was sent');
// 		});
//     });

//     // VOD Pause
//     socket.on('B307', function (data) {
// 		logger.info('B307 event occured');
// 		packet = struct.makeData(data.COMMAND, data);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B307 event to AppServer was sent');
// 		});
//     });
//     //# end

//     //# start 20170531 by ywhan
//     // AR Memo set up message [B210]
// 	socket.on('B210', function (data) {
// 		logger.info('B210 event occured');
// 		packet = struct.makeData(data.COMMAND, data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B210 event to AppServer was sent');
// 		});
// 	});
// 	// AR Memo play message [B211]
// 	socket.on('B211', function (data) {
// 		logger.info('B211 event occured');
// 		packet = struct.makeData(data.COMMAND, data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B211 event to AppServer was sent');
// 		});
// 	});
// 	// AR Memo add new pcviewer message [B212]
// 	socket.on('B212', function (data) {
// 		logger.info('B212 response event occured');
// 		//packet = struct.makeData(data.COMMAND, data.BODY);
// 		packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B212 event to AppServer was sent');
// 		});
// 	});

// 	// AR Memo History pcviewer message [B214]
// 	socket.on('B214', function (data) {
//         logger.info('B214 event occured');
//         packet = struct.makeData(data.COMMAND, data.BODY);

//         var retVal = client.write(packet, function(){
//             logger.info('B214 event to AppServer was sent');
//         });
//     });

// 	// AR Memo status notice message [B215]
// 	socket.on('B215', function (data) {
// 		logger.info('B215 event occured');
// 		packet = struct.makeData(data.COMMAND, data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B215 event to AppServer was sent');
// 		});
// 	});
// 	// AR Memo stop message [B216]
// 	socket.on('B216', function (data) {
// 		logger.info('B216 event occured');
// 		if (data.METHOD == "request") {
// 			logger.info('B216 request event occured');
// 			packet = struct.makeData(data.COMMAND, data.BODY);
// 		} else {
// 			logger.info('B216 response event occured');
// 			packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);
// 		}

// 		var retVal = client.write(packet, function(){
// 			logger.info('B216 event to AppServer was sent');
// 		});
// 	});
//     //# end 20170531

//     // notice wirte request [B230]
// 	socket.on('B230', function (data) {
// 		logger.info('B230 event occured');
// 		packet = struct.makeData(data.COMMAND, data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B230 event to AppServer was sent');
// 		});
// 	});

//     // notice recieve response [B231]
// 	socket.on('B231', function (data) {
// 		logger.info('B231 response event occured');
// 		packet = struct.makeResponseData(data.COMMAND, "0000", data.BODY);

// 		var retVal = client.write(packet, function(){
// 			logger.info('B231 event to AppServer was sent');
// 		});
// 	});

//     socket.on('log_OperatePCViewer', function (data) {

//         var logMsg;
//         logMsg = 'OperatePCViewer' + ' [' + data.USER_ID + ']' + '[' + data.DIR + ']' + '[' + data.OPERATE + ']' + '[' + data.PARAM + ']' + ' : ' + data.RESULT;
//         logger.info(logMsg);
//     });
// });


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
    pushServiceAPI.GetRegIds(dbConn, regQueue[0], function(tarGetInfo, regIdGrp) {

        // mVoIP
        if (typeof tarGetInfo.CALL_TYPE == "undefined" || tarGetInfo.CALL_TYPE == null) tarGetInfo.CALL_TYPE = 3;
        if (tarGetInfo.CALL_TYPE == 1) {
            tarGetInfo.title = '[IIOT-LIVECAM] mVoIP 음성 서비스';
            //tarGetInfo.content = tarGetInfo.MOBILE_NUM + '/' + tarGetInfo.DEV_NM + '/' + tarGetInfo.DEV_DEPT_NM + '로 부터 수신 받은 영상을 확인하시겠습니까?';
            tarGetInfo.content = tarGetInfo.MOBILE_NUM + '로부터 통화요청이 왔습니다.\n\n통화연결을 하시겠습니까?';
            //XX관제센터에서 통화요청이 왔습니다. 통화연결을 하시겠습니까?
            tarGetInfo.MSG_TYPE = 'CALL';
            tarGetInfo.PUSH_TYPE = '3';
        } else {
            tarGetInfo.title = '[IIOT-LIVECAM] 영상 수신 서비스';
            tarGetInfo.content = tarGetInfo.MOBILE_NUM + '/' + tarGetInfo.DEV_NM + '/' + tarGetInfo.DEV_DEPT_NM + '로 부터 수신 받은 영상을 확인하시겠습니까?';
            tarGetInfo.MSG_TYPE = 'VIEW';
            tarGetInfo.PUSH_TYPE = '1';
        }
        pushMessage(tarGetInfo, regIdGrp);
    });
}

var retransCount = 0;

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
        pushServiceAPI.insertResult(dbConn, info, registrationIds, response);

        //-- 응답 결과 분석 후 reg_id DB 수정
        pushServiceAPI.manageRegID(dbConn, info, response, function(ret) {

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


//공지사항  push Message Send
app.all('/noticepush', CheckAuth, function(request, response) {

    var message = request.param('title');
    var insert_date = request.param('insert_date');
    var cust_ctn = request.session.mobile_num;
    var seq = request.param('seq');
    var code3 = request.session.code_03;
    //console.log('session cust_ctn : ', cust_ctn);
    //console.log('session insert_date : ', insert_date);

    var dbRegistrationIdUpdate = []; //디비업데이트 정보 push

    var date = new Date();
    var senddate = date.formatDate("yyyyMMddhhmmss") + '' + utilLib.leftPad(date.getMilliseconds(), '0', 3);

    //console.log(seq + ']]]' + senddate);
    var query1 = 'update TB_NOTICE_POPUP set N_SENDDATE = ? where SEQ=?';

    dbConn.query(query1, [senddate, seq], function(err, result) {

        logger.info('Query: ', query1);
        if (err) {
            logger.error('DB Error:', err);
        } else {
            //
        }
    });

    var query2 = "UPDATE TB_TN_SERVICE SET N_READ_FLAG = '0' WHERE P_CUST_CTN = '" + seq + "'";
    dbConn.query(query2, function (error, results) {

        logger.info('Query:', query2);

        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
        }
    });

    var query = "SELECT DEV_KEY, DEV_TYPE, REG_ID, REG_STATUS, a.INSERT_DATE, a.UPDATE_DATE " +
    "FROM TB_PUSH_REG_INFO a LEFT JOIN TB_ORGANOGRAM b ON a.DEV_KEY = b.CTN " +
    "WHERE b.CTN IS NOT NULL AND b.BLOCK_FLAG = 'N'" +
    "ORDER BY DEV_KEY";

    var cnt = 0;
    var r_count = 0; //재전송

    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
            callback(error, null);
        } else {
            //타이틀, 디비데이타, 0, 10(범위), db 업데이트, notice insert시간, 발신자 번호
            gcm_go(message, results, 0, 1000, dbRegistrationIdUpdate, insert_date, cust_ctn, seq, r_count);
            response.send({"result" : "success"});
        }
    });
});


// push Message Send ( 메세지내용, 디비정보, 시작cnt, 마지막cnt, 디비업데이트 정보,notice insert시간, 발신자 번호 push)
function gcm_go(messages, results, sCnt, fCnt, dbRegistrationIdUpdate, insert_date, cust_ctn, seq, r_count) {

    //console.log('session cust_ctn1 : ', cust_ctn);
    //console.log('session insert_date1 : ', insert_date);

    var sender = new gcm.Sender(serverConf.server_access_key);
    var registrationIds = []; // 여기에 pushid 문자열을 넣는다.
    var ctn = [];

    var limitScap = 1000; //범위 (10개씩 push Message Send)

    var fCntFor = fCnt;
    var sCnt_b = sCnt + limitScap;
    var fCnt_b = fCnt + limitScap;

    var process = ""; //프로세스종료
    if (fCnt >= results.length) {
        fCntFor = results.length;
        process = "out";
    }

    //registrationId 범위만큼 추가
    for (var j = sCnt; j < fCntFor; j++) {
        //registrationIds.push(token3);
        registrationIds.push(results[j].REG_ID);
        ctn.push(results[j].DEV_KEY);
    }

    var message = new gcm.Message();

    var date = new Date();
    var req_time = date.formatDate("yyyyMMddhhmmss") + '' + date.getMilliseconds();

    var TITLE = "공지사항";
    var MESSAGE = messages;
    var CUST_KEY = date.getTime();

    message.addData('P_CUST_CTN', cust_ctn);
    message.addData('P_INSERT_DATE', insert_date);
    message.addData('CUST_KEY', CUST_KEY);
    message.addData('MSG_TYPE', 'NOTI');
    message.addData('PUSH_TYPE', '2');
    message.addData('TITLE', TITLE);
    message.addData('MESSAGE', MESSAGE);
    message.addData('REQUEST_TIME', req_time);

    var re_msg_id = "";

    sender.send(message, {
        registrationTokens: registrationIds
    }, 1, function(err, response) {

        if (err) {
            logger.crit('notice push send error:', err);

            //insert TB_PUSH_HISTORY
            for (var gcmj = 0; gcmj < registrationIds.length; gcmj++) {
                // 실행구간, registrationId, 결과값message_id, 결과값error ( 필요결과값 계속추가가능....)
                var sString = sCnt + "`" + registrationIds[gcmj] + "`" + "-" + "`" + "-" + "`" + "-" + "`" + "-" + "`" + ctn[gcmj];
                //console.log(sString);
                dbRegistrationIdUpdate.push(sString); //디비업데이트 정보 push
            }

            if (process == "") { //re_msg_id:리턴값, process:out 이면 프로세스 종료
                //logger.info("err:"+r_count);
                gcm_go(messages, results, sCnt_b, fCnt_b, dbRegistrationIdUpdate, insert_date, cust_ctn, r_count);
            } else if (process == "out") { //프로세스종료면 배열값 리턴
                //logger.info("err::"+r_count);
                gcm_db_update(dbRegistrationIdUpdate, MESSAGE, req_time, insert_date, cust_ctn, '408', CUST_KEY, seq, r_count);
            }

        } else {

            var r_date = new Date();
            var res_time = r_date.formatDate("yyyyMMddhhmmss") + '' + r_date.getMilliseconds();

            var statusCode;

            if (response.statusCode == undefined) {
                statusCode = '200';
                for (var gcmi = 0; gcmi < Object.keys(response.results).length; gcmi++) {
                    // 실행구간, registrationId, 결과값message_id, 결과값error ( 필요결과값 계속추가가능....)
                    var sString = sCnt + "`" + registrationIds[gcmi] + "`" + response.results[gcmi].message_id + "`" + response.results[gcmi].registration_id + "`" + response.results[gcmi].error + "`" + res_time + "`" + ctn[gcmi];
                    //console.log(sString);
                    dbRegistrationIdUpdate.push(sString); //디비업데이트 정보 push
                }
            } else {
                statusCode = response.statusCode;
                for (var gcmi = 0; gcmi < registrationIds.length; gcmi++) {
                    // 실행구간, registrationId, 결과값message_id, 결과값error ( 필요결과값 계속추가가능....)
                    var sString = sCnt + "`" + registrationIds[gcmi] + "`" + " " + "`" + " " + "`" + " " + "`" + res_time + "`" + ctn[gcmi];
                    //console.log(sString);
                    dbRegistrationIdUpdate.push(sString); //디비업데이트 정보 push
                }
            }
            
            if (process == "") { //re_msg_id:리턴값, process:out 이면 프로세스 종료
                // logger.info("1111"+r_count);
                gcm_go(messages, results, sCnt_b, fCnt_b, dbRegistrationIdUpdate, insert_date, cust_ctn, r_count);
            } else if (process == "out") { //프로세스종료면 배열값 리턴
                //logger.info("2222"+r_count);
                gcm_db_update(dbRegistrationIdUpdate, MESSAGE, req_time, insert_date, cust_ctn, statusCode, CUST_KEY, seq, r_count);
            }

        } //else
    }); //sender
}

//gcm 변경정보 업데이트
function gcm_db_update(dbRegistrationIdUpdate, MESSAGE, req_time, insert_date, cust_ctn, statusCode, CUST_KEY, seq, r_count) {
    logger.info("dbRegistrationIdUpdate" + dbRegistrationIdUpdate);

    var date = new Date();

    var datetime = date.formatDate("yyyyMMddhhmmss") + '' + date.getMilliseconds();
    var P_CUST_CTN = cust_ctn;
    var P_INSERT_DATE = insert_date;
    var TITLE = "공지사항";
    var MESSAGE = MESSAGE;
    var REQUEST_TIME = date.formatDate("yyyyMMddhhmmss") + '' + date.getMilliseconds();
    var RECEIVE_TIME = '';
    var PUSH_STATUS = '0';
    var PUSH_TYPE = '2';
    var HTTP_CODE = statusCode;
    var fail_reg_id = [];

    for (var i = 0; i < dbRegistrationIdUpdate.length; i++) {

        var res = dbRegistrationIdUpdate[i].split('`');

        var can_id = res[3];
        var res_time = res[5];
        var CTN = res[6];
        var MESSAGE_ID = res[2];
        var GCM_ERROR = res[4];

        var REG_ID = res[1];
        var GCM_RESULT;
        var CANONICAL_ID;

        if (MESSAGE_ID != 'undefined' && MESSAGE_ID != null) {
            GCM_RESULT = '1';
        } else {
            MESSAGE_ID = '';
            GCM_RESULT = '2';
        }

        if (can_id != 'undefined' && can_id != null) {
            CANONICAL_ID = '1';
        } else if (can_id == "-") {
            CANONICAL_ID = '';
        } else {
            CANONICAL_ID = '0';
        }

        if (HTTP_CODE != '200') {
            GCM_RESULT = '2';
            CANONICAL_ID = '0';
        }

        if (HTTP_CODE == "408") {
            HTTP_CODE = "408";
        }


        if (GCM_ERROR == 'undefined' || GCM_ERROR == '-') {
            GCM_ERROR = '';
        }

        if (res_time == '-') {
            res_time = '';
        }

        var query = 'INSERT INTO TB_PUSH_HISTORY ' +
            '(P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY,  TITLE, MESSAGE, REQUEST_TIME, RESPONSE_TIME, PUSH_TYPE, MESSAGE_ID, PUSH_STATUS, HTTP_CODE, GCM_RESULT, GCM_ERROR, REG_ID, CANONICAL_ID, RECEIVE_TIME, INSERT_DATE) ' +
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

        //console.log('session cust_ctn3 : ', cust_ctn)
        //console.log(P_CUST_CTN);

        dbConn.query(query, [P_CUST_CTN, P_INSERT_DATE, CTN, CUST_KEY, TITLE, MESSAGE, req_time, res_time, PUSH_TYPE, MESSAGE_ID, PUSH_STATUS, HTTP_CODE, GCM_RESULT, GCM_ERROR, REG_ID, CANONICAL_ID, RECEIVE_TIME, datetime], function(err, result) {

            if (err) {
                logger.error('DB Error:', err);
            } else {
                //console.log('DB success');
            }
        });

        if (can_id != null && can_id != 'undefined') { // can_id가 있으면 update
            var query = 'update TB_PUSH_REG_INFO set REG_ID = ?,  UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s") where DEV_KEY=?';

            dbConn.query(query, [can_id, CTN], function(err, result) {

                if (err) {
                    logger.error('DB Error:', err);
                } else {
                    //console.log('DB success');
                }
            });
        } else {}

        //error 메세지가 InvalidRegistration 또는 NotRegistered일 경우 delete
        if (GCM_ERROR == 'InvalidRegistration' || GCM_ERROR == 'NotRegistered') {

            var query = 'delete from TB_PUSH_REG_INFO where DEV_KEY=?';

            dbConn.query(query, [CTN], function(err, result) {

                if (err) {
                    logger.error('DB Error:', err);
                } else {
                    //console.log('DB success');
                }
            });
        }

        if (GCM_ERROR == 'Unavailable') {
            fail_reg_id.push(CTN);
        }
    }

    if (fail_reg_id.length > 0) {
        //logger.info("fail_reg_id:"+r_count);
        re_send(fail_reg_id, MESSAGE, insert_date, seq, cust_ctn, r_count);
    }
}

function re_send(fail_reg_id, MESSAGE, insert_date, seq, cust_ctn, r_count) {

    //logger.info("function re_send::::"+r_count);

    var message = MESSAGE;
    //var insert_date = insert_date;
    var cust_ctn = cust_ctn;
    var seq = seq;

    //logger.info("re_send::r_count::"+r_count);

    var dbRegistrationIdUpdate = []; //디비업데이트 정보 push

    var date = new Date();
    var senddate = date.formatDate("yyyyMMddhhmmss") + '' + date.getMilliseconds();

    fail_reg_id = "'" + fail_reg_id + "'";
    logger.info("fail_reg_id:::" + fail_reg_id);

    var f = "(" + fail_reg_id.replace(/,/g, "','") + ")";

    //logger.info(f);

    var query1 = 'update TB_NOTICE_POPUP set N_SENDDATE = ? where SEQ=?';

    dbConn.query(query1, [senddate, seq], function(err, result) {

        if (err) {
            logger.error('DB Error:', err);
        } else {
            //console.log('DB success');
        }
    });

    var query = 'SELECT DEV_KEY,REG_ID FROM TB_PUSH_REG_INFO where DEV_KEY in ' + f;

    var cnt = 0;
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error:', error);
            callback(error, null);
        } else {
            // logger.info("re_send:"+ r_count);
            //타이틀, 디비데이타, 0, 10(범위), db 업데이트, notice insert시간, 발신자 번호
            r_count = r_count + 1;
            if (r_count < 3) { // 1부터 시작
                gcm_go(message, results, 0, 1000, dbRegistrationIdUpdate, senddate, cust_ctn, seq, r_count);
                //gcm_go(messages,results, 0, 10, dbRegistrationIdUpdate,insert_date,cust_ctn,seq,r_count);
            }
            //response.send('ok');
        }
    });
}


app.get('/test', function(request, response) {
    logger.info('Path change : /test');
    fs.readFile('test.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


app.get('/knowReport', CheckAuth, function(request, response) {
    logger.info('Path change : /knowReport');

    fs.readFile('know_report.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/knowledgeAdd', CheckAuth, function(request, response) {
    logger.info('Path change : /knowledgeAdd');
    fs.readFile('knowledge_add.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


app.get('/getLPMS', CheckAuth, function(request, response) {
    logger.info('Path change : /getLPMS');

    var req_no = request.param('lpms_reqno');
    var query = 'select * from TB_LPMS_IFACE_HISTORY where LPMS_REQNO = \'' + req_no + '\' ';
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.get('/thumbnail', CheckAuth, function(request, response) {
    logger.info('Path change : /thumbnail');

    fs.readFile('thumbnail.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/thumbnailList', CheckAuth, function(request, response) {
    logger.info('Path change : /thumbnailList');

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');

    //var query = 'select * from TB_THUMBIMG_ANA_HISTORY where P_CUST_CTN = \''+cust_ctn+'\' and P_INSERT_DATE = \''+insert_date+'\' ';
    var query = 'select * from TB_THUMBIMG_ANA_HISTORY where P_CUST_CTN = \'' + cust_ctn + '\' and P_INSERT_DATE = \'' + insert_date + '\' ';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/thumbCount', CheckAuth, function(request, response) {
    logger.info('Path change : /thumbCount');

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');

    //var query = 'select * from TB_THUMBIMG_ANA_HISTORY where P_CUST_CTN = \''+cust_ctn+'\' and P_INSERT_DATE = \''+insert_date+'\' ';
    var query = 'select count(*) as cnt from TB_THUMBIMG_ANA_HISTORY where P_CUST_CTN = \'' + cust_ctn + '\' and P_INSERT_DATE = \'' + insert_date + '\' ';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            
            response.send(results[0]);
        }
    });
});

app.all('/thumbPaging', CheckAuth, function(request, response) {

    logger.info('Path change : /thumbPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');

    var query = 'select * from TB_THUMBIMG_ANA_HISTORY where P_CUST_CTN = \'' + cust_ctn + '\' and P_INSERT_DATE = \'' + insert_date + '\' ';

    query += 'limit ' + start + ',' + pageSize + ' ';


    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(results);

        }

    });
});

app.all('/addKnow', CheckAuth, function(request, response) {

    logger.info('Path Change: /addKnow')

    var id = request.session.userid;
    var CUST_CTN = request.param('CUST_CTN');
    var INSERT_DATE = request.param('INSERT_DATE');
    var date = request.param('date');
    var CODE_01 = request.param('CODE_01');
    var CODE_02 = request.param('CODE_02');
    var CODE_03 = request.param('CODE_03');
    var CODE_ID = request.param('CODE_ID');
    var PREWORK_1 = request.param('PREWORK_1');
    var PREWORK_2 = request.param('PREWORK_2');
    var PREWORK_3 = request.param('PREWORK_3');
    var PREWORK_4 = request.param('PREWORK_4');
    var PREWORK_5 = request.param('PREWORK_5');
    var PREWORK_6 = request.param('PREWORK_6');

    var query = 'INSERT INTO TB_KNOWMNG_INFO ' +
        '(REG_ID, INSERT_DATE, P_CUST_CTN, P_INSERT_DATE, CODE_01, CODE_02, CODE_03, CODE_ID, PREWORK_1, PREWORK_2, PREWORK_3, PREWORK_4, PREWORK_5, PREWORK_6) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    dbConn.query(query, [id, date, CUST_CTN, INSERT_DATE, CODE_01, CODE_02, CODE_03, CODE_ID, PREWORK_1, PREWORK_2, PREWORK_3, PREWORK_4, PREWORK_5, PREWORK_6], function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(id);
        }
    });


});

app.all('/addKnowWork', CheckAuth, function(request, response) {
    logger.info('Path Change: /addKnowWork')

    var reg_id = request.param('reg_id');
    var id;
    if (reg_id == null || reg_id == 'null' || reg_id == 'undefined' || reg_id == undefined) {
        id = request.session.userid;
    } else {
        id = reg_id;
    }

    var INSERT_DATE = request.param('INSERT_DATE');
    var CUST_CTN = request.param('CUST_CTN');
    var date = request.param('date');
    var WORK_SEQ = request.param('WORK_SEQ');
    var WORK_TYPE = request.param('WORK_TYPE');
    var WORK_CONTENT = request.param('WORK_CONTENT');
    var IMG_KEY1 = request.param('IMG_KEY1');
    var IMG_KEY2 = request.param('IMG_KEY2');
    var IMG_KEY3 = request.param('IMG_KEY3');

    var query = 'INSERT INTO TB_KNOWMNG_WORKFLOW_INFO ' +
        '(REG_ID, INSERT_DATE, WORK_SEQ, WORK_TYPE, WORK_CONTENT, IMG_KEY1, IMG_KEY2, IMG_KEY3) ' +
        'VALUES (?, ?, (SELECT    max(WORK_SEQ) + 1   FROM     TB_KNOWMNG_WORKFLOW_INFO A) , ?, ?, ?, ?, ?)';

    dbConn.query(query, [id, date, WORK_TYPE, WORK_CONTENT, IMG_KEY1, IMG_KEY2, IMG_KEY3], function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            var query2 = 'update TB_TERMINAL_IMAGE_TRANS set KNOWMNG_REG_FLAG="1" where INSERT_DATE = \'' + INSERT_DATE + '\' and CUST_CTN = \'' + CUST_CTN + '\' ';

            dbConn.query(query2, function(error, result) {
                logger.info('Query: ', query2);

                if (error) {
                    logger.error('DB Error:', error);
                } else {
                    
                    response.send(id);
                }
            });

        }
    });

});

app.all('/deleteKnow', CheckAuth, function(request, response) {

    logger.info('Path Change: /deleteKnow')

    var id = request.session.userid;
    var P_CUST_CTN = request.param('P_CUST_CTN');
    var P_INSERT_DATE = request.param('P_INSERT_DATE');
    var INSERT_DATE = request.param('INSERT_DATE');

    var query = 'update TB_KNOWMNG_INFO set DEL_FLAG="1" where P_INSERT_DATE = \'' + P_INSERT_DATE + '\' and P_CUST_CTN = \'' + P_CUST_CTN + '\' and INSERT_DATE = \'' + INSERT_DATE + '\'';

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(INSERT_DATE);
        }
    });

});

app.all('/UpdateThumb', CheckAuth, function(request, response) {
    logger.info('Path Change: /UpdateThumb')

    var id = request.session.userid;
    var INSERT_DATE = request.param('INSERT_DATE');
    var CUST_CTN = request.param('CUST_CTN');
    var IMG_KEY1 = request.param('IMG_KEY1');
    var IMG_KEY2 = request.param('IMG_KEY2');
    var IMG_KEY3 = request.param('IMG_KEY3');

    var img;
    if (IMG_KEY1 != 0) {
        img = '(SEQ = \'' + IMG_KEY1 + '\') ';
    }
    if (IMG_KEY2 != 0) {
        img += ' or (SEQ = \'' + IMG_KEY2 + '\')';
    }
    if (IMG_KEY3 != 0) {
        img += ' or (SEQ = \'' + IMG_KEY3 + '\')';
    }

    var query = 'update TB_THUMBIMG_ANA_HISTORY set KNOWMNG_REG_FLAG="1" where P_INSERT_DATE = \'' + INSERT_DATE + '\' and P_CUST_CTN = \'' + CUST_CTN + '\' and ';
    query += img;

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(id);
        }
    });


});

app.all('/modKnowWork', CheckAuth, function(request, response) {
    logger.info('Path Change: /modKnowWork')

    var reg_id = request.param('reg_id');
    var id;
    if (reg_id == null || reg_id == 'null' || reg_id == 'undefined' || reg_id == undefined) {
        id = request.session.userid;
    } else {
        id = reg_id;
    }

    var INSERT_DATE = request.param('INSERT_DATE');
    var WORK_SEQ = request.param('WORK_SEQ');
    var WORK_TYPE = request.param('WORK_TYPE');
    var WORK_CONTENT = request.param('WORK_CONTENT');
    var IMG_KEY1 = request.param('IMG_KEY1');
    var IMG_KEY2 = request.param('IMG_KEY2');
    var IMG_KEY3 = request.param('IMG_KEY3');

    var query = 'update TB_KNOWMNG_WORKFLOW_INFO set WORK_TYPE=\'' + WORK_TYPE + '\',';
    query += ' WORK_CONTENT = \'' + WORK_CONTENT + '\', IMG_KEY1 = \'' + IMG_KEY1 + '\' , IMG_KEY2 = \'' + IMG_KEY2 + '\' , IMG_KEY3 = \'' + IMG_KEY3 + '\'';
    query += ' where REG_ID = \'' + id + '\' and WORK_SEQ = \'' + WORK_SEQ + '\' and INSERT_DATE = \'' + INSERT_DATE + '\'';

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(id);
        }
    });

});

app.all('/knowWorkDelete', function(request, response) {
    logger.info('Path Change: /knowWorkDelete')

    var work_seq = request.param('work_seq');
    var id = request.session.userid;
    var INSERT_DATE = request.param('INSERT_DATE');

    var query = 'delete from TB_KNOWMNG_WORKFLOW_INFO ';
    query += 'where WORK_SEQ = \'' + work_seq + '\' and INSERT_DATE = \'' + INSERT_DATE + '\''

    dbConn.query(query, function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(work_seq);
        }
    });

});

app.all('/workList', CheckAuth, function(request, response) {

    logger.info('Path change : /workList');

    var id = request.session.userid;
    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');
    var k_insert_date = request.param('K_INSERT_DATE');

    var query = 'select a.*, b.WORK_TYPE, b.WORK_CONTENT, b.WORK_SEQ, b.IMG_KEY1,b.IMG_KEY2,b.IMG_KEY3, ';
    query += ' (select c.IMG_FILE_NM from TB_THUMBIMG_ANA_HISTORY c where b.IMG_KEY1 = c.SEQ) as IMG_NM1,'
    query += ' (select c.IMG_FILE_NM from TB_THUMBIMG_ANA_HISTORY c where b.IMG_KEY2 = c.SEQ) as IMG_NM2,'
    query += ' (select c.IMG_FILE_NM from TB_THUMBIMG_ANA_HISTORY c where b.IMG_KEY3 = c.SEQ) as IMG_NM3'
    query += ' from TB_KNOWMNG_INFO a ';
    query += ' LEFT JOIN';
    query += ' (SELECT REG_ID, INSERT_DATE, WORK_TYPE, WORK_CONTENT, IMG_KEY1, IMG_KEY2, IMG_KEY3, WORK_SEQ';
    query += ' FROM TB_KNOWMNG_WORKFLOW_INFO';
    query += ' ) b';
    query += ' ON a.REG_ID = b.REG_ID and a.INSERT_DATE = b.INSERT_DATE';
    query += ' where a.P_CUST_CTN = \'' + cust_ctn + '\' and a.P_INSERT_DATE = \'' + insert_date + '\' and a.INSERT_DATE = \'' + k_insert_date + '\'';
    query += ' order by b.WORK_SEQ';

    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(results);

        }

    });
});

app.all('/reportKnowList', CheckAuth, function(request, response) {

    logger.info('Path change : /reportKnowList');

    var id = request.session.userid;
    var userlevel = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');
    var todate = request.param('todate').replace(/-/g, '');
    var fromdate = request.param('fromdate').replace(/-/g, '');
    var ctn = request.param('ctn');
    var worktype = request.param('worktype');
    var worknum = request.param('worknum');
    var workcontent = request.param('workcontent');
    var type = request.param('type');

    if (type == 'excel') {
        fromdate = parseInt(fromdate) + 1;
    }

    var query = 'select a.P_CUST_CTN, b.CUST_NM, c.CTL_NM, ';
    query += ' e.LPMS_REQNO, e.LPMS_FACTORY, e.LPMS_CLASS, e.LPMS_TEAM, e.LPMS_GUBUN, e.LPMS_CONTENT, e.LPMS_COMPANY, e.REQUEST_STATUS,';
    query += ' if(isnull(b.UPLOAD_FILE_NM), "-", "O") as UPLOAD_FILE, b.UPLOAD_FILE_NM,';
    query += ' a.P_INSERT_DATE, b.UPDATE_DATE, b.UPLOAD_FILE_NM as UPLOAD_FILE, b.STATUS, b.DEFECT_CODE, d.REASON,';
    query += ' b.TOT_BRIGHT_LVL, b.TOT_BRIGHT_RATE , b.TOT_DIFF_LVL, b.TOT_DIFF_RATE, a.INSERT_DATE, a.REG_ID ';
    query += ' from TB_KNOWMNG_INFO a ';
    query += ' LEFT JOIN';
    query += ' (SELECT UPLOAD_FILE_NM, CUST_CTN, CUST_NM, INSERT_DATE, CODE_ID, DEFECT_CODE, UPDATE_DATE, STATUS, LPMS_REQNO,';
    query += ' TOT_BRIGHT_LVL, TOT_BRIGHT_RATE , TOT_DIFF_LVL, TOT_DIFF_RATE';
    query += ' FROM TB_TERMINAL_IMAGE_TRANS';
    query += ' ) b';
    query += ' ON a.P_CUST_CTN = b.CUST_CTN and a.P_INSERT_DATE = b.INSERT_DATE';
    query += ' LEFT JOIN';
    query += ' (SELECT CODE_ID, CTL_NM';
    query += ' FROM TB_CONTROL';
    query += ' ) c';
    query += ' ON a.CODE_ID = c.CODE_ID';
    query += ' LEFT JOIN';
    query += ' (SELECT REASON, DEFECT_CODE';
    query += ' FROM TB_DEFECT_CODE';
    query += ' ) d';
    query += ' ON b.DEFECT_CODE = d.DEFECT_CODE';
    query += ' LEFT JOIN (';
    query += ' 	SELECT';
    query += ' 		LPMS_CLASS';
    query += '         ,LPMS_REQNO';
    query += '         ,LPMS_FACTORY, LPMS_TEAM, LPMS_GUBUN, LPMS_CONTENT, LPMS_COMPANY, WORKER_NAME, REQUEST_STATUS';
    query += '     FROM';
    query += '         TB_LPMS_IFACE_HISTORY';
    query += ' ) e';
    query += ' ON b.LPMS_REQNO = e.LPMS_REQNO';
    query += ' WHERE P_INSERT_DATE >= \'' + todate + '\' and P_INSERT_DATE < \'' + fromdate + '\' and  a.DEL_FLAG is null';
    //query += ' where P_CUST_CTN = \''+cust_ctn+'\' and P_INSERT_DATE = \''+insert_date+'\' ';

    if (ctn == '' || ctn == null) {} else {
        query += ' and b.CUST_CTN like \"%' + ctn + '%\"';
    }

    if (worktype == '' || worktype == null) {} else {
        query += ' and e.LPMS_CLASS like \"%' + worktype + '%\"';
        //query += ' and a.DEFECT_CODE = \''+defectcode+'\'';
    }

    if (worknum == '' || worknum == null) {} else {
        query += ' and e.LPMS_REQNO like \"%' + worknum + '%\"';
        //query += ' and a.DEFECT_CODE = \''+defectcode+'\'';
    }

    if (workcontent == '' || workcontent == null) {} else {
        query += ' and e.LPMS_CONTENT like \"%' + workcontent + '%\"';
        //query += ' and a.DEFECT_CODE = \''+defectcode+'\'';
    }

    //if (code1 == '900' && code2 == '999' && lv == '1') {
    if (userlevel == 1) { // 슈퍼관리자
        logger.info('superuser');
    } else {
        query += ' and a.REG_ID=\'' + id + '\' ';
    }

    query += ' order by a.INSERT_DATE desc ';


    dbConn.query(query, function(error, results, fields) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            //response.send(results);
            var except = [];
            except.push('DEFECT_CODE');
            except.push('REASON');
            except.push('UPLOAD_FILE');
            except.push('INSERT_DATE');
            except.push('REQUEST_STATUS');
            except.push('UPLOAD_FILE_NM');
            except.push('REG_ID');

            if (type == 'excel') {
                var filename = todate + "_" + fromdate + ".xlsx";
                utilLib.excelExport(request, response, results, fields, filename, except);
            } else {
                response.send(results);
            }

        }

    });
});

app.all('/orgToggleModify', CheckAuth, function(request, response) {

    logger.info('Path change : /orgToggleModify');

    var ctn = request.param('ctn');
    var flag = request.param('flag');

    if (flag == 'Y') {
        flag = 'N'
    } else {
        flag = 'Y'
    }

    var query = 'UPDATE TB_ORGANOGRAM SET BLOCK_FLAG=\'' + flag + '\' WHERE CTN=\'' + ctn + '\'';

    logger.info('Query:', query);

    dbConn.query(query, function(error, result) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(ctn);
        }

    });
});

app.get('/thumbimg_file', function(request, response) {

    var img = request.param('img');
    var query = 'SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'THUMB_DIR\'';

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            var img_path = results[0].C_VALUE + '/' + img
            fs.readFile(img_path, function(err, data) {
                response.end(data);
            });
        }
    });
});

app.all('/rateCount', CheckAuth, function(request, response) {

    logger.info('Path change : /rateCount');

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');

    var query = " SELECT sum(CNT) TOT,";
    query += "       sum(NORMAL_CNT) NORMAL_CNT,";
    query += "       sum(DARK_CNT) DARK_CNT, ";
    query += "       sum(BRIGHT_CNT) BRIGHT_CNT, ";
    query += "       sum(STOP_CNT) STOP_CNT, ";
    query += "       sum(DIFF_CNT) DIFF_CNT ";
    query += " from ( ";
    query += "    SELECT count(1) CNT,";
    query += "        case BRIGHT_LVL when '0' then count(1) else 0 end NORMAL_CNT,";
    query += "        case BRIGHT_LVL when '1' then count(1) else 0 end DARK_CNT, ";
    query += "        case BRIGHT_LVL when '2' then count(1) else 0 end BRIGHT_CNT, ";
    query += "        case DIFF_LVL when '0' then count(1) else 0 end STOP_CNT, ";
    query += "        case DIFF_LVL when '1' then count(1) else 0 end DIFF_CNT ";
    query += "    from TB_THUMBIMG_ANA_HISTORY ";
    query += "    where P_CUST_CTN = '" + cust_ctn + "' and P_INSERT_DATE = '" + insert_date + "'";
    query += " group by P_CUST_CTN, P_INSERT_DATE, BRIGHT_LVL, DIFF_LVL ";
    query += " ) a";

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(results[0]);

        }

    });
});

app.get('/openOrgImg', CheckAuth, function(request, response) {
    logger.info('Path change : /openOrgImg');

    fs.readFile('thumbnail_img.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.all('/adminSessionDate', CheckAuth, function(request, response) {

    logger.info('Path change : /rateCount');

    var cust_ctn = request.param('CUST_CTN');
    var insert_date = request.param('INSERT_DATE');

    var query = " SELECT sum(CNT) TOT,";
    query += "       sum(NORMAL_CNT) NORMAL_CNT,";
    query += "       sum(DARK_CNT) DARK_CNT, ";
    query += "       sum(BRIGHT_CNT) BRIGHT_CNT, ";
    query += "       sum(STOP_CNT) STOP_CNT, ";
    query += "       sum(DIFF_CNT) DIFF_CNT ";
    query += " from ( ";
    query += "    SELECT count(1) CNT,";
    query += "        case BRIGHT_LVL when '0' then count(1) else 0 end NORMAL_CNT,";
    query += "        case BRIGHT_LVL when '1' then count(1) else 0 end DARK_CNT, ";
    query += "        case BRIGHT_LVL when '2' then count(1) else 0 end BRIGHT_CNT, ";
    query += "        case DIFF_LVL when '0' then count(1) else 0 end STOP_CNT, ";
    query += "        case DIFF_LVL when '1' then count(1) else 0 end DIFF_CNT ";
    query += "    from TB_THUMBIMG_ANA_HISTORY ";
    query += "    where P_CUST_CTN = '" + cust_ctn + "' and P_INSERT_DATE = '" + insert_date + "'";
    query += " group by P_CUST_CTN, P_INSERT_DATE, BRIGHT_LVL, DIFF_LVL ";
    query += " ) a";

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            

            response.send(results[0]);

        }

    });
});



app.post('/reportViewList', CheckAuth, function(request, response) {

    logger.info('Path change : /reportViewList');

    var userlevel = request.session.userlv;
    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var todate = request.body.todate;
    var fromdate = request.body.fromdate;
    var ctn = request.body.ctn;

    var query;
    query = util.format("SELECT DEV_KEY, CASE WHEN B.DEV_TYPE = '1' THEN 'MOBILE' ELSE 'PC' END DEV_TYPE, DEV_NM, IFNULL(DEV_DEPT_NM, '') DEV_DEPT_NM " +
    ",SVC_TIME_ST, SVC_TIME_ED, MODEL,VERSION, IFNULL(SVC_IP, '') SVC_IP, B.STATUS, B.DEFECT_CODE " +
    "FROM TB_TERMINAL_IMAGE_TRANS A LEFT JOIN TB_VIEW_SERVICE B " +
    "ON A.CUST_CTN = B.P_CUST_CTN AND A.INSERT_DATE = B.P_INSERT_DATE " +
    "WHERE A.INSERT_DATE >= '%s' AND A.INSERT_DATE <= '%s' AND A.CODE_03 = '%s'"
    ,todate+'000000', fromdate+'235959', code3);

    var where = '';
    if (userlevel == '2')
        where = util.format(" AND CODE_01 = '%s' AND CODE_02 = '%s'", code1, code2)
    query += where;

    if (ctn != "") {
        where = util.format(" AND CUST_CTN = '%s'", ctn)
    }
    query += where;

    logger.info('Query:', query);
    dbConn.query(query, function(error, results, fields) {
        if (error) {
            logger.error('DB Error:', error);
        } else {                
            var except = [];
            var filename = todate + "_" + fromdate + '_viewer' +".xlsx";
            utilLib.excelExport(request, response, results, fields, filename, except);
        }
    });
});

app.get('/getdata', CheckAuth, function(request, response) {
    logger.info('Path change : /getdata');

    fs.readFile('test.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

/*
app.post("/mLog",  function(request, response) {
	var date = new Date().formatDate("yyyyMMdd");//파일날짜
	var datetime = new Date().formatDate("yyyyMMddhhmmss");//로그시간

	var filename = "app_log_"+date+".txt";
	var a1 = request.param("CUSTOM_DATA");
	var a2 = request.param("STACK_TRACE");


	fs.exists(filename, function (exists) {
		console.log(exists ? "it's there" : "no exists!");

		var data = "";
		if(exists){ //파일이 있으면 읽고
			data = fs.readFileSync(""+filename,"utf8");//동기식 파일읽기
		}

		//로그내용
		var mes = data+"\r\n\r\n-"+datetime+":\r\n" + a1 + "\r\n" + a2   ;
		fs.writeFile(filename, ""+mes, "utf8", function(err) {
			if (err) {
				throw err;
			}
			logger.info(filename + " writeFile OK");
		});
	});
});*/

function mysqlSha2(a) {
    if (g_bEnableSha256) {
        return " sha2('" + a + "',256)";
    } else {
        return " '"+a+"' ";
    }
}

app.get('/map', CheckAuth, function(request, response) {

    logger.info('Path change : /map');
    if (request.session.drone !== 'Y') {
        fs.readFile('html/map.html', 'utf8', function(error, data) {
            if (error) {
                logger.error('Error:', error);
            } else {
                response.send(ejs.render(data, {
                    data: {
                        'userlv': request.session.userlv,
                        'mVoIP' : request.session.mVoIP
                    }
                }));
            }
        });
    } else {
        response.redirect('/notaccess');
    }    
});


app.get('/googleMap/:var', function(request, response) {
    logger.info('Path change : /googleMap');
    var vars = request.param('var');
    var varsList = vars.split("`"); //선택체크박스
    fs.readFile('html/googleMap.html', 'utf8', function(error, data) {
        var query = 'select C_VALUE from TB_COMMON where C_NAME=\'GOOGLE_KEY\'';
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(ejs.render(data, {
                    data: {
                        'ctn': varsList[0],
                        'date': varsList[1],
                        'map' : results[0].C_VALUE
                    }
                }));
            }
        });
    });
});


app.get('/vWorldMap/:var', function(request, response) {
    logger.info('Path change : /vWorldMap');
    var vars = request.param('var');
    var varsList = vars.split("`"); //선택체크박스
    fs.readFile('html/vWorldMap.html', 'utf8', function(error, data) {
        var query = 'select C_VALUE from TB_COMMON where C_NAME=\'VWORLD_KEY\' or C_NAME=\'DOMAIN\' order by C_NAME desc';
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                var port = serverConf.SecureOnOff ? serverConf.SecureWebPort : serverConf.WebPort;
                response.send(ejs.render(data, {
                    data: {
                        'ctn': varsList[0],
                        'date': varsList[1],
                        'map' : results[0].C_VALUE,
                        'domain' : results[1].C_VALUE,
                        'port' : port
                    }
                }));
            }
        });
    });
});

app.get('/LGUplusMap/:var', CheckAuth, function(request, response) {
    logger.info('Path change : /LGUplusMap');
    var vars = request.param('var');
    var varsList = vars.split("`"); //선택체크박스
    fs.readFile('html/LGUplusMap.html', 'utf8', function(error, data) {
        var query = 'select C_VALUE from TB_COMMON where C_NAME=\'LGUPLUSMAP_KEY\' or C_NAME=\'LGUPLUSMAP_URL\' order by C_NAME';
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            if (error) {
                logger.error('DB Error:', error);
            } else {
                
                response.send(ejs.render(data, {
                    data: {
                        'ctn': varsList[0],
                        'date': varsList[1],
                        'map' : results[0].C_VALUE,
                        'url' : results[1].C_VALUE
                    }
                }));
            }
        });
    });
});

app.get('/googleMapData', function(request, response) {

    var P_CUST_CTN = request.param('P_CUST_CTN');
    var P_INSERT_DATE = request.param('P_INSERT_DATE');
    logger.info('Path change : /googleMapData : ' + P_CUST_CTN);

    var query = "select P_CUST_CTN, P_INSERT_DATE, LOCATION_X, LOCATION_Y, LOCATION_ADDR, LOCATION_URL, INSERT_DATE from TB_LOCATION_HISTORY  where LOCATION_X > 10  ";
    if (P_CUST_CTN != "" && P_CUST_CTN != undefined) {
        query += " AND  P_CUST_CTN='" + P_CUST_CTN + "' AND P_INSERT_DATE ='" + P_INSERT_DATE + "' ";
    } else {
        query += " AND ( ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160223151156' ) OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160127160802' ) OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160222130112' )  OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160223144948' ) )   ";
    }
    query += "  order by  P_CUST_CTN,P_INSERT_DATE , INSERT_DATE    ";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(decryptArray(results));
            //response.send(results);
        }
    });
});

app.get('/googleMapDataList', function(request, response) {

    var P_CUST_CTN = request.param('P_CUST_CTN');
    var P_INSERT_DATE = request.param('P_INSERT_DATE');

    logger.info('Path change : /googleMapDataList : ');

    var query = "select P_CUST_CTN, P_INSERT_DATE, INSERT_DATE, COUNT(*) as CNT from TB_LOCATION_HISTORY  where LOCATION_X > 10 ";
    query += " AND ( ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160223151156' ) OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160127160802' ) OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160222130112' )  OR ( P_CUST_CTN='01022330445' AND P_INSERT_DATE ='20160223144948' ) ) ";
    query += " GROUP BY P_CUST_CTN, P_INSERT_DATE ";
    query += " order by  P_CUST_CTN,P_INSERT_DATE , INSERT_DATE ";


    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/vWorldXY', function(request, response) {
    logger.info('Path change : /map');
    fs.readFile('vWorld_xy.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

//부서관리New
app.get('/manageDeptNew', function(request, response) {

    logger.info('Path change : /manageDeptNew');

    fs.readFile('html/manage_dept_new.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


//부서조회
app.get('/manageDeptNewSelect', function(request, response) {
    logger.info('Path change : /manageDeptNewSelect');

    var g = request.param('g'); //대분류 1, 중분류 2 ,3 ,4
    var CODE_01 = request.param('S_CODE_01');
    var CODE_02 = request.param('S_CODE_02');
    var CODE_03 = request.param('S_CODE_03');
    var CODE_04 = request.param('S_CODE_04');

    var whereQuery = "";
    if (g == "1") whereQuery = " AND CODE_02='000' AND  CODE_03='000' AND  CODE_04='000' ";
    else if (g == "2") whereQuery = " AND CODE_01='" + CODE_01 + "' AND CODE_02 !='000' AND CODE_03='000' AND CODE_04='000' ";
    else if (g == "3") whereQuery = " AND CODE_01='" + CODE_01 + "' AND CODE_02='" + CODE_02 + "' AND CODE_03 !='000' AND CODE_04='000' ";
    else if (g == "4") whereQuery = " AND CODE_01='" + CODE_01 + "' AND CODE_02='" + CODE_02 + "' AND CODE_03='" + CODE_03 + "' AND CODE_04 !='000' ";
    else whereQuery = " AND CODE_01='xxx' ";

    var query = "select * from TB_DEPT_DEPTH_NEW where DEL_YN='N' " + whereQuery + " ";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

//부서등록
app.get('/manageDeptNewInsert', function(request, response) {
    logger.info('Path change : /manageDeptNewInsert');

    var g = request.param('g'); //대분류 1, 중분류 2 ,3 ,4
    var CODE_01 = request.param('S_CODE_01');
    var CODE_02 = request.param('S_CODE_02');
    var CODE_03 = request.param('S_CODE_03');
    var CODE_04 = request.param('S_CODE_04');
    var CODE_NM = request.param('CODE_NM');

    var whereQuery = "";
    if (g == "1") {
        CODE_01 = " (select substring(concat( '000' , ifnull(max(CODE_01),0) + 1), -3) from TB_DEPT_DEPTH_NEW A01 where CODE_02 = '000' and CODE_03 = '000' and CODE_04 = '000' ) ";
        CODE_02 = "'000'";
        CODE_03 = "'000'";
        CODE_04 = "'000'";
    } else if (g == "2") {
        CODE_02 = " (select substring(concat( '000' , ifnull(max(CODE_02),0) + 1), -3) from TB_DEPT_DEPTH_NEW A01 where CODE_01 = '" + CODE_01 + "' and CODE_03 = '000' and CODE_04 = '000' ) ";
        CODE_03 = "'000'";
        CODE_04 = "'000'";
        CODE_01 = "'" + CODE_01 + "'";
    } else if (g == "3") {
        CODE_03 = " (select substring(concat( '000' , ifnull(max(CODE_03),0) + 1), -3) from TB_DEPT_DEPTH_NEW A01 where CODE_01 = '" + CODE_01 + "' and CODE_02 = '" + CODE_02 + "' and CODE_04 = '000' ) ";
        CODE_04 = "'000'";
        CODE_01 = "'" + CODE_01 + "'";
        CODE_02 = "'" + CODE_02 + "'";
    } else if (g == "4") {
        CODE_04 = " (select substring(concat( '000' , ifnull(max(CODE_04),0) + 1), -3) from TB_DEPT_DEPTH_NEW A01 where CODE_01 = '" + CODE_01 + "' and CODE_02 = '" + CODE_02 + "' and CODE_03 = '" + CODE_03 + "' ) ";
        CODE_01 = "'" + CODE_01 + "'";
        CODE_02 = "'" + CODE_02 + "'";
        CODE_03 = "'" + CODE_03 + "'";
    }

    var query = " insert into TB_DEPT_DEPTH_NEW( CODE_01, CODE_02, CODE_03, CODE_04, CODE_NM, USER_YN ) ";
    query += " values(" + CODE_01 + ", " + CODE_02 + ", " + CODE_03 + ", " + CODE_04 + ", '" + CODE_NM + "', 'Y'  )  ";

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

//부서수정
app.get('/manageDeptNewUpdate', function(request, response) {
    logger.info('Path change : /manageDeptNewUpdate');

    var g = request.param('g'); //대분류 1, 중분류 2 ,3 ,4
    var CODE_01 = request.param('S_CODE_01');
    var CODE_02 = request.param('S_CODE_02');
    var CODE_03 = request.param('S_CODE_03');
    var CODE_04 = request.param('S_CODE_04');
    var CODE_NM = request.param('CODE_NM');

    var query = " update TB_DEPT_DEPTH_NEW set CODE_NM = '" + CODE_NM + "' where CODE_01='" + CODE_01 + "' and CODE_02='" + CODE_02 + "' and CODE_03='" + CODE_03 + "' and CODE_04='" + CODE_04 + "' ";
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

//부서삭제
app.get('/manageDeptNewDelete', function(request, response) {
    logger.info('Path change : /manageDeptNewDelete');

    var g = request.param('g'); //대분류 1, 중분류 2 ,3 ,4
    var CODE_01 = request.param('S_CODE_01');
    var CODE_02 = request.param('S_CODE_02');
    var CODE_03 = request.param('S_CODE_03');
    var CODE_04 = request.param('S_CODE_04');
    var CODE_NM = request.param('CODE_NM');

    var query = " update TB_DEPT_DEPTH_NEW set DEL_YN = 'Y' where CODE_01='" + CODE_01 + "' and CODE_02='" + CODE_02 + "' and CODE_03='" + CODE_03 + "' and CODE_04='" + CODE_04 + "' ";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});



//영상보기(PCView)
app.get('/mediaPlayer', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /mediaPlayer');

    fs.readFile('html/mediaPlayer.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});


//작업내용 등록
// app.get('/workDatailSave', function(request, response) {
//     logger.info('Path change : /workDatailSave');

//     var s_userid = request.session.userid;

//     var checkVar = request.param('checkVar');
//     var subject = request.param('subject');
//     var content = request.param('content');

//     var checkVarList = checkVar.split("`"); //선택체크박스

//     var queryS = "";
//     for (var i = 1; i < checkVarList.length; i++) {
//         var checkVarColumn = checkVarList[i].split(",");
//         if (i > 1) queryS += ", ";
//         queryS += "( '" + checkVarColumn[0] + "', '" + checkVarColumn[1] + "', '" + checkVarColumn[2] + "', '" + subject + "', '" + content + "', '" + s_userid + "', DATE_FORMAT(now(),'%Y%m%d%H%i%s')  ) ";
//     }

//     var query = " insert into TB_TERMINAL_IMAGE_TRANS_MEMO( P_CUST_CTN,P_CTN_DEVICE,P_INSERT_DATE,SUBJECT,CONTENT,ADMIN_ID, INSERT_DATE ) ";
//     query += " values  ";
//     query += queryS;

//     dbConn.query(query, function(error, results) {

//         logger.info('Query:', query);

//         if (error) {
//             logger.error('DB Error:', error);
//         } else {
            
//             response.send(results);
//         }
//     });
// });


app.get('/workDatailList', function(request, response) {
    logger.info('Path change : /workDatailList : ');

    var checkVar = request.param('checkVar');
    var checkVarList = checkVar.split("`"); //선택체크박스

    var queryS = "   P_CUST_CTN = 'xxx' ";
    for (var i = 1; i < checkVarList.length; i++) {
        var checkVarColumn = checkVarList[i].split(",");
        if (i == 1) queryS = "    ";
        if (i > 1) queryS += "  or  ";
        //queryS += " ( P_CUST_CTN='"+checkVarColumn[0]+"' and P_CTN_DEVICE='"+checkVarColumn[1]+"' and P_INSERT_DATE='"+checkVarColumn[2]+"' ) ";
        queryS += " ( P_CUST_CTN='" + checkVarColumn[0] + "' and P_INSERT_DATE='" + checkVarColumn[2] + "' ) ";
    }

    var query = "select P_CUST_CTN,P_CTN_DEVICE,P_INSERT_DATE,SUBJECT,CONTENT,ADMIN_ID,INSERT_DATE  from TB_TERMINAL_IMAGE_TRANS_MEMO ";
    query += "  where   ";
    query += queryS;
    query += " order by   INSERT_DATE DESC ";


    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/reportWorkList', function(request, response) {

    logger.info('Path change : /reportWorkList');

    var ctn = request.param('ctn');
    var insert_date = request.param('insert_date');

    var query = "select P_CUST_CTN,P_CTN_DEVICE,P_INSERT_DATE,SUBJECT,CONTENT,ADMIN_ID,INSERT_DATE  from TB_TERMINAL_IMAGE_TRANS_MEMO ";
    query += "  where P_CUST_CTN = '" + ctn + "' and P_INSERT_DATE = '" + insert_date + "' ";
    query += " order by INSERT_DATE DESC ";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(results);
        }
    });
});

app.get('/service', CheckAuth, function(request, response) {
    logger.info('Path change: /service');

    var id = request.session.userid;
    var lv = request.session.userlv;

    var query = "select CUST_ADMIN from TB_ADMIN ";
    query += "where ADMIN_ID = '" + id + "' ";

    dbConn.query(query, function(error, results) {
        if (lv != '1') {
            response.redirect('/notcustomer');
        } else {
            fs.readFile('html/opening.html', 'utf-8', function(error, data) {
                if (error) {
                    logger.error('Error:', error);
                } else {
                    response.writeHead(200, {
                        'Content-Type': 'text/html; charset=UTF-8'
                    });
                    response.end(data);
                }

            });
        }
    });

});

app.post('/getAdminInfo', CheckAuth, function(request, response) {
    logger.info('Path change: /getAdminInfo');

    var query = "SELECT ADMIN_NM, ADMIN_MOBILE_NUM, ADMIN_DEPT_NM, ADMIN_ARANK, VIEWER_DEBUG FROM TB_ADMIN";
    query += " WHERE ADMIN_ID = '" + request.session.userid + "'";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');
            response.send(results);
        }
    });
});

app.get('/getAdminCustomer', CheckAuth, function(request, response) {
    logger.info('Path change: /getAdminCustomer');

    var code_03 = request.param("code_03");

    var query = "SELECT ADMIN_ID FROM TB_ADMIN";
    query += " WHERE CODE_03 = '" + code_03 + "'";

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');
            response.send(results);
        }
    });
});

/* 고객관리페이지 */
app.get('/notcustomer', function(request, response) {
    logger.info('Path change : /notcustomer');

    fs.readFile('html2/notcustomer.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/cLogin', function(request, response) {
    logger.info('Path change : /cLogin');

    fs.readFile('html2/login.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/customer', CheckAuth, function(request, response) {
    logger.info('Path change: /customer');

    var id = request.session.userid;
    var code_03 = request.session.code_03;

    var query = "select CUST_ADMIN from TB_ADMIN ";
    query += "where ADMIN_ID = '" + id + "' ";

    dbConn.query(query, function(error, results) {
        if (results[0].CUST_ADMIN != '1') {
            response.redirect('/notcustomer');
        } else {
            fs.readFile('html2/customer.html', 'utf-8', function(error, data) {
                response.writeHead(200, {
                    'Content-Type': 'text/html; charset=UTF-8'
                });
                response.end(data);
            });
        }
    });

});

app.get('/opening', CheckAuth, function(request, response) {
    logger.info('Path change: /opening');

    fs.readFile('html2/opening.html', 'utf-8', function(error, data) {

        response.writeHead(200, {
            'Content-Type': 'text/html; charset=UTF-8'
        });
        response.end(data);

    });
});

app.get('/customerCount', function(request, response) {

    var query = 'select count(*) as cnt from TB_CUSTOMER';

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.get('/customerSearchCount', function(request, response) {

    var schtype = request.param('schtype');
    var schval = request.param('schval');

    var query = 'select count(*) as cnt from TB_CUSTOMER';
    query += ' where 1=1 ';

    if (schval != '') {
        if (schtype == 'c_name') {
            query += 'and CT_NAME like \"%' + schval + '%\" ';
        }
        if (schtype == 'essential') {
            query += 'and SV_NECESSARY_SV like \"%' + schval + '%\" ';
        }
        if (schtype == 'storage') {
            query += 'and SV_OP_SV_S like \"%' + schval + '%\" ';
        }
        if (schtype == 'status') {
            query += 'and STATUS like \"%' + schval + '%\" ';
        }
        if (schtype == 'm_tel') {
            query += 'and PSCR_TEL like \"%' + schval + '%\" ';
        }
        if (schtype == 'num') {
            query += 'and JOIN_NUM like \"%' + schval + '%\" ';
        }
    }

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.all('/customerPaging', function(request, response) {

    logger.info('Path change : /customerPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    //var c_name = request.param('c_name');
    var schtype = request.param('schtype');
    var schval = request.param('schval');
    var orderbytype = request.param('orderbytype');
    var orderbyval = request.param('orderbyval');

    var query = 'select * from TB_CUSTOMER ';
    query += 'where 1=1 ';

    if (schval != '') {
        if (schtype == 'c_name') {
            query += 'and CT_NAME like \"%' + schval + '%\" ';
        }
        if (schtype == 'essential') {
            query += 'and SV_NECESSARY_SV like \"%' + schval + '%\" ';
        }
        if (schtype == 'storage') {
            query += 'and SV_OP_SV_S like \"%' + schval + '%\" ';
        }
        if (schtype == 'status') {
            query += 'and STATUS like \"%' + schval + '%\" ';
        }
        if (schtype == 'm_tel') {
            query += 'and PSCR_TEL like \"%' + schval + '%\" ';
        }
        if (schtype == 'num') {
            query += 'and JOIN_NUM like \"%' + schval + '%\" ';
        }
    }

    if (orderbyval != 'undefined' && orderbyval != null && orderbyval != '') {
        query += 'order by ' + orderbyval + ' ' + orderbytype + ' ';
    } else {
        query += 'order by INSERT_DATE desc';
    }

    query += ' limit ' + start + ',' + pageSize + ' ';

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results);
        }

    });
});

app.all('/insertCustomer', function(request, response) {

    var session_id = request.session.userid;

    var c_gubun = request.param("c_gubun");
    var c_name = request.param("c_name");
    var c_num = request.param("c_num");
    var m_name = request.param("m_name");
    var m_tel = request.param("m_tel");
    var m_dept = request.param("m_dept");
    var m_email = request.param("m_email");
    var essential = request.param("essential");
    var storage = request.param("storage");
    var wearable = request.param("wearable");
    var note = request.param("note");
    var a_id = request.param("a_id");
    var a_name = request.param("a_name");
    var a_pw = request.param("a_pw");
    var a_arank = request.param("a_arank");
    var a_tel = request.param("a_tel");

    if (storage == null || storage == 'null') {
        storage = '4';
    }

    var v01 = " substring( concat('0000',ifnull((select max(CODE_03) from TB_DEPT_DEPTH a where GUBUN = '2' and CODE = '999'),0)+1),-3,3) ";

    var query = 'INSERT INTO TB_CUSTOMER ' +
        '(ADMIN_ID, CT_GUBUN, CT_NAME, CT_NUM, CT_START_DATE, PSCR_NM, PSCR_TEL, PSCR_POSITION, PSCR_EMAIL, SV_NECESSARY_SV, SV_OP_SV_S, SV_OP_SV_W, SV_OP_ETC, STATUS, INSERT_DATE, RGST_ID, CUSTOMER_CODE) ' +
        'VALUES (?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d"), ?, ?, ?, ?, ?, ?, ?, ? , ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?, ' + v01 + ')';

    dbConn.query(query, [a_id, c_gubun, c_name, c_num, m_name, m_tel, m_dept, m_email, essential, storage, wearable, note, "1", session_id], function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {

            var query2 = 'INSERT INTO TB_DEPT_DEPTH ' +
                '(GUBUN, CODE, CODE_NM, CODE_03) VALUES ("1", "900", \'' + c_name + '\', ' + v01 + '),("2", "999" , \'' + c_name + '\', ' + v01 + '),("3",' + v01 + ',\'' + c_name + '\', ' + v01 + ') ';

            dbConn.query(query2, function(error, result) {
                logger.info('Query: ', query);
                if (error) {
                    logger.error('DB Error:', error);
                } else {
                    var code_03_max = "(select max(CODE_03) from TB_DEPT_DEPTH a where GUBUN = '2' and CODE = '999')";

                    var query3 = 'INSERT INTO TB_ADMIN ' +
                        '(ADMIN_ID, ADMIN_PW, ADMIN_NM, ADMIN_ARANK, ADMIN_LV, ADMIN_MOBILE_NUM, INSERT_DATE, CODE_01, CODE_02, CODE_03, CODE_ID) ' +
                        'VALUES (?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?, ?, ' + code_03_max + ', concat("900999",' + code_03_max + '))';

                    dbConn.query(query3, [a_id, a_pw, a_name, a_arank, '1', a_tel, '900', '999'], function(error, result) {
                        logger.info('Query: ', query);
                        if (error) {
                            logger.error('DB Error:', error);
                        } else {
                            response.send(a_id);
                        }
                    });

                }
            });


        }
    });
});

app.all('/insertCustomerHistory', function(request, response) {

    var session_id = request.session.userid;

    var c_gubun = request.param("c_gubun");
    var c_name = request.param("c_name");
    var c_num = request.param("c_num");
    var m_name = request.param("m_name");
    var m_tel = request.param("m_tel");
    var m_dept = request.param("m_dept");
    var m_email = request.param("m_email");
    var essential = request.param("essential");
    var storage = request.param("storage");
    var wearable = request.param("wearable");
    var note = request.param("note");
    var a_id = request.param("a_id");

    var query = 'INSERT INTO TB_CUSTOMER_HISTORY ' +
        '(ADMIN_ID, CT_GUBUN, CT_NAME, CT_NUM, CT_START_DATE, PSCR_NM, PSCR_TEL, PSCR_POSITION, PSCR_EMAIL, SV_NECESSARY_SV, SV_OP_SV_S, SV_OP_SV_W, SV_OP_ETC, STATUS, INSERT_DATE, RGST_ID) ' +
        'VALUES (?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d"), ?, ?, ?, ?, ?, ?, ?, ? , ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';

    dbConn.query(query, [a_id, c_gubun, c_name, c_num, m_name, m_tel, m_dept, m_email, essential, storage, wearable, note, "1", session_id], function(error, result) {
        logger.info('Query: ', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            response.send(a_id);
        }
    });
});


app.all('/updateCustomer', CheckAuth, function(request, response) {
    logger.info('Path change : /updateCustomer');

    var join_num = request.param("join_num");
    var c_gubun = request.param("c_gubun");
    var c_name = request.param("c_name");
    var c_num = request.param("c_num");
    var m_name = request.param("m_name");
    var m_tel = request.param("m_tel");
    var m_dept = request.param("m_dept");
    var m_email = request.param("m_email");
    var essential = request.param("essential");
    var storage = request.param("storage");
    var wearable = request.param("wearable");
    var note = request.param("note");
    var status = request.param("status");
    var a_id = request.param("a_id");

    var query = 'UPDATE TB_CUSTOMER SET JOIN_NUM=?, CT_GUBUN=?, CT_NAME=?, CT_NUM=?, PSCR_NM=?, PSCR_TEL=?, PSCR_POSITION=?, PSCR_EMAIL=?, SV_NECESSARY_SV=?, SV_OP_SV_S=?, SV_OP_SV_W=?, SV_OP_ETC=?, STATUS=?, UPDATE_DATE=DATE_FORMAT(now(),"%Y%m%d%H%i%s") WHERE ADMIN_ID=?';

    dbConn.query(query, [join_num, c_gubun, c_name, c_num, m_name, m_tel, m_dept, m_email, essential, storage, wearable, note, status, a_id], function(error, result) {

        if (error) {
            logger.error('DB Error:', error);
        } else {
            
            response.send(a_id);
        }
    });
});

app.all('/customerList', function(request, response) {

    logger.info('Path change : /customerList');

    var admin_id = request.param('admin_id');

    var query = 'select a.*, b.*,a.STATUS as svc_status from TB_CUSTOMER a';
    query += ' left join('
    query += ' SELECT *'
    query += ' FROM '
    query += 'TB_ADMIN'
    query += ') b '
    query += 'on a.ADMIN_ID = b.ADMIN_ID'
    query += ' where a.ADMIN_ID = \'' + admin_id + '\' ';

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });
});

app.all('/customerListInfo', function(request, response) {

    logger.info('Path change : /customerListInfo');

    var code_03 = request.session.code_03;

    var query = 'select * from TB_CUSTOMER ';
    query += ' where CUSTOMER_CODE = \'' + code_03 + '\' ';

    dbConn.query(query, function(error, results) {
        logger.info('Query: ', query);

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            results[0].PSCR_NM = utilLib.masking_name(results[0].PSCR_NM);
            results[0].PSCR_TEL = utilLib.masking_tel(results[0].PSCR_TEL);
            results[0].CT_NUM = utilLib.masking_num(results[0].CT_NUM);

            response.send(results[0]);
        }

    });
});

app.get('/top2', function(request, response) {

    fs.readFile('html2/top.html', 'utf8', function(error, data) {

        var session_id = request.session.userid;
        var session_lv = request.session.userlv;
        var s_date = request.session.s_date;

        response.send(ejs.render(data, {
            data: {
                'session': session_id,
                'session_lv': session_lv,
                's_date': s_date
            }
        }));
    });
});

app.get('/notAccess', function(request, response) {
    logger.info('Path change : /notAccess');

    fs.readFile('html/notaccess.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            response.writeHead(200, {
                'Content-Type': 'text/html; charset=UTF-8'
            });
            response.end(data);
        }
    });
});

app.get('/rtmp', CheckAuth, function(request, response) {
    logger.info('Path change : /rtmp');

    if (request.session.drone !== 'Y') {
        fs.readFile('html/manage_rtmp.html', 'utf8', function(error, data) {
            //console.log('Query:', query);
            if (error) {
                logger.error('Error:', error);
            } else {
                response.writeHead(200, {
                    'Content-Type': 'text/html; charset=UTF-8'
                });
                response.end(data);
            }
        });
    } else {
        response.redirect('/notaccess');
    }    
});

app.get('/rtmpCount', function(request, response) {

    logger.info('Path Change : /rtmpCount');
    var dept_code_03 = request.session.code_03;

    rtmpAPI.GetRtmpCount(dbConn, dept_code_03, function(results) {
        response.send(results);
    });

});

app.get('/rtmpsearchCount', function(request, response) {

    logger.info('Path Change : /rtmpsearchCount');

    var rtmp_id = request.param('rtmp_id');
    var rtmp_nm = request.param('rtmp_nm');
    var ctl_nm = request.param('ctl_nm');
    var dept_code_03 = request.session.code_03;

    rtmpAPI.GetRtmpsearchCount(dbConn, rtmp_id, rtmp_nm, ctl_nm, dept_code_03, function(results) {
        response.send(results);
    });

});


app.all('/rtmpPaging', function(request, response) {

    logger.info('Path change : /rtmpPaging');

    var start = request.param('start');
    var pageSize = request.param('pageSize');
    var rtmp_id = request.param('rtmp_id');
    var rtmp_nm = request.param('rtmp_nm');
    var ctl_nm = request.param('ctl_nm');
    var type = request.param('type');
    var dept_code_03 = request.session.code_03;

    rtmpAPI.GetRtmpPaging(dbConn, start, pageSize, rtmp_id, rtmp_nm, ctl_nm, type, dept_code_03, response, request, function(results) {
        response.send(results);
    });

});

app.get('/rtmpAddModify', function(request, response) {

    logger.info('Path change : /rtmpAddModify');

    var rtmp_id = request.param('rtmp_id');

    fs.readFile('html/rtmp_add_modify.html', 'utf8', function(error, data) {

        var query = 'select * from TB_RTMP_SETUP_INFO where REG_ID =  \'' + rtmp_id + '\' ';

        dbConn.query(query, function(error, result) {

            logger.info('Query:', query);

            if (result.length == 0) {
                response.send(ejs.render(data, {
                    data: {
                        'REG_ID': '',
                        'DEVICE_NM': '',
                        'CTL_SEQ': ''
                    }
                }));
            } else {
                response.send(ejs.render(data, {
                    data: result[0]
                }));
            }

        });
    });

});

app.get('/rtmpControlList', function(request, response) {

    logger.info('Path change : /rtmpControlList');

    var code3 = request.session.code_03;

    rtmpAPI.GetRtmpControlList(dbConn, code3, function(results) {
        response.send(results);
    });
});

app.all('/rtmpAdd', CheckAuth, function(request, response) {
    logger.info('Path change : /rtmpAdd');

    var rtmp_id = request.param('rtmp_id');
    var rtmp_nm = request.param('rtmp_nm');
    var ctl_seq = request.param('ctl_seq');
    var nm = request.param('nm');
    var dept_code_01 = request.param('dept_code_01');
    var dept_code_02 = request.param('dept_code_02');
    var dept_code_03 = request.session.code_03;
    var dept_nm = request.param('dept_nm');
    var ctn = request.param('ctn');
    var arank = request.param('arank');

    rtmpAPI.GetRtmpAdd(dbConn, rtmp_id, rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_code_03, dept_nm, ctn, arank, function(results) {
        response.send({
            "rtmp_id": rtmp_id
        });
    });
});

app.all('/rtmpModify', CheckAuth, function(request, response) {
    logger.info('Path change : /rtmpModify');

    var rtmp_id = request.param('rtmp_id');
    var rtmp_nm = request.param('rtmp_nm');
    var ctl_seq = request.param('ctl_seq');
    var nm = request.param('nm');
    var dept_code_01 = request.param('dept_code_01');
    var dept_code_02 = request.param('dept_code_02');
    var dept_nm = request.param('dept_nm');
    var ctn = request.param('ctn');
    var arank = request.param('arank');

    rtmpAPI.GetRtmpModify(dbConn, rtmp_id, rtmp_nm, ctl_seq, nm, dept_code_01, dept_code_02, dept_nm, ctn, arank, function(results) {
        response.send({
            "rtmp_id": rtmp_id
        });
    });
});

app.all('/rtmpDelete', function(request, response) {
    logger.info('Path change : /rtmpDelete');

    var rtmp_id = request.param('rtmp_id');

    dbConn.query('delete from TB_RTMP_SETUP_INFO WHERE REG_ID = ?', [rtmp_id], function() {

        response.send({
            "rtmp_id": rtmp_id
        });

    });
});

app.all('/isValidRtmpId', function(request, response) {
    logger.info('Path change : /isValidRtmpId');

    var rtmp_id = request.param('rtmp_id');

    dbConn.query('select count(*) as cnt from TB_RTMP_SETUP_INFO where REG_ID = ?', [rtmp_id], function(error, results) {

        response.send(results[0]);

    });
});

/* 패스워드 초기화 */

app.get('/pwReset', function(request, response) {
    logger.info('Path change : /pwReset');

    var id = request.param('id');
    var type = request.param('type');

    fs.readFile('html/admin_pw_reset.html', 'utf8', function(error, data) {
        //console.log('Query:', query);
        if (error) {
            logger.error('Error:', error);
        } else {
            //response.writeHead(200, {'Content-Type':'text/html; charset=UTF-8'});
            //response.end(data);
            if (id != 'undefined') {
                response.send(ejs.render(data, {
                    data: {
                        'id': id,
                        'type': type
                    }
                }));
            }
        }
    });
});

app.get('/superadmin', function(request, response) {

    var code3 = request.param('code3');

    var query = 'select b.* from TB_CUSTOMER a ';
    query += ' left join (select * from TB_ADMIN)b on a.ADMIN_ID = b.ADMIN_ID '
    query += 'where a.CUSTOMER_CODE =  \'' + code3 + '\' ';

    dbConn.query(query, function(error, results) {

        if (error) {
            logger.error('DB Error: ', error);
        } else {
            
            response.send(results[0]);
        }

    });

});

app.get('/fileDelete', function(request, response) {

    var file_nm = request.param('file_nm');
    var cust_ctn = request.param('cust_ctn');
    var insert_date = request.param('insert_date');

    var query = 'SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'UP DIR\''

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (typeof results[0] != 'undefined') {

                var dir = results[0].C_VALUE;
                var file = dir + "/" + file_nm;

                var exec = require('child_process').exec,
                    child;

                child = exec('unlink ' + file,
                    function(error, stdout, stderr) {
                        if (error !== null) {
                            console.log('exec error: ' + error);
                            response.send({
                                "result": "fail",
                                "reason": "file delete error"
                            });
                        } else {
                            logger.info('fiie delete request id : ', request.session.userid, ' ', file_nm);
                            var query3 = util.format('DELETE FROM TB_LOCATION_HISTORY WHERE P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\'', cust_ctn, insert_date);
                            dbConn.query(query3, function(error, result) {
                                logger.info('Query:', query3)
                            });

                            var query2 = 'UPDATE TB_TERMINAL_IMAGE_TRANS SET UPLOAD_FILE_NM = "", UPLOAD_FILE_SZ = 0 WHERE INSERT_DATE = \'' + insert_date + '\' and CUST_CTN = \'' + cust_ctn + '\' ';

                            dbConn.query(query2, function(error, result) {
                                logger.info('UPDATE TB_TERMINAL_IMAGE_TRANS Query:', query2);
                            });

                            response.send({
                                "result": "success",
                                "file_nm": file_nm
                            });
                        }
                    });

                /* fs.unlink(file, function (err) {
            		if (err) {
            			logger.error('cannot deleted file' + err);
            		}else {
            			var query2 = 'UPDATE TB_TERMINAL_IMAGE_TRANS SET UPLOAD_FILE_NM = "" WHERE INSERT_DATE = \''+insert_date+'\' and CUST_CTN = \''+ cust_ctn +'\' ';

                		dbConn.query(query2, function (error, result) {
                        	logger.info('UPDATE TB_TERMINAL_IMAGE_TRANS Query:', query2);
                		});

                        response.send(file_nm);
            		}
            	});*/

            }

        }

    });

});

app.post('/adminCheck', function(request, response) {
    logger.info('Path change : /adminCheck');
    var id = request.session.userid;
    var pw = request.param('pw');

    var query = 'SELECT count(*) as cnt,ADMIN_LV FROM TB_ADMIN WHERE ADMIN_ID = \'' + id + '\' and ADMIN_PW = ' + mysqlSha2(pw) + ' ';
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('Error:', error);
        } else {
            if (results[0].cnt == '1') {
                request.session.accountCheck = 'success';
                if (results[0].ADMIN_LV == '1') {
                    request.session.manageAccountCheck = 'success';
                    response.redirect(307, '/manageAdmin');
                } else {
                    response.redirect(307, '/adminModifyPage');
                }
            } else {
                logger.error('login fail');
                response.redirect('/adminConfirm1?ErrorCode=001');
            }
        }
    });
});

app.get('/adminConfirm1', CheckAuth, function(request, response) {// checkauth
    logger.info('Path change : /adminConfirm1');
    
    // console.log('adminConfirm1------', request.session);
    fs.readFile('html/admin_confirm.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {}
            }));
            // response.writeHead(200, {
            //     'Content-Type': 'text/html; charset=UTF-8'
            // });
            // response.end(data);
        }
    });
});

app.post('/revgeocoding', function(request, response) {
    logger.info('Path change : /revgeocoding');

    logger.info('HOST :', request.param('HOST'));
    logger.info('PORT :', request.param('PORT'));
    logger.info('PATH :', request.param('PATH'));
    logger.info('LOCATION_X :', request.param('LOCATION_X'));
    logger.info('LOCATION_Y :', request.param('LOCATION_Y'));

    var bodyString = '{"cutflag":"0","coordtype":"1","startposition":"0","reqcount":"0","posx":"' + request.param('LOCATION_Y') + '","posy":"' + request.param('LOCATION_X') + '"}';
    /*
    var bodyString = {
    	'cutflag':'0',
    	'coordtype':'1',
    	'startposition':'0',
    	'reqcount':'0',
    	'posx':request.param('LOCATION_X'),
    	'posy':request.param('LOCATION_Y')
    }
    */
    logger.info('revgeocoding body :', bodyString);
    logger.info('revgeocoding length :', bodyString.length);

    var headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Content-Length': bodyString.length,
        'apiVersion': '1.0.0',
        'apiType': '01',
        'devInfo': '03',
        'authKey': 'beb570f165d54351b34729828ea704da',
        'svcId': 'b506df83b8884710b233ce78b699245b'
    };
    // toss direct 접속
    var options = {
        host: request.param('HOST'),
        port: request.param('PORT'),
        path: request.param('PATH'),
        method: 'POST',
        headers: headers
    };
    var callback = function(response1) {
        response1.on('data', function(data) {
            logger.info('revgeocoding response: ', data.toString());
            response.send(data);
        });
    }
    https.request(options, callback).write(bodyString);
});

app.all('/adminModify2', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /adminModify2');
    var id = request.session.userid;
    var pw = request.param('pw');
    var name = request.param('name');
    var rank = request.param('rank');
    var tel = request.param('tel');
    var date = request.param('date');

    var query = 'SELECT count(*) as cnt FROM TB_ADMIN WHERE ADMIN_ID = \'' + id + '\' and ADMIN_PW = ' + mysqlSha2(pw) + ' ';
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('Error:', error);
        } else {
            if (results[0].cnt == '1') {
                var query1 = util.format('UPDATE TB_ADMIN set ADMIN_PW= %s,  ADMIN_NM=\'%s\', ADMIN_ARANK=\'%s\', ADMIN_MOBILE_NUM=\'%s\',INSERT_DATE=\'%s\' WHERE ADMIN_ID=\'%s\'', mysqlSha2(pw), name, rank, tel, date, id);
                logger.info('Query:', query1);
                dbConn.query(query1, function(error, result) {
                    if (error) {
                        logger.error('DB Error: ', error);
                    } else {
                        
                        response.send({
                            "id": id
                        });
                    }
                });
            } else {
                logger.error('pw fail');
                response.send({
                    "error": "error_pw"
                });
            }
        }
    });
});

app.post('/adminPwChange', function(request, response) {
    logger.info('Path change : /adminPwChange');
    var id = request.param('id');
    var pw = request.param('pw');
    var date = request.param('date');

    var query = 'SELECT ADMIN_PW, UPDATE_DATE,PAST_PW FROM TB_ADMIN WHERE ADMIN_ID=\'' + id + '\'';
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
        } else {
            var hash_pw = crypto.createHash('sha256').update(pw).digest('hex');
            logger.error('term' + utilLib.term(results[0].UPDATE_DATE, date));
            if ((hash_pw == results[0].ADMIN_PW || hash_pw == results[0].PAST_PW) && utilLib.term(results[0].UPDATE_DATE, date) >= 90) {
                logger.error(' Error: Password');
                response.send({
                    "error": "error"
                });
            } else {
                var query1 = util.format('UPDATE TB_ADMIN set ADMIN_PW= %s,UPDATE_DATE=\'%s\',PAST_PW=\'%s\' WHERE ADMIN_ID=\'%s\'', mysqlSha2(pw), date, results[0].ADMIN_PW, id);

                logger.info('Query:', query1);
                dbConn.query(query1, function(error, result) {
                    if (error) {
                        logger.error('DB Error: ', error);
                    } else {
                        response.send({
                            "id": id
                        });
                    }
                });
            }
        }
    });
});

app.get('/initPwInfo', CheckPwCommon, function(request, response) {
    logger.info('Path change : /initPwInfo');
    fs.readFile('html/init_pw_info.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {
                    'isEnableLocale': request.session.locale,
                    'initType': request.query.initType,
                    'redirect': '/pwChange'
                }
            }));
        }
    });
});

app.get('/pwChange', CheckPwCommon, function(request, response) {
    logger.info('Path change : /pwChange');
    fs.readFile('html/admin_pw_change.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {
                    'pass_change': request.session.pass_change
                }
            }));
        }
    });
});

app.get('/alert', function(request, response) {
    var reValue = request.param('reValue');
    console.log("alert_reValue :" + reValue);
    logger.info('Path change : /alert');
    fs.readFile('html/alert.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {
                    'reValue': reValue
                }
            }));
        }
    });
});

app.post('/pwChange', CheckAuthCommon, function(request, response) {
    var key_id = request.param('key_id');
    logger.info('Path change : /pwChange');
    fs.readFile('html/admin_pw_change.html', 'utf8', function(error, data) {
        if (error) {
            logger.error('Error:', error);
        } else {
            response.send(ejs.render(data, {
                data: {
                    'pass_change': key_id
                }
            }));
        }
    });
});

app.post('/adminPwCheckChange', pwValidator, function(request, response) {
    logger.info('Path change : /adminPwCheckChange');
    var id = request.param('id');
    var pw = request.param('pw');
    var new_pw = request.param('new_pw');
    var date = request.param('date');
    var query = 'SELECT count(*) as cnt FROM TB_ADMIN WHERE ADMIN_ID = \'' + id + '\' and ADMIN_PW = ' + mysqlSha2(pw) + ' ';
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('Error:', error);
        } else {
            if (results[0].cnt == '1') {
                var query2 = 'SELECT ADMIN_PW, UPDATE_DATE,PAST_PW FROM TB_ADMIN WHERE ADMIN_ID=\'' + id + '\'';
                logger.info('Query:', query2);
                dbConn.query(query2, function(error, results) {
                    if (error) {
                        logger.error('DB Error: ', error);
                    } else {
                        var hash_pw = crypto.createHash('sha256').update(new_pw).digest('hex');
                        if (hash_pw == results[0].ADMIN_PW || hash_pw == results[0].PAST_PW) {
                            logger.error(' Error: Password');
                            response.send({
                                "error": "error"
                            });
                        } else {
                            var query3 = util.format('UPDATE TB_ADMIN set ADMIN_PW= %s,UPDATE_DATE=\'%s\',PAST_PW=\'%s\' WHERE ADMIN_ID=\'%s\'', mysqlSha2(new_pw), date, results[0].ADMIN_PW, id);
                            logger.info('Query:', query3);
                            dbConn.query(query3, function(error, result) {
                                if (error) {
                                    logger.error('DB Error: ', error);
                                } else {
                                    response.send({
                                        "id": id
                                    });
                                }
                            });
                        }
                    }
                });
            } else {
                logger.error('login fail');
                response.send({
                    "error": "error_pw"
                });
            }
        }
    });
});

app.post('/pageout', function(request, response) {
    logger.info('Path change : /pageout');
    //logger.info('account:'+request.session.manageAccountCheck);
    request.session.manageAccountCheck = null;
    //logger.info('account:'+request.session.manageAccountCheck);
});

// channel notice 정보 저장
app.post('/getCountNewNoticeOnChannel', CheckAuth, function (request, response) {
    logger.info('Path change: /getCountNewNoticeOnChannel');

    channelAPI.getCountNewNoticeOnChannel(dbConn, request, response);
});

app.post('/InsertNoticeDataOnChannel', CheckAuth, function (request, response) {
    logger.info('Path change: /InsertNoticeDataOnChannel');

    channelAPI.InsertNoticeDataOnChannel(dbConn, request, response);
});

app.post('/SelectNoticeDataOnChannel', CheckAuth, function (request, response) {
    logger.info('Path change: /SelectNoticeDataOnChannel');

    channelAPI.SelectNoticeDataOnChannel(dbConn, request, response);
});

app.post('/UpdateNoticeDataOnChannel', CheckAuth, function (request, response) {
    logger.info('Path change: /UpdateNoticeDataOnChannel');

    channelAPI.UpdateNoticeDataOnChannel(dbConn, request, response);
});

app.post('/UpdateSystemNoticeChangeStatus', CheckAuth, function (request, response) {
    logger.info('Path change: /UpdateSystemNoticeChangeStatus');

    channelAPI.UpdateSystemNoticeChangeStatus(dbConn, request, response);
});

app.post('/getSystemNoticeContent', CheckAuth, function (request, response) {
    logger.info('Path change: /getSystemNoticeContent');

    channelAPI.getSystemNoticeContent(dbConn, request, response);
});

app.post('/getServiceNoticeContent', CheckAuth, function (request, response) {
    logger.info('Path change: /getServiceNoticeContent');

    channelAPI.getServiceNoticeContent(dbConn, request, response);
});

app.get('/service/output/count', CheckAuth, function(request, response) {

    logger.info('Path move : /service/output/count');
    var query = "SELECT OUTPUT_SVC, OUTPUT_MAX FROM TB_SVC_STS_INFO WHERE CATE_CODE = '" + request.session.code_03 + "'";

    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);

        if (error){
            logger.error('DB Error:', error);
        }else {
            response.send(results[0]);
        }
    });
});

// VOD 시에 AR offset 정보
app.get('/ar/service', CheckAuth, function (request, response) {
    logger.info('Path change : /ar/service');

    var urlquery = querystring.parse(url.parse(request.url).query);
    var query = util.format(
        'SELECT ' +
        'c.AR_START_OFFSET + c.PLAY_TIME - c.DIFF_TIME AR_START_OFFSET, ' +
        'c.AR_END_OFFSET + c.PLAY_TIME - c.DIFF_TIME AR_END_OFFSET, ' +
        'c.PLAY_TIME SVC_RUNNING_TIME, ' +
        'c.FEATURE_KEY ' +
        'FROM ' +
                '(SELECT TIME_TO_SEC(TIMEDIFF(a.INSERT_DATE, b.INSERT_DATE)) AR_START_OFFSET ' +
                ',TIME_TO_SEC(TIMEDIFF(a.UPDATE_DATE, b.INSERT_DATE)) AR_END_OFFSET ' +
                ',TIME_TO_SEC(TIMEDIFF(b.UPDATE_DATE, b.INSERT_DATE)) DIFF_TIME ' +
                ',ROUND(b.PLAY_TIME) PLAY_TIME ' +
                ',a.FEATURE_KEY ' +
        'FROM TB_AR_SERVICE a ' +
        'LEFT JOIN TB_TERMINAL_IMAGE_TRANS b ' +
        'ON a.P_CUST_CTN = b.CUST_CTN AND a.P_INSERT_DATE = b.INSERT_DATE ' +
        'WHERE P_CUST_CTN = \'%s\' AND P_INSERT_DATE = \'%s\' AND OWNER_TYPE = \'1\' ' +
        'AND F_FILE_NAME <> \'\' AND M_FILE_NAME <> \'\' AND O_FILE_NAME <> \'\' ' +
        'ORDER BY a.INSERT_DATE ASC) c', urlquery.CUST_CTN, urlquery.INSERT_DATE);

    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);

        if (error){
            logger.error('DB Error:', error);
        }else {
            response.send(results);
        }
    });
});


app.get('/modbookTitle', CheckAuth, function(request, response) {
    logger.info('Path change : /modbookTitle');

    var code1;
    var code2;
    var code3;
    if(request.session.userlv == 2) {
          code1 = request.session.code_01;
          code2 = request.session.code_02;
          code3 = request.session.code_03;
    }else {
          code1 = request.param('code1');
          code2 = request.param('code2');
          code3 = request.param('code3');
    }

    var codeId = code1 + '' + code2 + '' + code3;
    var id = request.session.userid;
    var name = request.param('name');
    var update_date = request.param('insert_date');
    var key = request.param('favkey');

    var query = 'UPDATE TB_BOOKMARK_INFO SET FAV_NAME=?, UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s")' +
    ' WHERE FAV_KEY=?';

    dbConn.query(query, [name, key], function (error, result) {
        logger.info('Query: ', query);
        if (error){
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');

            var query2 = 'UPDATE TB_BOOKMARK_CONNECT_INFO SET FAV_NAME=?, UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s")' +
            ' WHERE FAV_KEY=?';
            dbConn.query(query2, [name, key], function (error, result) {
                logger.info('Query: ', query);
                if (error){
                    logger.error('DB Error:', error);
                }else {
                    response.send(result);
                }
            });
        }
    });
});

app.all('/deletebookTitle', function(request, response) {

    logger.info('Path Change: /deletebookTitle');

    var fav_key = request.param('fav_key');

    dbConn.query('delete from TB_BOOKMARK_INFO where FAV_KEY = ?', [fav_key], function () {
        dbConn.query('delete from TB_BOOKMARK_CONNECT_INFO where FAV_KEY = ?', [fav_key], function () {
            response.send(fav_key);
        });
    });
});

app.get('/addBookInfo', CheckAuth, function(request, response) {
    logger.info('Path change : /addBookInfo');

    var id = request.session.userid;
    var FAV_NAME = request.param('FAV_NAME');
    var FAV_KEY = request.param('FAV_KEY');
    var DEV_KEY = request.param('DEV_KEY');
    var DEV_TYPE = request.param('DEV_TYPE');
    var DEV_NM = request.param('DEV_NM');
    var DEV_DEPT_NM = request.param('DEV_DEPT_NM');

    var query = 'INSERT INTO TB_BOOKMARK_CONNECT_INFO ' +
        '(FAV_TYPE, FAV_NAME, FAV_KEY, DEV_KEY, DEV_TYPE, DEV_NM, DEV_DEPT_NM, INSERT_DATE, REG_ID) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), ?)';

    dbConn.query(query, ["2", FAV_NAME, FAV_KEY, DEV_KEY, DEV_TYPE, DEV_NM, DEV_DEPT_NM, id], function (error, result) {
            logger.info('Query: ', 	query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');
            response.send(result);
        }
    });
});

app.get('/getdefault', function(request, response) {
    logger.info('Path change : /getdefault');

    var code1 = request.param('code1');
    var code2 = request.param('code2');
    var code3 = '000';

    var query = 'select * from TB_CONTROL where CODE_01 = \''+code1+'\' and CODE_02 = \''+code2+'\' and CODE_03 = \''+code3+'\' ';

    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);

        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
            response.send(results);
        }
    });
});

app.get('/getdefaultView', function(request, response) {
    logger.info('Path change : /getdefaultView');

    var dev_type = request.param('dev_type');
    var code1 = request.param('code1');
    var code2 = request.param('code2');
    var code3 = '000';

    var query = 'select DEV_KEY, DEV_TYPE, DEV_NM, DEV_DEPT_NM from TB_DEFAULT_CONNECT_INFO ';
    query += 'where CODE_01 = \''+code1+'\' and CODE_02 = \''+code2+'\' and CODE_03 = \''+code3+'\' and DEV_TYPE = \''+dev_type+'\'';

    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');
            response.send(results);
        }
    });
});

app.get('/getconnectList', function(request, response) {
    logger.info('Path change : /getconnectList');

    var fav_Key = request.param('fav_key');

    var query = 'select * from TB_BOOKMARK_CONNECT_INFO where FAV_KEY = \''+fav_Key+'\'';

    dbConn.query(query, function (error, results) {

        logger.info('Query:', query);

        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
            response.send(results);
        }
    });
});

app.get('/bookmarkDelete', function(request, response) {

  logger.info('Path Change: /bookmarkDelete');

    var fav_key = request.param('fav_key');
    var dev_key = request.param('dev_key');
    var dev_type = request.param('dev_type');

    dbConn.query('delete from TB_BOOKMARK_CONNECT_INFO where FAV_KEY = ? and DEV_KEY = ? and DEV_TYPE = ?', [fav_key, dev_key, dev_type], function () {
        response.send(fav_key);
    });
});


app.get('/updateConnCnt', CheckAuth, function(request, response) {
logger.info('Path change : /updateConnCnt');

  var key = request.param('favkey');
  var f_mobile_cnt = request.param('f_mobile_cnt');
  var mobile_cnt = request.param('mobile_cnt');
  var pc_cnt = request.param('pc_cnt');
  var stb_cnt = request.param('stb_cnt');

  var query = 'UPDATE TB_BOOKMARK_INFO SET F_MOBILE_CNT=?, MOB_CNT=?, STB_CNT=?, PC_CNT=?, UPDATE_DATE = DATE_FORMAT(now(),"%Y%m%d%H%i%s")' +
    ' WHERE FAV_KEY=?';

  dbConn.query(query, [f_mobile_cnt, mobile_cnt, stb_cnt, pc_cnt, key], function (error, result) {
    logger.info('Query: ', query);

    if (error){
    logger.error('DB Error:', error);
    }else {
    response.send(result);
    }
  });

});

// 토스 연동
app.get('/tossReport', function(request, response) {
	var urlquery = request.url;

    var url = urlquery.split("PRPS_COBYPTYID=");

    logger.info("toss url[1]: ",url[1]);

    fs.readFile('html/toss.html', 'utf8', function (error, data) {

  	  response.send(ejs.render(data, {
  	      data: {'prpsCoByPtyId':url[1]}
  	  }));
    });
});

app.all('/tossList', function (request, response) {
	var CUST_CTN = request.param('CUST_CTN');
    var INSERT_DATE = request.param('INSERT_DATE');

	var query = "select * from TB_TERMINAL_IMAGE_TRANS where CUST_CTN = ? and INSERT_DATE = ? ";

    dbConn.query(query, [CUST_CTN, INSERT_DATE], function (error, result) {
    	logger.info('Query: ', query);

        if (error){
        	logger.error('DB Error:', error);
        }else {
        	logger.info('DB success');
            response.send(result[0]);
        }
    });
});

app.get('/tossServiceReport', CheckAuth, function(request, response) {
	logger.info('Path change : /tossServiceReport');

    fs.readFile('html/toss_report.html', function (error, data) {

        response.writeHead(200, {'Content-Type':'text/html; charset=UTF-8'});
        response.end(data);
    });
});

app.all('/reportTossList', function(request, response) {
	logger.info('Path change : /reportTossList');

    var code1 = request.session.code_01;
    var code2 = request.session.code_02;
    var code3 = request.session.code_03;
    var fromdate = request.param('fromdate').replace(/-/g,'');
    var todate = request.param('todate').replace(/-/g,'');
    var ctn = request.param('ctn');
    var consNo = request.param('consNo');
    var consReqNo = request.param('consReqNo');
    var lcsProcNo = request.param('lcsProcNo');
    var type = request.param('type');
    var dept_nm = request.param('dept_nm');


    fs.readFile('report.html', function (error, data) {

        var query =  "select TOSS_TYPE,";
        	query += ' a.LCS_FLMGNO,a.LCS_FLMGDV_CD,a.CONS_NO,a.CONS_REQNO,';
        	query += ' a.LCS_USE_BIZIDNTNO, a.PRPSCOBYPTY_ID, c.CTL_NM, a.P_CUST_CTN, a.P_INSERT_DATE, a.REQUEST_TIME, a.DEL_PRPSCOBYPTY_ID as DEL_PRPSCOBYPTY_ID, a.RESPONSE_TIME,';
			query += ' a.RESULT,';
        	query += ' a.DEL_FLAG as DEL_FLAG, a.LCS_ACCURL, a.MESSAGE,';
        	query += ' b.CODE_02';
        	query += ' FROM TB_TOSS_HISTORY a';
        	query += ' LEFT JOIN(';
        	query += ' SELECT CODE_02,CUST_CTN,INSERT_DATE,LCS_FLMGNO';
        	query += ' FROM TB_TERMINAL_IMAGE_TRANS)b';
        	query += ' ON a.P_CUST_CTN = b.CUST_CTN AND a.P_INSERT_DATE = b.INSERT_DATE AND a.LCS_FLMGNO = b.LCS_FLMGNO';
        	query += ' LEFT JOIN(';
        	query += ' SELECT CTL_NM,CODE_02';
        	query += ' FROM TB_CONTROL)c ';
        	query += ' ON b.CODE_02 = c.CODE_02';
        	query += ' WHERE a.P_INSERT_DATE >= \''+fromdate+'\'';
        	query += ' AND a.P_INSERT_DATE < \''+todate+'\'';

        if (ctn == '' || ctn == null) {
        } else {
        	query += ' and a.P_CUST_CTN like \"%' + ctn + '%\"';
        }

        if (consNo == '' || consNo == null) {
        } else {
        	query += ' and a.CONS_NO like \"%' + consNo + '%\"';
        }

        if (consReqNo == '' || consReqNo == null) {
        } else {
        	query += ' and a.CONS_REQNO like \"%' + consReqNo + '%\"';
        }

        if (lcsProcNo == '' || lcsProcNo == null) {
        } else {
        	query += ' and a.LCS_FLMGNO like \"%' + lcsProcNo + '%\"';
        }
        if (dept_nm == '' || dept_nm == null) {
        } else {
        	query += ' and c.CTL_NM like \"%' + dept_nm + '%\"';
        }

        query += ' group by a.REQUEST_TIME';
        query += ' order by P_INSERT_DATE desc, a.REQUEST_TIME desc ';

        dbConn.query(query ,function (error, results, fields) {

        	logger.info('Query:', query);
            if (error){
            	logger.error('DB Error:', error);
            }else {
            	logger.info('DB success');

				var excepts = [];
				excepts.push('CODE_02');
				excepts.push('LCS_ACCURL');
				excepts.push('MESSAGE');
				excepts.push('DEL_FLAG');

                if (type =='excel'){
	            	var filename =  fromdate+ "_" + todate+ ".xlsx";
	            	utilLib.excelExport(request, response, results, fields, filename, excepts);
                } else{
                	response.send(results);
				}
            }
        });
    });
});

app.get('/resultTossList', function(request, response) {

    var ctn = request.param('ctn');
    var insertdate = request.param('insertdate');
    var lcsprocNo = request.param('lcsprocNo');
    var query =  'select * from TB_TOSS_HISTORY where P_INSERT_DATE = \''+insertdate+'\' and P_CUST_CTN = \''+ctn+'\' and LCS_FLMGNO = \''+lcsprocNo+'\'';
    dbConn.query(query ,function (error, results) {
        logger.info('Query:', query);
        if (error){
            logger.error('DB Error:', error);
        }else {
            logger.info('DB success');
            response.send(results[0]);
        }
    });
});

app.get('/tossfileDownload', function (request, response) {

	logger.info('Path change : /tossfileDownload');

    var query = 'SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'TOSS UP DIR\'';
    dbConn.query(query, function (error, results) {

    	logger.info('Query:', query);
        if (error){
        	logger.error('DB Error:', error);
        }else {
        	logger.info('DB success');

            if (typeof results[0] != 'undefined') {
                var dir = results[0].C_VALUE;
                var file = dir + "/"+request.param('fileName');
                response.download(file);
            }else {
            	logger.error('cannot find download directory');
            }
        }
    });
});

app.get('/DeleteToss', function(request, response) {

	logger.info('Path Change: /DeleteToss');

	var LCS_FLMGNO = request.param('LCS_FLMGNO');
	var DEL_PRPSCOBYPTY_ID = request.param('DEL_PRPSCOBYPTY_ID');

	var xml;
	xml = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:q0="http://lguplus/u3/esb" xmlns:q1="java:lguplus.u3.esb.osc116" xmlns:q2="java:lguplus.u3.esb.common" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n';
	xml += '<soapenv:Body>\n';
	xml += '<q0:Oscpc116>\n';
	xml += '<q0:RequestRecord>\n';
	xml += '<q1:ESBHeader>\n';
	xml += '<q2:ServiceID>OSC116</q2:ServiceID>\n';
	xml += '<q2:TransactionID>'+ LCS_FLMGNO +'</q2:TransactionID>\n';
	xml += '<q2:SystemID>LCS000</q2:SystemID>\n';
	xml += '<q2:ErrCode></q2:ErrCode>\n';
	xml += '<q2:ErrMsg></q2:ErrMsg>\n';
	xml += '<q2:Reserved></q2:Reserved>\n';
	xml += '</q1:ESBHeader>\n';
	xml += '<q1:RequestBody>\n';
	xml += '<q1:Oscpc116RequestInVO>\n';
	xml += '<q1:lcsFlmgNo>'+ LCS_FLMGNO +'</q1:lcsFlmgNo>\n';
	xml += '<q1:prpsCoByPtyId>'+ DEL_PRPSCOBYPTY_ID  +'</q1:prpsCoByPtyId>\n';
	xml += '</q1:Oscpc116RequestInVO>\n';
	xml += '</q1:RequestBody>\n';
	xml += '</q0:RequestRecord>\n';
	xml += '</q0:Oscpc116>\n';
	xml += '</soapenv:Body>\n';
	xml += '</soapenv:Envelope>\n';

	var bodyString = xml;

	logger.info('toss delete bodyString:',bodyString);

	response.send(LCS_FLMGNO);

	var headers = {
		'Content-Type': 'text/xml;charset=UTF-8',
		'Content-Length': bodyString.length,
		'soapAction': ''
	};

	var options = {
      host: TOSS_HOST,
      port: TOSS_PORT,
        path: '/CSSI/OSC/Oscpc116',
        method: 'POST',
        headers: headers
	};

	var callback = function(response) {
        response.on('data', function(data) {

	    	logger.info('toss response: ', data.toString());
	        var xmlparse = data;
	        var succYn;
	        var msg;
	        var transactionID;

        //  logger.info('xmlparse:',xmlparse);

            parseString(xmlparse, function (err, result) {

	            //json 값 가져오기
	            if (err)
	        	    logger.crit('toss parse err:',err);

	            logger.info('toss result:',result);

	            transactionID = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc116Response'][0]['ns3:ResponseRecord'][0]['q1:ESBHeader'][0]['q2:TransactionID'];
		        succYn = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc116Response'][0]['ns3:ResponseRecord'][0]['ResponseBody'][0]['Oscpc116ResponseOutVO'][0]['succYn'];
		        msg = result['soapenv:Envelope']['soapenv:Body'][0]['ns3:Oscpc116Response'][0]['ns3:ResponseRecord'][0]['ResponseBody'][0]['Oscpc116ResponseOutVO'][0]['msg'];

		        logger.info('toss delete transactionID:',transactionID);
		        logger.info('toss delete succYn:',succYn);
		        logger.info('toss delete msg:',msg);

	        });

	        //TOSS 삭제 이력 UPDATE

			var query = 'UPDATE TB_TOSS_HISTORY SET RESULT=?, MESSAGE=?, RESPONSE_TIME = DATE_FORMAT(now(),"%Y%m%d%H%i%s")' +
	                   ' WHERE LCS_FLMGNO=? and TOSS_TYPE="2"';

	        dbConn.query(query,[succYn, msg, transactionID ], function (error, results) {
	        	logger.info('Query:', query);

		        if (error) {
		        	logger.error('DB Error:', error);
				} else {
					logger.info('DB success');
				}
			});
        });

	    response.on('end', function() {
	    	logger.info('end');
		    //response.send('aa');
		});
    }; //response end

    http.request(options, callback).write(bodyString);

    //TOSS 삭제 이력 INSERT
    var query = 'INSERT INTO TB_TOSS_HISTORY ';
    query += '(P_CUST_CTN, P_INSERT_DATE, LCS_FLMGNO, TOSS_TYPE, LCS_FLMGDV_CD, CONS_NO, CONS_REQNO, LCS_USE_BIZIDNTNO, LCS_ACCURL, PRPSCOBYPTY_ID, REQUEST_TIME, RESULT, DEL_FLAG, DEL_PRPSCOBYPTY_ID) ';
    query += 'SELECT ';
    query += 'P_CUST_CTN, P_INSERT_DATE, LCS_FLMGNO, "2", LCS_FLMGDV_CD, CONS_NO, CONS_REQNO, LCS_USE_BIZIDNTNO, LCS_ACCURL, PRPSCOBYPTY_ID, DATE_FORMAT(now(),"%Y%m%d%H%i%s"), "", "1", \''+DEL_PRPSCOBYPTY_ID+'\' ';
    query += 'FROM TB_TOSS_HISTORY ';
    query += 'WHERE LCS_FLMGNO=\''+LCS_FLMGNO+'\'';

    dbConn.query(query, function (error, results) {
        logger.info('Query:', query);

        if (error) {
        logger.error('DB Error:', error);
        } else {
        logger.info('DB success');
        }
    });

	 //서비스 이력 UPDATE
	var query1 = 'UPDATE TB_TERMINAL_IMAGE_TRANS SET DEL_FLAG=?' +
                ' WHERE LCS_FLMGNO=?';

     dbConn.query(query1,['1',LCS_FLMGNO], function (error, results) {
     	logger.info('Query:', query);

        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB success');
        }
	});
});

app.post('/adminPwReset', function (request,response){
    logger.info('Path change : /adminPwReset');
    var id =request.param('id');
    var pw = id.slice(0, 3) + 'qwe12!@';
    var query = util.format('update TB_ADMIN set ADMIN_PW=%s,LOGIN_TRYCNT=\'0\',UPDATE_DATE=\'00000000000000\' where ADMIN_ID=\'%s\'', mysqlSha2(pw),id);
    dbConn.query(query, function(error,results){
        logger.info('query:',query);
        logger.info('$password reset ID:',id,'&Admin ID :',request.session.userid);
        if(error){
            logger.info('DB Error:',error);
        }else{
            response.send({
                "id":id
            });
        }
    })
})

app.get('/pcviewer-check', CheckAuth, function(request, response) {

var query = 'SELECT (SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'IPADDR\')';
    query += ' AS IPADDR, ';
    query += '(SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'RTSP_URL\')';
    query += ' AS RTSP_URL, ';
    query += '(SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'CTL_PORT\')';
    query += ' AS CTL_PORT ';

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.info('DB Error:', error);
        } else {
            response.send(results[0]);
        }
    });
});

app.get('/lctGoogle', function(request, response) {
    logger.info('Path change : /lctGoogle : ');

    //var g = request.param('g');
    //var f_date = request.param('f_date');
    //var t_date = request.param('t_date');
    var ctn = request.param('ctn');
    var date = request.param('date');
    var userid = request.session.userid;

    var query;


    logger.info('map : ', ctn);
    var queryS = "    ";
    if (ctn != undefined && ctn != 'undefined' && (ctn == "google" || ctn == "vworld" || ctn == "lguplus")) { //지도뷰어(큰창)

        query = util.format('SELECT CTN_DEVICE, CUST_CTN, LIST.INSERT_DATE, HIS.*' +
            ' FROM TB_LOCATION_HISTORY HIS,' +
            ' (SELECT A.CTN_DEVICE, A.CUST_CTN, A.INSERT_DATE' +
            ' FROM TB_TERMINAL_IMAGE_TRANS A, (' +
            ' SELECT P_CUST_CTN,P_INSERT_DATE' +
            ' FROM (' +
            ' SELECT P_CUST_CTN,P_INSERT_DATE, INSERT_DATE, STATUS,' +
            ' (CASE @vP_CUST_CTN WHEN A.P_CUST_CTN THEN @rownum:=@rownum+1 ELSE @rownum:=1 END) rank,' +
            ' (@vP_CUST_CTN:=A.P_CUST_CTN) vP_CUST_CTN' +
            ' from TB_LOCATION_ADMIN_MAPPING A, (SELECT @vP_CUST_CTN:=\'\', @rownum:=0 FROM DUAL) B' +
            ' where A.ADMIN_ID = \'%s\'' +
            ' order by P_CUST_CTN, INSERT_DATE desc' +
            ' ) LIST' +
            ' WHERE RANK = 1 AND STATUS < \'3\'' +
            ' ) B' +
            ' WHERE A.STATUS < \'3\' AND A.CUST_CTN = B.P_CUST_CTN AND A.INSERT_DATE = B.P_INSERT_DATE' +
            ' ) LIST' +
            ' WHERE HIS.P_CUST_CTN = LIST.CUST_CTN AND HIS.P_INSERT_DATE = LIST.INSERT_DATE and HIS.P_CUST_CTN > \'0\'', userid);

        /*
        queryS += "  and concat(P_CUST_CTN,P_INSERT_DATE) in ( ";
        queryS += "  select concat(CUST_CTN,INSERT_DATE) from ( ";
        queryS += " 		 SELECT   ";
        queryS += " 			 a.CUST_CTN ,   a.INSERT_DATE ,   ";
        queryS += " 			(SELECT status  FROM TB_LOCATION_ADMIN_MAPPING i  WHERE i.P_CUST_CTN=a.CUST_CTN  AND i.P_INSERT_DATE=a.INSERT_DATE  AND i.ADMIN_ID = '"+userid+"' ORDER BY i.INSERT_DATE DESC limit 0, 1  ) as mapstatus ";
        queryS += " 		 FROM TB_TERMINAL_IMAGE_TRANS a  ";
        queryS += " 		 WHERE status < 3  ";
        queryS += " 		 ORDER BY INSERT_DATE desc ";
        queryS += "  ) p where mapstatus < 3  ) ";
        */
    } else if (ctn != undefined && ctn != 'undefined') { // 작은창 0000`20160000
        var ctnVarList = ctn.split(","); //선택체크박스
        var dateVarList = date.split(","); //선택체크박스

        query = util.format('SELECT HIS.*, CTN_DEVICE FROM TB_LOCATION_HISTORY HIS LEFT JOIN TB_TERMINAL_IMAGE_TRANS TER' +
            ' ON HIS.P_CUST_CTN = TER.CUST_CTN AND HIS.P_INSERT_DATE = TER.INSERT_DATE' +
            ' WHERE HIS.P_CUST_CTN = \'%s\' AND HIS.P_INSERT_DATE = \'%s\' ORDER BY INSERT_DATE DESC LIMIT 0, 50', ctnVarList[0], dateVarList[0]);
        /*
		for(var i=0 ; i< ctnVarList.length; i++ ){
			if( i > 0) queryS += " or ";
			queryS += " ( P_CUST_CTN='"+ctnVarList[i]+"' and P_INSERT_DATE='"+dateVarList[i] +"' ) ";
		}
		queryS = " AND ("+queryS+")";
		*/
    } else { //값이 없을때
        //queryS += " AND P_CUST_CTN ='xxxx' and P_INSERT_DATE='xxxx'  ";
        query = util.format('SELECT HIS.*, CTN_DEVICE FROM TB_LOCATION_HISTORY HIS LEFT JOIN TB_TERMINAL_IMAGE_TRANS TER' +
            ' ON HIS.P_CUST_CTN = TER.CUST_CTN AND HIS.P_INSERT_DATE = TER.INSERT_DATE' +
            ' WHERE HIS.P_CUST_CTN = \'%s\' AND HIS.P_INSERT_DATE = \'%s\'', '', '');
    }

    /*
    var query = "";

	    query += " SELECT  ";
		query += " P.*  ";
		query += " ,(select CTN_DEVICE FROM TB_TERMINAL_IMAGE_TRANS i WHERE  P.P_CUST_CTN=i.CUST_CTN  AND P.P_INSERT_DATE=i.INSERT_DATE  limit 0, 1) as CTN_DEVICE FROM TB_LOCATION_HISTORY P WHERE LOCATION_X > 1  ";
		query += queryS;
		query += " ORDER BY P_CUST_CTN ,P_INSERT_DATE, INSERT_DATE    ";
	*/

    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            //logger.info('DB success');
            response.send(decryptArray(results));
            //response.send(results);
        }
    });
});

exports.dbConn = dbConn;
// exports.client = client;
exports.droneResult = droneResult;
exports.g_lcsAddrIP = g_lcsAddrIP;
// exports.io = io;
exports._io = _io;
exports.cloudLib = cloudLib;
exports.pcViewerAPI = pcViewerAPI;
exports.pushServiceAPI = pushServiceAPI;
