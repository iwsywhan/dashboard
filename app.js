/**
 * Created by iwsywhan on 2015-04-15.
 */
var util = require('util');
var fs = require('fs');
// var ejs = require('ejs');
var http = require('http');
var https = require('https');
var express = require('express');
var path = require('path');
var url = require('url');
var querystring = require('querystring');
var utilLib = require('./libs/utilLib.js');
var pwValidator = require('./libs/passwordValidate');

var bodyParser = require('body-parser');
// var cookieParser = require('cookie-parser');
// var session = require('express-session');
var pushServiceAPI = require('./pushServiceAPI.js');
var lcsServiceAPI = require('./lcsServiceAPI.js');
var pcViewerAPI = require('./pcViewerAPI.js');
// var rtmpAPI = require('./rtmpAPI.js');
var channelAPI = require('./channelServiceAPI.js');
// var crypto = require('crypto');
var morgan = require('morgan');
// var cors = require('cors');
var aes256cbc = require('./aes256cbc.js');
var logger = require('./libs/logger');
var DroneResult = require('./libs/DroneResult');
var CloudLib = require('./libs/CloudLib');
var dbConn = require('./db');

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
var { auth } = require('./libs/auth');

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
        console.log("Https server listening on port " + httpsWebServerPort);
    });
} else {// http
    server = http.createServer(app).listen(httpWebServerPort, function(){
        console.log("Http server listening on port " + httpWebServerPort);
    });
}

// var _io = require('./sockets').initialize(server);

logger.stream = {
    write: function(message, encoding) {
        logger.info(message);
    }
};

app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined', {
    'stream': logger.stream
}));

// app.use(helmet({
//     noSniff: false
// }));

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

// app.use(cookieParser());
app.use(bodyParser.json());
// app.use(session({
//     secret: 'secret key',
//     key: 'ltelcs_b2b_widget',
//     cookie: {
//         secure: serverConf.SecureOnOff,
//         httpOnly: true
//     }
// }));
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

app.use(auth);

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


app.get('/serviceStatusView/:id', function(request, response) {
    
    logger.info('Path change : /serviceStatusView/', request.param('id'));
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

            // response.send(ejs.render(data, {
            response.send({
                data: {
                    'userid': request.session.userid,
                    'userlevel': request.session.userlv,
                    'code01': request.session.code_01,
                    'code02': request.session.code_02,
                    'code03': request.session.code_03,
                    'mVoIP': mVoIP
                }
            });
        });
    // });
});

app.get('/serviceMultiVoice/:ctn', CheckAuth, function(request, response) {
    logger.info('Path change : /serviceMultiVoice');

    // fs.readFile('html/service_multi_voice.html', 'utf8', function(error, data) {
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

            // response.send(ejs.render(data, {
            response.send({
                data: {
                    'mVoIP': mVoIP
                }
            });
        });
    // });
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


//----------------------------------- 이력조회 -------------------------------------

app.get('/service/report', CheckAuthCommon, function(request, response) {
    logger.info('Path change : /service/report');

    // fs.readFile('html/report.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            // response.send(ejs.render(data, {
            response.send({
                data: {
                    'session': request.session.userid,
                    'session_pw': request.session.userpw,
                    'drone': request.session.drone
                }
            });
        }
    // });
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

    // fs.readFile('html/report_view.html', 'utf8', function(error, data) {

        if (error) {
            logger.error('Error:', error);
        } else {
            // response.send(ejs.render(data, {
            response.send({
                data: {
                    'session': request.session.userid,
                    'session_pw': request.session.userpw,
                    'drone': request.session.drone
                }
            });            
        }
    // });
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

            }

        }

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

app.post('/revgeocoding', function(request, response) {
    logger.info('Path change : /revgeocoding');

    logger.info('HOST :', request.param('HOST'));
    logger.info('PORT :', request.param('PORT'));
    logger.info('PATH :', request.param('PATH'));
    logger.info('LOCATION_X :', request.param('LOCATION_X'));
    logger.info('LOCATION_Y :', request.param('LOCATION_Y'));

    var bodyString = '{"cutflag":"0","coordtype":"1","startposition":"0","reqcount":"0","posx":"' + request.param('LOCATION_Y') + '","posy":"' + request.param('LOCATION_X') + '"}';
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
    var query = 'SELECT C_VALUE FROM TB_COMMON WHERE C_NAME = \'UP DIR\''
    dbConn.query(query, function(error, results) {

        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
        } else {
            

            if (typeof results[0] != 'undefined') {

                var dir = results[0].C_VALUE;
                var file = dir + "/" + filename;
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
    // fs.readFile('html/login_history.html', 'utf8', function(error, data) {
 
        var query = util.format('SELECT a.* FROM TB_LOGIN_HISTORY a' +
            ' LEFT JOIN TB_ADMIN b on a.ADMIN_ID = b.ADMIN_ID' +
            ' WHERE b.CODE_03 = \'%s\'', code3);
 
        dbConn.query(query, function(error, results) {
            logger.info('Query:', query);
            // response.send(ejs.render(data, {
            response.send({
                data: results
            });
        });
    // });
 });


app.get('/loginList', CheckAuth, function(request, response) {

    // fs.readFile('login_history.html', function(error, data) {

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
    // });
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


/**
 * 설정 시작
 */
/**
 * 계정 관리
 */
/*
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
*/
/**
 * STB 관리
 */
/*
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
*/

/**
 * 관제센터 관리
 */
/*
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
*/

/**
 * 공통 관리
 */
/*
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
*/

/**
 * 영상단말관리
 */
/*
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
*/

/**
 * 부서DEP관리
 */
/*
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
*/

/**
 * 공지사항 관리
 */
/*
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
*/


/**
 * DEFECTCODE 조회
 */
/*
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
*/

/**
 * 기본연결 관리
 */
/*
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
*/

/**
 * PC뷰어는 윈도우 어플리케이션으로 대체되므로 필요 없는 기능
 */
/*
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
*/

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

            results[i].LOCATION_X = aes256cbc.decrypt(results[i].LOCATION_X);
            results[i].LOCATION_Y = aes256cbc.decrypt(results[i].LOCATION_Y);
        }
    }
    return results;
}


/**
 * 공지사항 PUSH 기능
 */
/*
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
*/

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


function mysqlSha2(a) {
    if (g_bEnableSha256) {
        return " sha2('" + a + "',256)";
    } else {
        return " '"+a+"' ";
    }
}

/**
 * MAP
 */
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

/**
 * 가입 서비스 조회
 */
/*
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
*/

/**
 * front end 부분은 reverse proxy 서버로 이동
 */
/*
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
*/

/**
 * rtmp 관리
 */
/*
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
*/

/**
 * 계정관리는 setup api로 이동
 */
/*
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
*/

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
/**
 * AR서비스도 윈도우 어플리케이션으로 대체되므로 필요 없음
 */
/*
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
*/

/**
 * 북마크 기능은 안 쓰임
 */
/*
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
*/

// 토스 연동
/**
 * 토스 연동도 안 쓰임
 */
/*
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
*/

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




exports.dbConn = dbConn;
exports.droneResult = droneResult;
exports.g_lcsAddrIP = g_lcsAddrIP;
// exports._io = _io;
exports.cloudLib = cloudLib;
exports.pcViewerAPI = pcViewerAPI;
exports.pushServiceAPI = pushServiceAPI;
