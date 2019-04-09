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
var TerraLib = require('../libs/TerraLib');
// var app = require('../js');
var utilLib = require('../public/javascripts/utilLib');
var util = require('util');
var serverConf = JSON.parse(fs.readFileSync("./config/server.json"));
var decodeJWT = require('../libs/decodeJWT');
var client = require('../socketClient')
var dbConn = require('../db')

const DEF_ILIVECAM = '1';
const DEF_UTM = '2';

var cloudLib = new CloudLib();
var terraLib = new TerraLib();

module.exports = router;

router.all('*', function(req, res, next) {    
    if (req.session.drone === 'Y') {
        next();
    } else {
        decodeJWT(req, res, function(result, token) {
            if (result) {
                if (!token.drone) {
                    next();
                } else {
                    res.redirect('/notaccess');
                }
            } else {
                res.redirect('/notaccess');
            }            
        });
    } 
});

router.get('/', function(req, res) {
    logger.info('Path change : /drone'); 
  
        fs.readFile('html/drone.html', 'utf8', function(error, data) {
            res.send(ejs.render(data, {}));
        });    
});

router.get('/report', function(req, res) {
    logger.info('Path change : /drone/report');
    fs.readFile('html/drone_report.html', 'utf8', function(error, data) {
        res.send(ejs.render(data, {}));
    });    
});

router.post('/cloud/upload', function(req, res) {
    logger.info('Path change : /drone/cloud/upload');
    var where = '';
    if (req.body.dev_key != '')
        where = util.format(" AND a.DEV_KEY LIKE '%%%s%%' ", req.body.dev_key);
    if (req.body.dev_nm != '')
        where += util.format(" AND DEV_NM LIKE '%%%s%%' ", req.body.dev_nm);
    where += util.format(" AND a.UPDATE_DATE >= '%s' AND a.UPDATE_DATE <= '%s' ", req.body.fromdate + '000000', req.body.todate + '235959');

    var query = util.format("SELECT a.DEV_KEY, a.UPDATE_DATE, REQ_TYPE, FILE_TYPE, IDENTIFICATION, UCLOUD_STATUS, UCLOUD_DELETE_STATUS, FOLDER_ID, FOLDER_NAME " + 
                            ",DEV_NM, COUNT(*) CNT, COUNT(IF(UCLOUD_DELETE_STATUS = '0' AND UCLOUD_STATUS = '3', UCLOUD_DELETE_STATUS, NULL)) CNT2 " +
                            "FROM TB_FILE_MNG_HISTORY a " +
                            "LEFT JOIN TB_DRON_SETUP_INFO b ON a.DEV_KEY = b.DEV_KEY " +
                            "WHERE CUSTOMER_CODE = '%s' " + where +
                            "GROUP BY IDENTIFICATION ORDER BY a.UPDATE_DATE DESC ", req.session.code_03);
    if (req.body.type != 'excel') {
        query += 'LIMIT ' + req.body.start + ',' + req.body.pageSize + ' ';
    }

	logger.info('Query:', query);
    dbConn.query(query, function (error, results, fields) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');
            if (req.body.type == "excel") {
                var filename = "droneHistory.xlsx";
                var excepts = [];
                excepts.push('CNT');
                excepts.push('CNT2');
                excepts.push('FOLDER_ID');
                excepts.push('IDENTIFICATION');
                utilLib.excelExport(req, res, results, fields, filename, excepts);
            } else {
                res.send(results);
            }
        }
    });
});

router.post('/cloud/count', function(req, res) {
    logger.info('Path change : /drone/cloud/count');
    var where = '';
    if (req.body.dev_key != '')
        where = util.format(" AND a.DEV_KEY LIKE '%%%s%%' ", req.body.dev_key);
    if (req.body.dev_nm != '')
        where += util.format(" AND DEV_NM LIKE '%%%s%%' ", req.body.dev_nm);
    where += util.format(" AND a.UPDATE_DATE >= '%s' AND a.UPDATE_DATE <= '%s' ", req.body.fromdate + '000000', req.body.todate + '235959');
                
    var query = util.format("" +
    "SELECT COUNT(*) cnt FROM " +
    "(SELECT a.DEV_KEY " +
    "FROM TB_FILE_MNG_HISTORY a " +
    "LEFT JOIN TB_DRON_SETUP_INFO b ON a.DEV_KEY = b.DEV_KEY " +
    "WHERE CUSTOMER_CODE = '%s' " + where + 
    "GROUP BY IDENTIFICATION) A", req.session.code_03);

	logger.info('Query:', query);
    dbConn.query(query, function (error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            res.send(results[0]);
        }
    });
});

router.post('/count', function(req, res) {
    logger.info('Path change : /droneCount');
    var query = 'select count(*) as cnt from TB_DRON_SETUP_INFO ';
    query += 'where DEPT_CODE_03 = \''+ req.session.code_03 + '\' ';
	if(req.body.dev_nm != '') {
		query += 'and DEV_NM like \"%' + req.body.dev_nm + '%\" ';
	}
	if(req.body.dev_key != '') {
		query += 'and DEV_KEY like \"%' + req.body.dev_key + '%\" ';
    }
    if (req.session.userlv == 1) {
        if (req.body.code_01 != 'all') {
            query += 'and DEPT_CODE_01 = \'' + req.body.code_01 + '\' ';
        }
        if (req.body.code_02 != 'all') {
            query += 'and DEPT_CODE_02 = \'' + req.body.code_02 + '\' ';
        }
    } else if (req.session.userlv == 2) {
        query += 'and DEPT_CODE_01=\'' + req.session.code_01 + '\' and DEPT_CODE_02=\'' + req.session.code_02 + '\' ';
    }

    logger.info('Query:', query);
    dbConn.query(query, function (error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:', results[0].cnt);            
            res.send(results[0]);
        }
    });
});

router.post('/paging', function(req, res) {    
    logger.info('Path change : /dronePaging', req.body);
    var query = ""
    query += "SELECT * ";
    query += ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(4) > 0 THEN 'FHD' ELSE '' END CAM_RESOLUTION_FHD ";
    query += ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(2) > 0 THEN 'HD'  ELSE '' END CAM_RESOLUTION_HD ";
    query += ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(1) > 0 THEN 'SD'  ELSE '' END CAM_RESOLUTION_SD ";
    query += "FROM ( ";
    query += "  SELECT D.*, ";
    query += "  CASE WHEN @prev_value = HEX(D.DEV_KEY) THEN @rownum ";
    query += "  WHEN @prev_value:=HEX(D.DEV_KEY) THEN @rownum:=@rownum + 1 END AS ROWNUM ";
    query += "  FROM ";
    query += "  ( ";
    query += "      SELECT A.*, C.CAM_NM, C.CAM_MODEL_NM, C.CAM_TYPE, C.CAM_RESOLUTION, C.DIS ";
    query += "      ,B.CAM_NM DRONE_CAM_NM, B.CAM_MODEL_NM DRONE_CAM_MODEL_NM, B.CAM_TYPE DRONE_CAM_TYPE, B.CAM_NUM ";
    query += "      FROM TB_DRON_SETUP_INFO A ";
    query += "      LEFT JOIN TB_DRON_CAMERA_SETUP_INFO B ";
    query += "      ON A.DEV_KEY = B.DEV_KEY ";
    query += "      LEFT JOIN TB_DRON_CAMERA_MANAGE C ";
    query += "      ON B.CAM_MODEL_NM = C.CAM_MODEL_NM ";
    query += "      ,(SELECT @rownum := 0, @prev_value := null) R ";
    query += "      WHERE 1 = 1 ";
    query += 'and DEPT_CODE_03 = \''+ req.session.code_03 + '\' ';
	if(req.body.dev_nm != '' && req.body.dev_nm != undefined) {
		query += 'and A.DEV_NM like \"%' + req.body.dev_nm + '%\" ';
	}
	if(req.body.dev_key != '' && req.body.dev_key != undefined) {
		query += 'and A.DEV_KEY like \"%' + req.body.dev_key + '%\" ';
    }
    if (req.session.userlv == 1) {
        if (req.body.code_01 != 'all') {
            query += 'and DEPT_CODE_01 = \'' + req.body.code_01 + '\' ';
        }
        if (req.body.code_02 != 'all') {
            query += 'and DEPT_CODE_02 = \'' + req.body.code_02 + '\' ';
        }
    } else if (req.session.userlv == 2) {
        query += 'and DEPT_CODE_01=\'' + req.session.code_01 + '\' and DEPT_CODE_02=\'' + req.session.code_02 + '\' ';
    }
    query += "      ) D ";
    query += "  ORDER BY HEX(DEV_KEY), CAM_NUM ";
    query += ') E ';
    if (req.body.type != 'excel' && req.body.type != undefined) {
        query += 'LIMIT ' + req.body.start + ',' + req.body.pageSize + ' ';
    }

    logger.info('Query: ',query);
    dbConn.query(query, function (error, results, fields) {
        if (error) {
            res.send({result: false, data: null,  error: {code:"505", message:"db error"}});
        } else {
			if(req.body.type == 'excel') {
	    		var filename = "droneInfo.xlsx";
                var excepts = [];
                excepts.push('INSERT_DATE');
	    		utilLib.excelExport(req, res, results, fields, filename, excepts);
			}else {
	    		res.send(results);
			}
        }
    });    
});

router.get('/view', function(req, res) {
    logger.info('Path change : /droneAddModify');
    var type = typeof req.query.dev_key === "undefined" ? 'add' : 'modify';
    logger.info('type', type)
    fs.readFile('html/drone_add_modify.html', 'utf8', function(error, data) {
        if (type === 'modify') {
            var query = util.format("SELECT * FROM TB_DRON_SETUP_INFO WHERE DEV_KEY = '%s'", req.query.dev_key);
            logger.info('Query: ', query);
            dbConn.query(query, function (error, results) {
                res.send(ejs.render(data, {
                    data: results[0], type: type
                }));
            });
        } else {// add
            res.send(ejs.render(data, {
                data: { DEV_KEY: '' }, type: type
            }));
        }
    });    
});

router.post('/add', function(req, res) {
    logger.info('Path change : /droneAdd');
	var date = new Date().formatDate("yyyyMMddhhmmss");
    var rtspUrl = "";
    var dev_key = req.body.dev_key;
    var dev_nm = req.body.dev_nm;
    var dept_code_01 = req.body.dept_code_01;
    var dept_code_02 = req.body.dept_code_02;
    var dept_code_03 = req.session.code_03;
    var nm = req.body.dev_model_nm;
    var dept_nm = req.body.dept_nm;
    var arank = req.body.arank;
    var ctn = "";
    var ctl_seq = 0;
    var rtsp_url = "";
    var insert_date = date;
    var update_date = date;
    var gimbal_nm = req.body.gimbal_nm;
    var gimbal_model_nm = req.body.gimbal_model_nm;
    var gimbal_ptz_ctr = req.body.gimbal_ptz_ctr;
    var home_position = req.body.home_position;

    var query = util.format("INSERT INTO TB_DRON_SETUP_INFO " +
    "(DEV_KEY, DEV_NM, DEPT_CODE_01, DEPT_CODE_02, DEPT_CODE_03, NM, DEPT_NM, ARANK, CTN, CTL_SEQ, RTSP_URL, INSERT_DATE, UPDATE_DATE, " +
    "GIMBAL_NM, GIMBAL_MODEL_NM, GIMBAL_PTZ_CTR, HOME_POSITION) " +
    "VALUES " +
    "('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " +
    "'%s', '%s', '%s', '%s')"
    ,dev_key, dev_nm, dept_code_01, dept_code_02, dept_code_03, nm, dept_nm, arank, ctn, ctl_seq, rtsp_url, insert_date, update_date
    ,gimbal_nm, gimbal_model_nm, gimbal_ptz_ctr, home_position);

	logger.info('Query:', query);
    dbConn.query(query, function (error, results) {
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send(error);
        } else {
            logger.info('DB Success:');            
            res.send({result: true});
            cloudLib.createDefaultFolder(dev_key, req.session.userid, function(bResult) {
                if (bResult) {
                    logger.info('drone create default folder success');
                } else {
                    logger.info('drone create default folder fail');
                }
            })

            // 테라 UTM 드론 정보 동기화
            var serial = dev_key;
            var name = dev_nm;
            var manufacture = 'LG';
            terraLib.getApiToken(function(err, bResult, token) {
                if (err) {
                    return;
                }

                if (bResult) {
                    logger.info("get terra api token success", token)
                    terraLib.droneSync(token, serial, name, manufacture, function (err, bResult2, result2) {
                        if (bResult2) {
                            logger.info("terra droneSync succuess")
                        } else {
                            logger.info("terra droneSync fail")
                        }
                    })
                } else {
                    logger.info("get terra api token failed", result)
                }
            });
        }
    });
});

router.post('/isValidDroneCtn', function(req, res) {
    logger.info('Path change : /isValidDroneCtn');
    var query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_SETUP_INFO WHERE DEV_KEY = '%s'", req.body.dev_key);
    
	logger.info('Query:', query);
    dbConn.query(query, function (error, results) {
        if (error) {
            logger.error('DB Error:', error);
        } else {
            logger.info('DB Success:');            
            res.send(results[0]);
        }
    });
});

router.post('/modify', function(req, res) {
    logger.info('Path change : /droneModify');
    var dev_key = req.body.dev_key;
    var dev_nm = req.body.dev_nm;
    var dept_code_01 = req.body.dept_code_01;
    var dept_code_02 = req.body.dept_code_02;
    var dept_code_03 = req.session.code_03;
    var nm = req.body.dev_model_nm;
    var dept_nm = req.body.dept_nm;
    var arank = req.body.arank;
    var ctn = req.body.ctn;
    var ctl_seq = 0;
    var rtsp_url = "";
    var update_date = new Date().formatDate("yyyyMMddhhmmss");
    var gimbal_nm = req.body.gimbal_nm;
    var gimbal_model_nm = req.body.gimbal_model_nm;
    var gimbal_ptz_ctr = req.body.gimbal_ptz_ctr;
    var home_position = req.body.home_position;

    var query = util.format("UPDATE TB_DRON_SETUP_INFO " +
    "SET DEV_NM= '%s', DEPT_CODE_01= '%s', DEPT_CODE_02= '%s', DEPT_CODE_03= '%s', NM= '%s', DEPT_NM= '%s', ARANK= '%s', " +
    "CTN= '%s', CTL_SEQ= '%s', RTSP_URL= '%s', UPDATE_DATE= '%s', GIMBAL_NM= '%s', GIMBAL_MODEL_NM= '%s', GIMBAL_PTZ_CTR= '%s', HOME_POSITION='%s' " +
    "WHERE DEV_KEY = '%s'", dev_nm, dept_code_01, dept_code_02, dept_code_03, nm, dept_nm, arank, ctn, ctl_seq, rtsp_url, update_date, 
    gimbal_nm, gimbal_model_nm, gimbal_ptz_ctr, home_position, dev_key); 
    logger.info('Query:', query);
    dbConn.query(query, function (error, result) {
        res.send({result: true});
    });
});

// 드론 삭제 시에 드론 내의 카메라 정보들도 함께 삭제
router.post('/droneDelete', function(req, res) {     
    logger.info('Path change : /droneDelete', req.session.userid);
    
    var query = util.format("" +
    "DELETE TB_DRON_SETUP_INFO, TB_DRON_CAMERA_SETUP_INFO " +
    "FROM TB_DRON_SETUP_INFO " +
    "LEFT JOIN TB_DRON_CAMERA_SETUP_INFO ON TB_DRON_SETUP_INFO.DEV_KEY = TB_DRON_CAMERA_SETUP_INFO.DEV_KEY " +
    "WHERE TB_DRON_SETUP_INFO.DEV_KEY = '%s'", req.body.dev_key);
    logger.info('POST /droneDelete', query);
    dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
    });

    // 드론 등록 제거 시에 클라우드 파일 삭제 여부?
    // cloudLib.deleteDefaultFolder(req.body.dev_key, req.session.userid, function(bResult) {
    //     if (bResult) {
    //         logger.info('drone delete default folder success');
    //     } else {
    //         logger.info('drone delete default folder fail');
    //     }
    // })
});

router.get('/control', function(req, res) {    
    logger.info('Path change : /drone/control');
    var JWT = decodeJWT(req, res, function(result, token) {
        if (result) {
            var where = '';
            if (req.body.userlv == '2')
                where = util.format(" AND a.CODE_02 = '%s' ", req.body.code_02); 
        
            var query = util.format("SELECT a.CTL_NM, a.DEFAULT_DEVICE, b.DEV_KEY, a.CODE_01, b.CODE_02 " +
            "FROM " +
            "TB_CONTROL a LEFT JOIN TB_DEFAULT_CONNECT_INFO b " +
            "ON a.CODE_01 = b.CODE_01 " +
            "AND a.CODE_02 = b.CODE_02 " +
            "AND a.CODE_03 = b.CODE_03 " +
            "AND a.DEFAULT_DEVICE = b.DEV_TYPE " +
            "WHERE a.CODE_03 = '%s'" + where, token.code_03);
            logger.info('query', query);
            dbConn.query(query, function (error, result) {
                res.send(result);
            });
        }
    });
});


// 드론 정보
// router.post('/:id/cameras/:cam_nm', function(req, res) {
router.post('/:id/cameras', function(req, res) {
	// var query = util.format("INSERT INTO TB_DRON_CAMERA_SETUP_INFO (" + 
	// "CAM_TYPE, CAM_ID, CAM_NM, CAM_MODEL_NM, CAM_NUM, " + 
	// "CAM_KEY, CAM_SET_USE, INSERT_DATE, UPDATE_DATE, DEV_KEY, " + 
	// "RESOLUTION, FPS, VCODEC, BIT_RATE, CHAN_ID, " + 
	// "PIP_FLAG, PIP_MAIN) VALUES (" + 
	// "'%s', '%s', '%s', '%s', '%s', " + 
	// "'%s', '%s', %s, %s, '%s', " + 
	// "'%s', '%s', '%s', '%s', '%s', " + 
    // "'%s', '%s')"    
    var query = util.format("INSERT INTO TB_DRON_CAMERA_SETUP_INFO " +
    "(CAM_TYPE, CAM_ID, CAM_NM, CAM_MODEL_NM, CAM_NUM, CAM_KEY, CAM_SET_USE, " +
    "INSERT_DATE, UPDATE_DATE, DEV_KEY, RESOLUTION, FPS, VCODEC, BIT_RATE, CHAN_ID, PIP_FLAG, PIP_MAIN) " +
    "SELECT '%s', COUNT(IF(CAM_TYPE='%s', 1, NULL))+1, '%s', '%s', '%s', '', 'Y', " +
    "%s, %s, '%s', '', '', '', '', '', '', '' " + 
    "FROM TB_DRON_CAMERA_SETUP_INFO WHERE DEV_KEY = '%s'"
	, req.body.CAM_TYPE, req.body.CAM_TYPE, req.body.CAM_NM, req.body.CAM_MODEL_NM, req.body.CAM_NUM
    , 'DATE_FORMAT(now(),\"%Y%m%d%H%i%s\")', 'DATE_FORMAT(now(),\"%Y%m%d%H%i%s\")', req.params.id
    , req.params.id);
	// , req.body.RESOLUTION, req.body.FPS, req.body.VCODEC, req.body.BIT_RATE, req.body.CHAN_ID
	// , req.body.PIP_FLAG, req.body.PIP_MAIN);
    logger.info("POST :id/camera", query)
	dbConn.query(query, function(err, results) {
		if (err) {
            logger.error(err)
            res.status(500).send(err)
		} else {
            logger.info('DB Success:')
            res.send(results)
		}
	});
});

router.get('/:id/camera', function(req, res) {
    var orderby = "";
    if (req.query.orderby == "num") {
        orderby = "ORDER BY CAM_NUM ASC"
    } else if (req.query.orderby == "type") {
        orderby = "ORDER BY CAM_TYPE ASC"
    }

    var where = "";
    if (req.query.cam_type != undefined && req.query.cam_type != "") {
        where = util.format(" AND CAM_TYPE = '%s'", req.query.cam_type);
    }
    
	var query = util.format("SELECT * FROM TB_DRON_CAMERA_SETUP_INFO " + 
	"WHERE DEV_KEY = '%s' AND CAM_SET_USE = 'Y' %s %s", req.params.id, where, orderby);	
    logger.info("GET /:id/camera", query);
	dbConn.query(query, function(err, results) {
		if (err) {
            logger.error(err)
            res.status(500).send(err)
		} else {
            logger.info('DB Success:')
            res.send(results)
		}
	});
});

router.post('/:id/cameras/:cam_num/u', function(req, res) {
	var query = util.format("UPDATE TB_DRON_CAMERA_SETUP_INFO " + 
	"SET " + 
	"CAM_TYPE = '%s', CAM_ID = '%s', CAM_MODEL_NM = '%s', " + 
	"CAM_KEY = '%s', INSERT_DATE = %s, UPDATE_DATE = %s, " + 
	"RESOLUTION = '%s', FPS = '%s', VCODEC = '%s', BIT_RATE = '%s', CHAN_ID = '%s', " + 
	"PIP_FLAG = '%s', PIP_MAIN = '%s'" + 
	"WHERE DEV_KEY = '%s' AND CAM_NUM = '%s'"
	, req.body.CAM_TYPE, req.body.CAM_ID, req.body.CAM_MODEL_NM
	, '', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
	, '', '', '', '', ''
	, '', ''
	, req.params.id, req.params.cam_num);
	// , req.body.RESOLUTION, req.body.FPS, req.body.VCODEC, req.body.BIT_RATE, req.body.CHAN_ID
    // , req.body.PIP_FLAG, req.body.PIP_MAIN
    logger.info('POST /:id/cameras/:cam_num/u', query)
	dbConn.query(query, function(err, results) {
		if (err) {
            logger.error(err)
            res.status(500).send(err)
		} else {
            logger.info('DB Success:')
            res.send(results)
		}
	});
});

router.post('/:id/cameras/:cam_num/d', function(req, res) {
	var query = util.format("DELETE FROM TB_DRON_CAMERA_SETUP_INFO " + 
	"WHERE DEV_KEY = '%s' AND CAM_NUM = '%s'", req.params.id, req.params.cam_num);
    logger.info('POST /:id/cameras/:cam_num/d', query)
	dbConn.query(query, function(err, results) {
		if (err) {
            logger.error(err)
            res.status(500).send(err)
		} else {
            logger.info('DB Success:')
            res.send(results)
		}
	});
});

router.get('/cameras/:cam_model_nm/count', function(req, res) {
    var query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_CAMERA_SETUP_INFO WHERE CAM_MODEL_NM = '%s' AND CAM_SET_USE = 'Y'"
    ,req.params.cam_model_nm);
    logger.info('GET /cameras/:cam_model_nm/count', query)
	dbConn.query(query, function(err, results) {
		if (err) {
            logger.error(err)
            res.status(500).send(err)
		} else {
            logger.info('DB Success:')
            res.send(results)
		}
	});
})