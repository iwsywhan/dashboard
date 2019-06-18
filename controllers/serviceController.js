var logger = require('../libs/logger');
var querystring = require('querystring');
var url = require('url');
var util = require('util');
var dbConn = require('../db');
var fs = require('fs')
// var ejs = require('ejs')

var init = function(req, res) {// 로그인 후 위젯바에서 호출
    logger.info('Path move : /mainPage');

    var storage_size;
    var query = util.format('SELECT C_VALUE as STORAGE' +
        ' FROM TB_COMMON WHERE C_NAME = concat(\'STORAGE_\', (SELECT SV_OP_SV_S FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'))' +
        ' UNION' +
        ' SELECT ifnull(SUM(UPLOAD_FILE_SZ),0) as STORAGE' +
        ' FROM TB_TERMINAL_IMAGE_TRANS WHERE CODE_03 = \'%s\'', req.session.code_03, req.session.code_03);
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            var total_size = 0;
            var used_size = 0;
            if (Object.keys(results).length > 0) {// results[0] 스토리지의 총량 results[1] 스토리지 사용량

                if (results[0].STORAGE.indexOf('GB') > 0) {
                    total_size = results[0].STORAGE.replace(/[^0-9]/g, '') * 1024 * 1024 * 1024; // GB로 변환
                } else if (results[0].STORAGE.indexOf('MB') > 0) {
                    total_size = results[0].STORAGE.replace(/[^0-9]/g, '') * 1024 * 1024; // MB로 변환
                }
                
                used_size = results[1] ? results[1].STORAGE : 0;// results[1]가 없는 이유: 고객사가 없어서 사용량에 해당하는 객체가 없음. 고로 사용량은 0이다.
                
                logger.info('DISK_TOTAL:' + total_size + 'DISK_USED:' + used_size);

                if (total_size <= used_size) {
                    storage_size = 'full';
                } else {
                    storage_size = 'notfull';
                }
            } else {
                storage_size = 'notfull';
            }

            res.send({
                // userid: req.session.userid,
                // userlevel: req.session.userlv,
                // code01: req.session.code_01,
                // code02: req.session.code_02,
                // code03: req.session.code_03,
                storage_size: storage_size,
                total_size: total_size,
                used_size: used_size,
                // drone: req.session.drone
            });
        }
    });
};

var mainPage = function(req, res) {
    console.log('Path move : /service/mainPage');

    if (req.session.drone !== 'Y') {


                    var storage_size;
                    var query = util.format('SELECT C_VALUE as STORAGE' +
                        ' FROM TB_COMMON WHERE C_NAME = concat(\'STORAGE_\', (SELECT SV_OP_SV_S FROM TB_CUSTOMER WHERE CUSTOMER_CODE = \'%s\'))' +
                        ' UNION' +
                        ' SELECT ifnull(SUM(UPLOAD_FILE_SZ),0) as STORAGE' +
                        ' FROM TB_TERMINAL_IMAGE_TRANS WHERE CODE_03 = \'%s\'', req.session.code_03, req.session.code_03);
                
                    dbConn.query(query, function(error, results) {
                        logger.info('Query:', query);
                        if (error) {
                            logger.error('DB Error:', error);
                            res.status(500).send('DB ' + error);
                        } else {
                            var total_size = 0;
                            var used_size = 0;
                            if (Object.keys(results).length > 0) {// results[0] 스토리지의 총량 results[1] 스토리지 사용량
                
                                if (results[0].STORAGE.indexOf('GB') > 0) {
                                    total_size = results[0].STORAGE.replace(/[^0-9]/g, '') * 1024 * 1024 * 1024; // GB로 변환
                                } else if (results[0].STORAGE.indexOf('MB') > 0) {
                                    total_size = results[0].STORAGE.replace(/[^0-9]/g, '') * 1024 * 1024; // MB로 변환
                                }
                                
                                used_size = results[1] ? results[1].STORAGE : 0;// results[1]가 없는 이유: 고객사가 없어서 사용량에 해당하는 객체가 없음. 고로 사용량은 0이다.
                                
                                logger.info('DISK_TOTAL:' + total_size + 'DISK_USED:' + used_size);
                
                                if (total_size <= used_size) {
                                    storage_size = 'full';
                                } else {
                                    storage_size = 'notfull';
                                }
                            } else {
                                storage_size = 'notfull';
                            }
                            console.log('storage====================', storage_size, total_size, used_size);
                            // res.send(ejs.render(data, {
                            res.send({
                                data: {
                                    'userid': req.session.userid,
                                    'userlevel': req.session.userlv,
                                    'code01': req.session.code_01,
                                    'code02': req.session.code_02,
                                    'code03': req.session.code_03,
                                    'storage_size': storage_size,
                                    'total_size': total_size,
                                    'used_size': used_size,
                                    'drone': req.session.drone
                                }
                            });                            
                        }
                    });
    } else {
        res.redirect('/notaccess');
    }
};

var droneStatus = function(req, res) {
    logger.info('Path change : /service/drone');

    var code1 = req.session.code_01;
    var code2 = req.session.code_02;
    var code3 = req.session.code_03;
    var s_userid = req.session.userid;
    var userlevel = req.session.userlv;
    
    var query;
    query = "SELECT ";
    query += "  CUST_CTN, CTN_DEVICE, INSERT_DATE, CUST_NM, CUST_DEPT_NM, STATUS, SVC_TYPE, ";
    query += "  DEV_TYPE, CAMERA_TYPE, VCODEC, FPS, WIDTH, HEIGHT, BIT_RATE, LOGIN_DATE, thumimg ";
    query += "FROM TB_TERMINAL_IMAGE_TRANS A ";
    query += "LEFT JOIN ( ";
    query += "  SELECT  ";
    query += "  P_CUST_CTN, P_INSERT_DATE, SUBSTRING_INDEX(IMG_FILE_NM,'/',-2) thumimg ";
    query += "  FROM ( ";
    query += "      SELECT ";
    query += "          A.*, ";
    query += "          (CASE @vjob WHEN P_CUST_CTN THEN @rownum:=@rownum+1 ELSE @rownum:=1 END) rnum, ";
    query += "          (@vjob:=P_CUST_CTN) vjob ";
    query += "      FROM ";
    query += "          (SELECT * FROM TB_THUMBIMG_ANA_HISTORY WHERE P_CUST_CTN LIKE '" + req.params.id + "%') A, ";
    query += "          (SELECT @vjob:='', @rownum:=0 FROM DUAL) B ";
    query += "      ORDER BY P_CUST_CTN ASC, INSERT_DATE DESC ";
    query += "      ) C ";
    query += "      WHERE rnum = '1' ";
    query += "  ) B ";
    query += "ON A.CUST_CTN = B.P_CUST_CTN AND A.INSERT_DATE = B.P_INSERT_DATE ";
    query += "WHERE ";
    query += "STATUS < '3' ";
    if (userlevel == 1) {
        query += " AND CODE_03= '" + code3 + "' ";
    } else {
        query += " AND CODE_01= '" + code1 + "' AND CODE_02= '" + code2 + "' AND CODE_03= '" + code3 + "' ";
    }
    query += "AND (SVC_TYPE = '0' AND CUST_CTN LIKE '" + req.params.id + "%' OR SVC_TYPE = '3' ";
    query += "AND CUST_CTN LIKE '" + req.params.id + "%' OR SVC_TYPE = '4' AND CUST_CTN LIKE '" + req.params.id + "_%') ";
    query += "ORDER BY CUST_CTN ASC ";
            
    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
}

var dronesStatus = function(req, res) {
    logger.info('Path change : /service/drones');
 
    var code1 = req.session.code_01;
    var code2 = req.session.code_02;
    var code3 = req.session.code_03;
    var s_userid = req.session.userid;
    var userlevel = req.session.userlv;
    
    var query;
    query = "SELECT DISTINCT B.DEV_KEY CUST_CTN, DEV_NM, IFNULL(A.STATUS, '3') STATUS, A.CTN_DEVICE, SVC_TYPE, DEV_TYPE ";
    query += "FROM (SELECT * FROM TB_TERMINAL_IMAGE_TRANS WHERE STATUS < '3') A ";
    query += "RIGHT JOIN (SELECT DEV_KEY, DEV_NM FROM TB_DRON_SETUP_INFO WHERE ";
    if (userlevel == 1) {
        query += " DEPT_CODE_03= '" + code3 + "'";
    } else {
        query += " DEPT_CODE_01= '" + code1 + "' AND DEPT_CODE_02= '" + code2 + "' AND DEPT_CODE_03='" + code3 + "'";
    }
    query += ") B ";
    query += "ON SUBSTRING_INDEX(A.CUST_CTN, '__', 1) = B.DEV_KEY ";
    query += "ORDER BY LOGIN_DATE DESC, INSERT_DATE DESC, CUST_CTN ASC ";

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
}

var status = function(req, res) {
    logger.info('Path change : /serviceStatus');

    var code1 = req.session.code_01;
    var code2 = req.session.code_02;
    var code3 = req.session.code_03;
    var s_userid = req.session.userid;
    var userlevel = req.session.userlv;
    
    var query;
    query = 'SELECT ';
    query += "case isnull(min(SVC_TIME_ST)) + isnull(min(V_SVC_TIME_ST)) when 2 then '' else least(ifnull(min(SVC_TIME_ST), '99999999999999'), ifnull(min(V_SVC_TIME_ST), '99999999999999')) end SVC_TIME_ST,"
    query += 'tot.CUST_CTN as CUST_CTN,'
    query += 'tot.CTN_DEVICE as CTN_DEVICE,'
    query += 'tot.INSERT_DATE as INSERT_DATE,'
    query += 'tot.CUST_NM as CUST_NM,'
    query += 'tot.CUST_DEPT_NM as CUST_DEPT_NM,'
    query += 'tot.CTN_CNT as CTN_CNT,'
    query += 'tot.STB_CNT as STB_CNT,'
    query += 'tot.SUBJECT as SUBJECT,'
    query += 'tot.STATUS  as STATUS,'
    query += 'tot.CTL_NM  as CTL_NM,'
    query += 'tot.SVC_TYPE as SVC_TYPE,'
    query += 'tot.CAMERA_TYPE,'
    query += '    (SELECT SUBSTRING_INDEX(IMG_FILE_NM,\'/\',-2) from TB_THUMBIMG_ANA_HISTORY s WHERE tot.CUST_CTN=s.P_CUST_CTN and tot.INSERT_DATE=s.P_INSERT_DATE order by insert_date desc limit 0, 1) as thumimg , '
    query += '    (SELECT status   FROM TB_LOCATION_ADMIN_MAPPING s WHERE tot.CUST_CTN=s.P_CUST_CTN and tot.INSERT_DATE=s.P_INSERT_DATE and s.STATUS>4 and s.ADMIN_ID=\'' + s_userid + '\' order by INSERT_DATE desc limit 0, 1) as mypcstatus , '
    query += '    (SELECT status  FROM TB_LOCATION_ADMIN_MAPPING i  WHERE i.P_CUST_CTN=tot.CUST_CTN  AND i.P_INSERT_DATE=tot.INSERT_DATE  AND i.STATUS<4 and i.ADMIN_ID = \'' + s_userid + '\' ORDER BY i.INSERT_DATE DESC limit 0, 1  ) as mapstatus, '
    query += 'tot.MOBILE_CNT,'
    query += 'tot.PC_CNT,'
    query += 'tot.DEV_TYPE, tot.LOGIN_DATE, tot.VCODEC, tot.FPS, tot.WIDTH, tot.HEIGHT, tot.BIT_RATE '
    query += ' FROM( '
    query += 'SELECT '
    query += 'a.CUST_CTN,'
    query += 'a.CTN_DEVICE,'
    query += 'a.INSERT_DATE,'
    query += 'a.CUST_NM,'
    query += 'a.CUST_DEPT_NM,'
    query += 'a.SUBJECT,'
    query += 'a.CONTENT,'
    query += 'ifnull(e.CTN_CNT, 0) CTN_CNT,'
    query += 'ifnull(b.STB_CNT, 0) STB_CNT,'
    query += 'b.P_CUST_CTN,'
    query += 'b.P_INSERT_DATE,'
    query += 'b.SVC_TIME_ST,'
    query += 'V_SVC_TIME_ST,'
    query += 'a.STATUS,'
    query += 'a.CODE_01,'
    query += 'a.CODE_02,'
    query += 'a.CODE_03,'
    query += 'a.SVC_TYPE,'
    query += 'd.CTL_NM,'
    query += 'a.CAMERA_TYPE,'
    query += 'ifnull(MOBILE_CNT, 0) MOBILE_CNT,'
    query += 'ifnull(PC_CNT, 0) PC_CNT,'
    query += 'a.DEV_TYPE, a.LOGIN_DATE, a.VCODEC, a.FPS, a.WIDTH, a.HEIGHT, a.BIT_RATE '
    query += ' FROM '
    query += 'TB_TERMINAL_IMAGE_TRANS a'
    query += ' left join('
    query += ' SELECT '
    query += 'count(P_CUST_CTN) as STB_CNT'
    query += ',P_CUST_CTN'
    query += ',P_INSERT_DATE'
    query += ',STB_MAC_ADDR'
    query += ',STB_NM'
    query += ',STB_DEPT_NM'
    query += ',SVC_TIME_ST'
    query += ',SVC_TIME_ED'
    query += ',SVC_STB_IP'
    query += ',STATUS'
    query += ',INSERT_DATE'
    query += ',UPDATE_DATE'
    query += ' FROM '
    query += 'TB_STB_SERVICE'
    query += ' WHERE '
    query += 'STATUS < \'3\''
    query += ' GROUP BY '
    query += 'P_CUST_CTN,'
    query += 'P_INSERT_DATE'
    query += ') b '
    query += 'on a.CUST_CTN = b.P_CUST_CTN and a.INSERT_DATE = b.P_INSERT_DATE'
    query += ' left join('
    query += ' SELECT '
    query += 'P_CUST_CTN'
    query += ',P_INSERT_DATE'
    query += ',SVC_TIME_ST as V_SVC_TIME_ST'
    query += ',count(if (DEV_TYPE = "1",DEV_TYPE,NULL)) as MOBILE_CNT'
    query += ',count(if (DEV_TYPE = "3",DEV_TYPE,NULL)) as PC_CNT'
    query += ' FROM '
    query += 'TB_VIEW_SERVICE'
    query += ' WHERE '
    query += 'STATUS < \'3\''
    query += ' GROUP BY P_CUST_CTN, P_INSERT_DATE'
    query += ') c '
    query += 'on a.CUST_CTN = c.P_CUST_CTN and a.INSERT_DATE = c.P_INSERT_DATE'
    query += ' LEFT JOIN'
    query += ' (SELECT CODE_01, CODE_02, CODE_03, CTL_NM'
    query += ' FROM TB_CONTROL'
    query += ' ) d '
    query += ' ON a.CODE_01 = d.CODE_01 AND a.CODE_02 = d.CODE_02 AND a.CODE_03 = d.CODE_03'
    query += ' LEFT JOIN'
    query += ' (SELECT P_CUST_CTN,P_INSERT_DATE,count(P_CUST_CTN) CTN_CNT'
    query += ' FROM TB_VOICE_CALL_SERVICE'
    query += '  where STATUS < \'3\''
    query += ' GROUP BY P_CUST_CTN,P_INSERT_DATE'
    query += ' ) e '
    query += ' ON a.CUST_CTN = e.P_CUST_CTN and a.INSERT_DATE = e.P_INSERT_DATE'
    query += ' WHERE '
    query += 'a.STATUS < \'3\''
    query += ' GROUP BY a.CUST_CTN, a.INSERT_DATE'
    query += ' HAVING CUST_CTN is not null'
    query += ') tot'
    if (userlevel == 1) {
        query += ' WHERE tot.CODE_03=\'' + code3 + '\' ';
    } else {
        query += ' WHERE tot.CODE_01=\'' + code1 + '\' and tot.CODE_02=\'' + code2 + '\' and tot.CODE_03=\'' + code3 + '\' ';
    }
    query += ' GROUP BY '
    query += 'tot.CUST_CTN,'
    query += 'tot.INSERT_DATE'
    query += ' ORDER BY tot.LOGIN_DATE desc, tot.INSERT_DATE desc'

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
};

var view = function(req, res) {
    logger.info('Path change : /viewService');

    var query = util.format('select b.DEV_NM,b.DEV_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,b.MODEL,b.VERSION,IFNULL(b.SVC_IP, \'\') as SVC_IP,IFNULL(b.DEV_KEY,\'\') as DEV_KEY,b.STATUS,b.VSTATUS,b.INSERT_DATE' +
        ' from ( select P_CUST_CTN, P_INSERT_DATE, DEV_KEY, max(INSERT_DATE) as INSERT_DATE from TB_VIEW_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, DEV_KEY) a' +
        ' left join TB_VIEW_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.DEV_KEY = b.DEV_KEY' +
        ' WHERE DEV_TYPE = \'%s\'' +
        ' order by b.INSERT_DATE', req.query.CUSTCNT, req.query.INSERTDATE, req.query.view_type);

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
}

var stb = function(req, res) {
    logger.info('Path change : /stbService');

    var query = util.format('select b.STB_NM,b.STB_DEPT_NM,b.SVC_TIME_ST,b.SVC_TIME_ED,IFNULL(b.SVC_STB_IP, \'\') as SVC_STB_IP,IFNULL(b.STB_MAC_ADDR,\'\') as STB_MAC_ADDR,b.STATUS,b.INSERT_DATE,' +
        'IFNULL(b.STB_MODEL,\'\') as STB_MODEL, IFNULL(b.STB_OS,\'\') as STB_OS' +
        ' from ( select P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR, max(INSERT_DATE) as INSERT_DATE from TB_STB_SERVICE' +
        ' where P_CUST_CTN = \'%s\' and P_INSERT_DATE = \'%s\' group by P_CUST_CTN, P_INSERT_DATE, STB_MAC_ADDR) a' +
        ' left join TB_STB_SERVICE b' +
        ' on a.INSERT_DATE = b.INSERT_DATE and a.P_CUST_CTN = b.P_CUST_CTN and a.P_INSERT_DATE = b.P_INSERT_DATE and a.STB_MAC_ADDR = b.STB_MAC_ADDR' +
        ' order by b.INSERT_DATE', req.param('CUSTCNT'), req.param('INSERTDATE'));

    dbConn.query(query, function(error, results) {
        logger.info('Query:', query);
        if (error) {
            logger.error('DB Error:', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results);
        }
    });
};

var refresh = function(req, res) {
    logger.info('Path change : refreshService/', req.url);

    query = util.format('select * from TB_TERMINAL_IMAGE_TRANS where CUST_CTN=\'%s\' and CTN_DEVICE=\'%s\' and INSERT_DATE=\'%s\' ', req.param('ctn'), req.param('device'), req.param('insertdate'));
    logger.info('Query:', query);
    dbConn.query(query, function(error, results) {
        if (error) {
            logger.error('DB Error: ', error);
            res.status(500).send('DB ' + error);
        } else {
            res.send(results[0]);
        }
    });
};

var totalCount = function(req, res) {
    var cust_ctn = req.param('CUSTCNT');
    var insert_date = req.param('INSERTDATE');

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
            res.status(500).send('DB ' + error);
        } else {
            res.send(results[0]);
        }
    });
};

module.exports = {
    init: init,
    mainPage: mainPage,
    status: status,
    droneStatus: droneStatus,
    dronesStatus: dronesStatus,
    view: view,
    stb: stb,
    refresh: refresh,
    totalCount: totalCount
};
