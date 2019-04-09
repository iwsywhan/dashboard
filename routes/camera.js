var express = require('express');
var router = express.Router();
var logger = require('../libs/logger');
var fs = require('fs')
var dbConn = require('../db')
var util = require('util')
var ejs = require('ejs')

module.exports = router;

router.get('/v', function(req, res) {
    fs.readFile('html/camera_control.html', 'utf8', function(error, data) {
        res.send(data);
        // res.send(ejs.render(data, {}));
    });
});

router.get('/popup/v', function(req, res) {
	var type = typeof req.query.cam_nm === "undefined" ? 'add' : 'modify';
    fs.readFile('html/camera_control_popup.html', 'utf8', function(error, data) {
        if (type === 'modify') {
			var query = util.format("SELECT * " + 
			",CASE WHEN BIN(CAM_RESOLUTION) & BIN(4) > 0 THEN 'FHD' ELSE '' END CAM_RESOLUTION_FHD " +
			",CASE WHEN BIN(CAM_RESOLUTION) & BIN(2) > 0 THEN 'HD'  ELSE '' END CAM_RESOLUTION_HD " +
			",CASE WHEN BIN(CAM_RESOLUTION) & BIN(1) > 0 THEN 'SD'  ELSE '' END CAM_RESOLUTION_SD " + 
			"FROM TB_DRON_CAMERA_MANAGE WHERE CAM_MODEL_NM = '%s'"
			, req.query.cam_nm);
            logger.info('Query: ', query);
            dbConn.query(query, function (error, results) {
                res.send(ejs.render(data, {
                    data: results[0], type: type
                }));
            });
        } else {					// add
            res.send(ejs.render(data, {
                data: "", type: type
            }));
        }
    });
});

router.post('/', function(req, res) {
	var query = util.format("INSERT INTO TB_DRON_CAMERA_MANAGE (" + 
	"CAM_TYPE, CAM_NM, CAM_MODEL_NM, CAM_RESOLUTION, ZOOM_CTL, " + 
	"AUTOFOCUS, DIS, INSERT_DATE, UPDATE_DATE) VALUES (" + 
	"'%s', '%s', '%s', '%s', '%s', " + 
	"'%s', '%s', %s, %s)"
	, req.body.CAM_TYPE, req.body.CAM_NM, req.body.CAM_MODEL_NM, req.body.CAM_RESOLUTION, req.body.ZOOM_CTL
	, req.body.AUTOFOCUS, req.body.DIS, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")');

	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});

router.get('/', function(req, res) {

	var where = "WHERE 1=1";
	if (req.query.cam_model_nm != "" && req.query.cam_model_nm != undefined) {
		where += " AND CAM_MODEL_NM LIKE '%" + req.query.cam_model_nm + "%'";
	}
	if (req.query.cam_resolution >= 0 && req.query.cam_resolution != undefined) {
		where += " AND BIN(CAM_RESOLUTION) & BIN(" + req.query.cam_resolution + ") > 0 ";
	}
	if (req.query.cam_type != "" && req.query.cam_type != undefined) {
		where += " AND CAM_TYPE = '" + req.query.cam_type + "'";
	}
	if (req.query.start != "" && req.query.start != undefined && req.query.pageSize != "" && req.query.pageSize != undefined) {
		where += " LIMIT " + req.query.start + "," + req.query.pageSize;
	}

	var query = util.format("SELECT * " +
    ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(4) > 0 THEN 'FHD' ELSE '' END CAM_RESOLUTION_FHD " +
    ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(2) > 0 THEN 'HD'  ELSE '' END CAM_RESOLUTION_HD " +
    ",CASE WHEN BIN(CAM_RESOLUTION) & BIN(1) > 0 THEN 'SD'  ELSE '' END CAM_RESOLUTION_SD " +
	"FROM TB_DRON_CAMERA_MANAGE %s ", where);
	logger.info("GET /cameras", query);
	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});

router.post('/:id/u', function(req, res) {
	var query = util.format("UPDATE TB_DRON_CAMERA_MANAGE " + 
	"SET " + 
	"CAM_TYPE = '%s', CAM_MODEL_NM = '%s', CAM_RESOLUTION = '%s', ZOOM_CTL = '%s', IS_TRACKING = '%s', " + 
	"AUTOFOCUS = '%s', DIS = '%s', INSERT_DATE = %s, UPDATE_DATE = %s " + 
	"WHERE CAM_MODEL_NM = '%s'"
	,req.body.CAM_TYPE, req.body.CAM_MODEL_NM, req.body.CAM_RESOLUTION, req.body.ZOOM_CTL, req.body.IS_TRACKING
	,req.body.AUTOFOCUS, req.body.DIS, 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")', 'DATE_FORMAT(now(),"%Y%m%d%H%i%s")'
	,req.params.id);
	logger.info('POST /:id/u', query);
	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});

router.post('/:id/d', function(req, res) {
	var query = util.format("DELETE FROM TB_DRON_CAMERA_MANAGE " + 
	"WHERE CAM_MODEL_NM = '%s'"
	,req.params.id);
	logger.info('POST /:id/d', query)
	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});

router.get('/count', function(req, res) {
	var query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_CAMERA_MANAGE");

	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});

router.get('/:id/count', function(req, res) {
	var query = util.format("SELECT COUNT(*) CNT FROM TB_DRON_CAMERA_MANAGE WHERE CAM_MODEL_NM = '%s'"
	,req.params.id);
	dbConn.query(query, function(err, results) {
		if (err) {
			logger.error(err)
			res.status(500).send(err);
		} else {
			logger.info('DB Success:')
			res.send(results);
		}
	});
});