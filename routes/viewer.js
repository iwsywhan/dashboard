var express = require('express');
var router = express.Router();
var viewerC = require('../controllers/viewerController');

router.get('/pc/check', viewerC.pcCheck);

module.exports = router;
