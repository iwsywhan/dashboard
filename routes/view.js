var express = require('express');
var router = express.Router();
var viewC = require('../controllers/viewerController');

router.get('/service', viewC.pclist);

module.exports = router;
