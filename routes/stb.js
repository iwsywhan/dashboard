var express = require('express');
var router = express.Router();
var stbC = require('../controllers/stbController');

router.get('/service', stbC.service);

module.exports = router;
