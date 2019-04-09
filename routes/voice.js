var express = require('express');
var router = express.Router();
var voiceC = require('../controllers/voiceController');

router.get('/call/status', voiceC.callStatus);

module.exports = router;
