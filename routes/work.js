var express = require('express');
var router = express.Router();
var workC = require('../controllers/workController');

router.get('/detail/save', workC.detailSave);
router.get('/list', workC.list);

module.exports = router;
