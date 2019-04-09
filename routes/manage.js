var express = require('express');
var router = express.Router();
var manageC = require('../controllers/manageController');
var checkAuthCommon = require('../middlewares/checkAuthCommon');
var checkAuth = require('../middlewares/checkAuth');
var verifyToken = require('../middlewares/jwt');

router.get('/check', manageC.check);
router.get('/check2', manageC.check2);

module.exports = router;
