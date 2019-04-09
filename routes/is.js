var express = require('express');
var router = express.Router();
var isC = require('../controllers/isController');
var checkAuthCommon = require('../middlewares/checkAuthCommon');
var checkAuth = require('../middlewares/checkAuth');
var verifyToken = require('../middlewares/jwt');

router.post('/mVoIP', verifyToken, isC.mVoIP);
router.post('/exist-regid', verifyToken, isC.existRegid);

module.exports = router;
