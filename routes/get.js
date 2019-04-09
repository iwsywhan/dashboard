var express = require('express');
var router = express.Router();
var getC = require('../controllers/getController');
var checkAuth = require('../middlewares/checkAuth');
var verifyToken = require('../middlewares/jwt');

router.get('/count/servcing', verifyToken, getC.countServcing);

module.exports = router;
