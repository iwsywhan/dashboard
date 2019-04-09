var express = require('express');
var router = express.Router();
var serviceC = require('../controllers/serviceController');
var checkAuth = require('../middlewares/checkAuth');
var checkAuthCommon = require('../middlewares/checkAuthCommon');
var verifyToken = require('../middlewares/jwt');

router.get('/', verifyToken, serviceC.init);
router.get('/mainPage', serviceC.mainPage);
router.get('/status', verifyToken, serviceC.status);
router.get('/drone/:id', verifyToken, serviceC.droneStatus);
router.get('/drones', verifyToken, serviceC.dronesStatus);
router.get('/view', serviceC.view);
router.get('/stb', serviceC.stb);
router.get('/refresh/:ctn', serviceC.refresh);
router.get('/total-count', serviceC.totalCount);

module.exports = router;
