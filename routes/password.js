var express = require('express');
var router = express.Router();
var pwC = require('../controllers/pwController');
var verifyToken = require('../middlewares/jwt');

router.post('/reset', pwC.reset);
router.put('/change', pwC.putchange);
router.get('/get', verifyToken, pwC.get);

module.exports = router;
