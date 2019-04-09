var express = require('express');
var router = express.Router();
var loginC = require('../controllers/loginController');
var verifyToken = require('../middlewares/jwt');

router.get('/', loginC.loginR);// 웹에서 로그인 페이지 랜더링
router.post('/', loginC.loginPost)// 웹에서 로그인 입력 전송
router.get('/top', loginC.topstate);
router.get('/logout', loginC.logout);
router.get('/logout2', loginC.logout2);

router.get('/check/:tken', loginC.tken);

module.exports = router;
