var express = require('express');
var router = express.Router();
var loginC = require('../controllers/loginController');

router.post('/', loginC.login);

module.exports = router;
