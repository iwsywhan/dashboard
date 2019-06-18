var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var logger = require('../libs/logger');
var fs = require('fs');
var pcViewerAPI = require('../pcViewerAPI.js');
var LiveCam2UTM = require('../libs/LiveCam2UTM');
var Protocol = require('../libs/Protocol');
var AccountResult = require('../libs/AccountResult')
var app = require('../app.js')
var accountC = require('../controllers/accountController');


var accountResult = new AccountResult();

module.exports = router;

router.post('/getLanguage', accountC.getLanguage);
router.post('/setLanguage', accountC.setLanguage);

// router.post('/v1/checkAccount', function(req, res) {
//     logger.info('Path change : /utmapi/v1/checkAccount');
//     if (accountResult.checkParam(req, res)) {
//         accountResult.checkCustomer(app.dbConn, req, res, function(result) {
//             if (result) {
//                 accountResult.isEntry(app.dbConn, req, res);
//             }
//         });
//     }
// });

// router.post('/v1/createAccount', function(req, res) {
//     logger.info('Path change : /utmapi/v1/createAccount');

//     // CODE_01, CODE02, UTM_ID 컬럼 필요
//     if (accountResult.checkParam(req, res)) {
//         accountResult.checkCustomer(app.dbConn, req, res, function(result1) {
//             if (result1) {
//                 accountResult.isEntry(app.dbConn, req, res, function(result2) {
//                     if (result2) {
//                         accountResult.insertAccount(app.dbConn, req, res);
//                     }
//                 });
//             }
//         });
//     }   
// });


