var express = require('express');
var router = express.Router();
var chNoticeC = require('../controllers/chNoticeController');
var verifyToken = require('../middlewares/jwt');

router.post('/getCountNewNoticeOnChannel', chNoticeC.getCountNewNoticeOnChannel);
router.post('/InsertNoticeDataOnChannel', chNoticeC.InsertNoticeDataOnChannel);
router.post('/SelectNoticeDataOnChannel', chNoticeC.SelectNoticeDataOnChannel);
router.post('/UpdateNoticeDataOnChannel', chNoticeC.UpdateNoticeDataOnChannel);
router.post('/UpdateSystemNoticeChangeStatus', chNoticeC.UpdateSystemNoticeChangeStatus);
// router.post('/UpdateSystemNoticeResend', chNoticeC.UpdateSystemNoticeResend);
router.post('/getSystemNoticeContent', chNoticeC.getSystemNoticeContent);
router.post('/getServiceNoticeContent', chNoticeC.getServiceNoticeContent);

module.exports = router;
