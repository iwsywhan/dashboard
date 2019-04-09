var JPush = require('./JPush/JPush.js')
var client = JPush.buildClient('d55d6af52a74cc1d6fecced8', 'a7bcb0461fadc35777160b0c')
// var client = JPush.buildClient('c9ac32fe84abeaa52910b625', '04364ea92ac221aeb994840e')
var logger = require('./logger');


// full push.
exports.sendJPush = function(info, registration_id) {
    var notification;
    if (info.PHONE_TYPE == 2) {
        notification = JPush.ios('ios alert');
    } else {
        notification = JPush.android('android alert');
    }

    var extras = {};
    extras.P_CUST_CTN = info.MOBILE_NUM;
    extras.P_INSERT_DATE =  info.INSERT_DATE;
    extras.VIEW_NUM = info.mobileList[0].ctn;
    extras.MSG_TYPE = info.MSG_TYPE;
    extras.CUST_KEY = info.CUST_KEY;
    extras.PUSH_TYPE = info.PUSH_TYPE;
    extras.TITLE = info.title;
    extras.MESSAGE= info.content;
    extras.REQUEST_TIME = info.REQUEST_TIME;

    logger.info('JPush extras: ' + JSON.stringify(extras));

    client.push().setPlatform(JPush.ALL)
        .setAudience(JPush.registration_id(registration_id))
        .setNotification(notification)
        .setMessage(info.content, info.title, 'content type', extras)
        .send(function (err, res) {
        if (err) {
            if (err instanceof JPush.APIConnectionError) {
                logger.error('JPUSH Error', err.message);
                // Response Timeout means your request to the server may have already received,
                // please check whether or not to push
                logger.error('JPUSH Error', err.isResponseTimeout);
            } else if (err instanceof JPush.APIRequestError) {
                logger.error('JPUSH Error', err.message);
            }
        } else {
            logger.info('JPUSH Success', res);
            //logger.info('Sendno: ' + res);
            // logger.info('Msg_id: ' + res.msg_id);
        }
    })
}