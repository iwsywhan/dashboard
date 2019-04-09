var logger = require('../libs/logger');

module.exports = function(req, res, next) {console.log('checkauthcommon', req.session);
    if (typeof req.session.userid == 'undefined') {
        logger.info('CheckAuth:', req.session.userid)
        res.status(400).send('Auth failed from middleware named "CheckAuthCommon"');
    } else {
        next();
    }
};
