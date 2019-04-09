var logger = require('../libs/logger');

module.exports = function(req, res, next) {
    if (typeof req.session.pass_change == 'undefined') {
        logger.info('CheckAuth:', req.session.pass_change);
        res.status(400).send('Auth failed from middleware named "CheckPWCommon"');
    } else {
        next();
    }
};
