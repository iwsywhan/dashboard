var logger = require('../libs/logger');

module.exports = function(req, res, next) {console.log('checkauth', req.session);
    if (typeof req.session.userid == 'undefined' || req.session.userlv == '3') {
        logger.info('CheckAuth:', req.session.userid, req.session.userlv);
        res.status(400).send('Auth failed from middleware named "CheckAuth"');
    } else {
        next();
    }
};
