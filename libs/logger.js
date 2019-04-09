var winston = require('winston');
var moment = require('moment');
var path = require('path');
var fs = require('fs');

var LOGGER_FOLDER_PATH = '/LCS/APP/LOG/WEBAPP/daily-w';

/* log 관리 */
var logger = new(winston.Logger)({
    transports: [
        new winston.transports.DailyRotateFile({
            name: 'dailyInfoLog',
            level: 'emerg',
            filename: '' + LOGGER_FOLDER_PATH,
            timestamp: function() {
                return moment().format("YYYY-MM-DD HH:mm:ss.SSS");
            },
            datePattern: 'yyyyMMdd.log',
            json: false
        }),
    ]
});

winston.setLevels(winston.config.syslog.levels);
logger.setLevels(winston.config.syslog.levels);

logger.info('init logger');

module.exports = logger;
