var mysql = require('mysql');
var logger = require('../libs/logger');

// var DB_HOST = '127.0.0.1';
var DB_HOST = '192.168.0.120';
var db_config = {
    host: DB_HOST,
    port: 3306,
    user: 'vcs',
    password: 'vcs123',
    database: 'vcsDB',
    insecureAuth: true
};
var dbConn = mysql.createConnection(db_config);
var bConnect = true;

function handleDisconnect() {
    dbConn = mysql.createConnection(db_config); // Recreate the connection, since
    // the old one cannot be reused.
    dbConn.connect(function(err) { // The server is either down

        if (err) {
            // or restarting (takes a while sometimes).
            logger.error('error when connecting to db:' + err);
            //console.log('error when connecting to db:', err);
            setTimeout(handleDisconnect, 2000); // We introduce a delay before attempting to reconnect,
        } else { // to avoid a hot loop, and to allow our node script to
            bConnect = true;
        }

    }); // process asynchronous requests in the meantime.
    // If you're also serving http, display a 503 error.
    dbConn.on('error', function(err) {
        //console.log('db error', err);
        logger.error('DB Error', err);

        // if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.fatal) { // Connection to the MySQL server is usually
            if (bConnect == true) {
                handleDisconnect(); // lost due to either server restart, or a
                bConnect = false;
            }
        // } else { // connnection idle timeout (the wait_timeout
            // throw err; // server variable configures this)
        // }
    });

    dbConn.on('end', function(err) {
        //console.log('db end', err);
        logger.error('db end', err);
        if (bConnect == true) {
            handleDisconnect();
            bConnect = false;
        }
    });
}

handleDisconnect();

module.exports = dbConn;
