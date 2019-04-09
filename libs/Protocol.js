/*
 * es7부터 Object.entries 지원
 * 임대형 node 버전은 v0.10 이기 때문에 object.entries 모듈 필요
*/

var entries = require('object.entries');
var Header = require('./Header');
var Body = require('./Body');
var logger = require('./logger');

module.exports = Protocol;

function Protocol(command, request) {
    this._command = command;
    this._request = request;
    this._header = new Header();
    this._body = new Body();
    this._headerBuf = null;
    this._bodyBuf = null;
    this._buffer = null;
}

Protocol.prototype.make = function (packet) {
    this._bodyBuf = this._body.make(this._request);
    this._headerBuf = this._header.make(this._command, this._bodyBuf.length);

    var headerSize = this._header.size();
    var bodSize = this._body.size();
    var totalSize = headerSize + bodSize;

    this._buffer = new Buffer(totalSize);
    this._headerBuf.copy(this._buffer, 0, 0, headerSize);
    this._bodyBuf.copy(this._buffer, headerSize, 0, bodSize);

    logger.info('send data => :', this._buffer.toString());

    return this._buffer;    
}