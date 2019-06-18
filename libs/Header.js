var Struct = require('struct');
var utilLib = require('./utilLib');

module.exports = Header;

function Header() {
    this._ctasMessageSt = Struct()
                        .chars('prefix',2)
                        .chars('protocolVersion',2)
                        .chars('reqType', 1)
                        .chars('command', 4)
                        .chars('resultCode', 4)
                        .chars('bodyLength', 8)
                        .chars('reserved', 1) 
}

Header.prototype.size = function () {
    return this._ctasMessageSt.buffer().length;
}

Header.prototype.make = function(command, bodyLen) {    
        this._ctasMessageSt.allocate();
        var proxy = this._ctasMessageSt.fields;
        proxy.prefix = 'AC';
        proxy.protocolVersion = '02';
        proxy.reqType = '1';
        proxy.command = command;
        proxy.resultCode = '0000';
        proxy.bodyLength = utilLib.leadingZeros(bodyLen, 8);
        proxy.reserved = ' ';
    
        var header = this._ctasMessageSt;    
        var headerbuf = header.buffer();    
    
        var buf = new Buffer(headerbuf.length);
        headerbuf.copy(buf, 0, 0, headerbuf.length);
    
        return buf;
}

