var entries = require('object.entries');

function Body() {
    this._offset = 0;
}

Body.prototype.size = function () {
    return this._offset;
}

Body.prototype.make = function (request) {
    var body = this.makeProtocolObject(request).slice(0, -1);
    var bodybuf = new Buffer(body);
    this._offset = bodybuf.length;
    return bodybuf;
}

Body.prototype.makeProtocolObject = function makeProtocolObject(data) {
    var body = '';
    entries(data).forEach(function (key, index) {        
        if (typeof key[1] == "object") {
            var newObject = makeProtocolArray(key[0], key[1]);
            body += makeProtocolObject(newObject);
        } else {
            body += key[0] + '=' + key[1] + '&';
        }
    })

    return body;
};

function makeProtocolArray(rootKey, arr) {
    if (!Array.isArray(arr)) {
        throw new 'Parameter is not a array';
    }

    var newObject = {};
    arr.forEach(function (element) {
        if (typeof element == "object") {
            entries(element).forEach(function (key) {
                if (newObject.hasOwnProperty(key[0])) {
                    newObject[key[0]] = newObject[key[0]] + ',' + key[1];
                } else {
                    newObject[key[0]] = key[1];
                }
            })
        } else {        // string or Number
            if (newObject.hasOwnProperty(rootKey)) {
                newObject[rootKey] = newObject[rootKey] + ',' + element;
            } else {
                newObject[rootKey] = element;
            }
        }
    })

    return newObject;
}

module.exports = Body;