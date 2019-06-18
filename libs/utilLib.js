/**
 * Created by iwsywhan on 2015-05-22.
 */

Date.prototype.formatDate= function(f) {

    //alert(123);

    if (!this.valueOf()) return " ";

    var weekName = ["�Ͽ���", "������", "ȭ����", "������", "�����", "�ݿ���", "�����"];
    var d = this;

    return f.replace(/(yyyy|yy|MM|dd|E|hh|mm|ss|a\/p)/gi, function($1) {
        switch ($1) {
            case "yyyy": return d.getFullYear();
            case "yy": return (d.getFullYear() % 1000).zf(2);
            case "MM": return (d.getMonth()+1).zf(2);
            case "dd": return d.getDate().zf(2);
            case "E": return weekName[d.getDay()];
            case "HH": return d.getHours().zf(2);
            case "hh": return d.getHours().zf(2);
            case "mm": return d.getMinutes().zf(2);
            case "ss": return d.getSeconds().zf(2);
            case "a/p": return d.getHours() < 12 ? "AM" : "PM";
            default: return $1;
        }
    });
};

String.prototype.string = function(len){var s = '', i = 0; while (i++ < len) { s += this; } return s;};
String.prototype.zf = function(len){return "0".string(len - this.length) + this;};
Number.prototype.zf = function(len){return this.toString().zf(len);};


String.prototype.num = function() {
    return (this.trim().replace(/[^0-9]/g, ""));
}
/*
var util = require('util')
Buffer.prototype.print = function (division) {

    if (typeof division == 'undefined')
        division = 16;

    var logBuf = new Buffer(division);

    var index;
    for (var i = 0; i < this.length; i++){

        var remainder = i%division;
        if (remainder == 0)
            index = 0;

        logBuf[index++] = this[i];

        if (remainder == division-1) {
            util.print(leadingZeros(parseInt(i / division), 4) + ' = ');
            console.log(logBuf);
        }

        if (remainder != division-1 && i == this.length-1) {
            //console.log(remainder);
            util.print(leadingZeros(parseInt(i/division), 4) + ' = ');
            logBuf = logBuf.slice(0, remainder+1);
            console.log(logBuf);
        }
    }
};
*/

function leadingZeros(n, digits) {
    var zero = '';
    n = n.toString();

    if (n.length < digits) {
        for (var i = 0; i < digits - n.length; i++)
            zero += '0';
    }
    return zero + n;
}

function stringToDate(date, dFormat) {

    if (date == null)
        return '';
    else if (Number(date) == 0)
        return '';

    return date == null ? '' : toDate(date, dFormat);
}


function toDate(date, dFormat) {

    if (date.length == 14) {
        var year = date.substr(0, 4);
        var month = date.substr(4, 2)-1;
        var day = date.substr(6, 2);
        var hour = date.substr(8, 2);
        var min = date.substr(10, 2);
        var sec = date.substr(12, 2);

        var today = new Date(year, month, day, hour, min, sec);

        return today.formatDate(dFormat);
    }else if (date.length > 14 && date.length < 18){

        var year = date.substr(0, 4);
        var month = date.substr(4, 2)-1;
        var day = date.substr(6, 2);
        var hour = date.substr(8, 2);
        var min = date.substr(10, 2);
        var sec = date.substr(12, 2);

        var today = new Date(year, month, day, hour, min, sec);

    	return today.formatDate(dFormat) + "." + date.substr(14, 3);
    }else {

        return date;
    }
}

function HrefVar(a,b){
    var vara = a.split(b);
    var varb = vara[1].split("&");
    return varb[0]
}

function NullVar(a){
    if(a == null || a == 'null') a="";
    return a;
}

function ifnullvar(a,b){
    if(a == null || a == '')
        return b;
    else
        return a;
}

function NullVarNumber(a){
    if (a == null)
        return 0;
    return parseInt(a);
}

function getCookie(name) {
    var cname = name + "=";
    var dc = document.cookie;
    if (dc.length > 0) {
        begin = dc.indexOf(cname);
        if (begin != -1) {
            begin += cname.length;
            end = dc.indexOf(";", begin);
            if (end == -1)
                end = dc.length;
            return unescape(dc.substring(begin, end));
        }
    }
    return null;
}

function trim(str) {
	return str.replace(/^\s\s*/,'').replace(/\s\s*$/,'');
}

var i18n = require("i18next");
var toValue = require('./excelValue');
var nodeExcel = require('excel-export');
var dbConn = require('../db')
var util = require('util');

function excelExport(req, res, rows, fields, filename, exceptfields) {
    
    var query = util.format("SELECT LOCALE FROM TB_ADMIN WHERE ADMIN_ID = '%s'", req.session.userid);
    dbConn.query(query, function(error, results) {
        // logger.info('Query:', query);
        if (error) {
            // logger.error('DB Error:', error);
        } else {
            var locale;
            if (results.length > 0) {
                locale = results[0].LOCALE;
            } else {
                locale = 'ko';
            }

            i18n.changeLanguage(locale);

            var padding = 4;
            var conf={};
            for (var i = 0; i < fields.length; i++){
                fields[i].maxLen = 0;
            }
        
            arr = [];
            for (i = 0; i < rows.length; i++) {
        
                   var a = [];
                for (var j = 0; j < fields.length; j++){
        
                    var isInclude;
                    if (isArray(exceptfields)) {
                        isInclude = exceptfields.filter(function(item){
                            return item == fields[j].name;
                        });
                    }
        
                    if (typeof isInclude != 'undefined' && isInclude.length == 1)
                        continue;
        
                       if (rows[i][fields[j].name] == null){
                           a.push('');
        
                       }else {
                        a.push(toValue.getCodeToValue(fields[j].name, rows[i][fields[j].name]));
                        fields[j].maxLen = Math.max(fields[j].maxLen, rows[i][fields[j].name].toString().length);
                    }
                }
        
                arr.push(a);
            }
        
            conf.cols = [];
            for (var i = 0; i < fields.length; i++){        
                var isInclude;
                if (isArray(exceptfields)) {
                    isInclude = exceptfields.filter(function(item){
                        return item == fields[i].name;
                    });
                }

                if (typeof isInclude != 'undefined' && isInclude.length == 1)
                    continue;
        
                //}else {
                    var header = {};
        
                    header.caption = toValue.columnNameToValue(fields[i].name);
                    header.type = 'string';
                    header.width = Math.max(fields[i].maxLen+padding, toValue.fn_strlen(header.caption));
        
                    conf.cols.push(header);
        
                //}
            }
            conf.rows = arr;
            var result = nodeExcel.execute(conf);
            res.setHeader('Content-Type', 'application/vnd.openxmlformates');
            //res.setHeader("Content-Disposition", "attachment;filename="+ filename);
            res.setHeader("Content-Disposition", "attachment;filename="+ encodeURI(filename));
            res.end(result, 'binary');            
        }
    });
}

function getTimeToStringTime(strTime) {

    if (strTime.length == 14) {
        var year = strTime.substr(0, 4);
        var month = strTime.substr(4, 2)-1;
        var day = strTime.substr(6, 2);
        var hour = strTime.substr(8, 2);
        var min = strTime.substr(10, 2);
        var sec = strTime.substr(12, 2);

        var today = new Date(year, month, day, hour, min, sec);

        return today.getTime();
	}

	return 0;
}

function getTimeSecond(time){

	return parseInt(time / 1000);
}

function getVersion(str){

	var pattern = /(([0-9]{1,2})\.){2}([0-9]{1,2})/g;
	return str.match(pattern);
}

function validate(key) {
	for(var i = 0; i < key.value.length; i++) {
         var chr = key.value.substr(i,1);

         if(",".indexOf(chr) > -1){

            alert(","+$.i18n.t('msg.277'));
            // alert(", 는 등록하실 수 없습니다.")
            key.value='';
            key.focus();
         }

    }
    return;
}

function validate_tel() {
	if((event.keyCode<48)||(event.keyCode>57))
		event.returnValue=false;
}

function numbersonly(e, decimal) {
    var key;
    var keychar;

    if (window.event) {
        key = window.event.keyCode;
    } else if (e) {
        key = e.which;
    } else {
        return true;
    }
    keychar = String.fromCharCode(key);

    if ((key == null) || (key == 0) || (key == 8) || (key == 9) || (key == 13)
            || (key == 27)) {
        return true;
    } else if ((("0123456789").indexOf(keychar) > -1)) {
        return true;
    } else if (decimal && (keychar == ".")) {
        return true;
    } else
        return false;
}

function GetBrowserInfo(userAgent) {

    var start, end;
    var browser = new Object();

    browser.name = 'Chrome';
    start = userAgent.indexOf(browser.name);

    if (start > -1) {
        browser.version = userAgent.substr(start + browser.name.length + 1, 2);
        return browser;
    }

    browser.name = 'Firefox';
    start = userAgent.indexOf(browser.name);
    if (start > -1) {
        browser.version = userAgent.substr(start + browser.name.length + 1, 2);
        return browser;
    }

    browser.name = 'Trident';
    start = userAgent.indexOf(browser.name);
    if (start > -1) {
        // +3을 해야 ie실제 버전과 맞는다.
        browser.version = Number(userAgent.substr(start + browser.name.length + 1, 1));
        browser.version += 4;
        browser.name = "IE";
        return browser;
    }
}

function isArray(o) {
    return Object.prototype.toString.call(o) == '[object Array]';
}

function term(startTime,endTime){

  var startDate = new Date(parseInt(startTime.substring(0,4), 10),
             parseInt(startTime.substring(4,6), 10)-1,
             parseInt(startTime.substring(6,8), 10),
             parseInt(startTime.substring(8,10), 10),
             parseInt(startTime.substring(10,12), 10),
             parseInt(startTime.substring(12,14), 10)
            );
   var endDate = new Date(parseInt(endTime.substring(0,4), 10),
             parseInt(endTime.substring(4,6), 10)-1,
             parseInt(endTime.substring(6,8), 10),
             parseInt(endTime.substring(8,10), 10),
             parseInt(endTime.substring(10,12), 10),
             parseInt(endTime.substring(12,14), 10)
            );

   // 두 일자(startTime, endTime) 사이의 차이를 구한다.
   var dateGap = endDate.getTime() - startDate.getTime();
   var timeGap = new Date(0, 0, 0, 0, 0, 0, endDate - startDate);

   // 두 일자(startTime, endTime) 사이의 간격을 "일-시간-분"으로 표시한다.
   var diffDay  = Math.floor(dateGap / (1000 * 60 * 60 * 24)); // 일수
   var diffHour = timeGap.getHours();       // 시간
   var diffMin  = timeGap.getMinutes();      // 분
   var diffSec  = timeGap.getSeconds();      // 초

   return diffDay;
}
function today(){
  var today = new Date();

  var year = today.getFullYear();
  var month = today.getMonth() + 1;
  var day = today.getDate();
  var hour = today.getHours();
  var min = today.getMinutes();
  var second = today.getSeconds();

  if (month < 10) {
    month = '0' + month;
  }
  if (day < 10) {
    day = '0' + day;
  }
  if (hour < 10) {
    hour = '0' + hour;
  }
  if (min < 10) {
    min = '0' + min;
  }
  if (second < 10) {
    second = '0' + second;
  }
  var date = year + '' + month + '' + day + '' + hour + '' + min + '' + second;
  return date
}
function RPAD(s, c, n) {
  if (!s || !c || s.length >= n) {
    return s;
  }
  var max = (n - s.length) / c.length;
  for (var i = 0; i < max; i++) {
    s += c;
  }
  return s;
}

function masking_name(name) {
  if (name == null || name == 'null') {
    return "";
  } else if (name.length == '2') {
    return name.substr(0, 1)+"*"
  } else {
    return RPAD(name.substr(0, 1), '*', name.length - 1) + name.substr(name.length - 1, 1);
  }
}

function masking_tel(tel) {
  if (tel == null || tel == 'null') {
    return "";
  } else if (tel.length<9){
    return RPAD(tel.substr(0, 1), '*', tel.length - 1) + tel.substr(tel.length - 1, 1);
  } else if (tel.indexOf('02') == 0) {
    return tel.replace(/(\d{2})(\d{3,4})(\d{4})/, '$1****$3');
  } else {
    var pattern = /^(\d{2,3})-?(\d{3,4})-?(\d{4})$/;
    var match = pattern.exec(tel);
    match[2] = match[2].replace(/[0-9]/gi, "*");
    return match[1] + match[2] + match[3];
  }
}

function masking_num(num) {
  if (num == null || num == 'null') {
    return "";
  } else {
    var pattern = /^(\S{6})(\S{1,10})$/;
    var match = pattern.exec(num);
    if (num.length > 6) {
      match[2] = match[2].replace(/\S/gi, "*");
      return match[1] + match[2];
    }
    return num;
  }
}

function leftPad(str, chr, num) {
	str = str + "";

	var max = num - str.length;
	for (var i = 0; i < max; i++) {
		str = chr + str;
	}

	return str;
}

function toResolution(resolution) {
    var ret = {};
    switch (resolution) {
        case '1' :  // SD
            ret.V_WIDTH = '640';
            ret.V_HEIGHT = '480';
            break
        case '2' :  // HD
            ret.V_WIDTH = '1280';
            ret.V_HEIGHT = '900';
            break
        case '3' :  // FHD
            ret.V_WIDTH = '1920';
            ret.V_HEIGHT = '1080';
            break
        default:
            ret.V_WIDTH = '640';
            ret.V_HEIGHT = '480';
            break;
    }

    return ret;
}

exports.masking_num = masking_num;
exports.masking_tel = masking_tel;
exports.masking_name = masking_name;
exports.trim = trim;
exports.leadingZeros = leadingZeros;
exports.stringToDate = stringToDate;
exports.NullVar = NullVar;
exports.ifnullvar = ifnullvar;
exports.excelExport = excelExport;
exports.getVersion = getVersion;
exports.validate = validate;
exports.validate_tel = validate_tel;
exports.getTimeSecond = getTimeSecond;
exports.GetBrowserInfo = GetBrowserInfo;
exports.term = term;
exports.today = today;
exports.leftPad = leftPad;
exports.toResolution = toResolution;
