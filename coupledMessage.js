/**
 * Created by iwsywhan on 2015-05-15.
 */

var Struct = require('struct');
var querystring = require('querystring');
var logger = require('./libs/logger');
var utilLib = require('./libs/utilLib');

var ctasMessageSt = Struct()
        .chars('prefix',2)
        .chars('protocolVersion',2)
        .chars('reqType', 1)
        .chars('command', 4)
        .chars('resultCode', 4)
        .chars('bodyLength', 8)
        .chars('reserved', 1)

function parsingBodyData(data, callback) {
    logger.info('receive data  <= ', data.toString());

    ctasMessageSt.allocate();
    var headerbuf = ctasMessageSt.buffer();
    var headerLength = headerbuf.length;

    ctasMessageSt._setBuff(data);
    var proxy = ctasMessageSt.fields;
    var header = { 'prefix':proxy.prefix, 'protocolVersion':proxy.protocolVersion, 'reqType':proxy.reqType,
        'command':proxy.command, 'resultCode':proxy.resultCode, 'bodyLength':proxy.bodyLength };    

	var bodyBuf = data.slice(headerLength, headerLength+Number(header.bodyLength));
    var body = bodyBuf.toString('utf8');
    
    logger.info('receive body <= ', body);
    var parse = querystring.parse(body);
    var error = 0;
    if (header.prefix != 'AC') {
        error = 'prefix is not AC';
        callback(error, header, parse, '');
    } else if (header.protocolVersion != 2) {
        error = 'protocol Version is mismatch';
        callback(error, header, parse, '');
    } else {
		var unProcessDataLength = data.length - headerLength - Number(header.bodyLength);
		var unProcessedBuf = '';
		if (unProcessDataLength > 0){
			unProcessedBuf = data.slice(headerLength + Number(header.bodyLength), headerLength+Number(header.bodyLength)+unProcessDataLength);
		    logger.info('unProcessed data  <= ', unProcessedBuf.toString());
		}
        callback(error, header, parse, unProcessedBuf);
    }        
};

//#1 Start [2015.7.15] by ywhan
function makeResponseData(cmd, resCode, data) {

    var body;
    body = data;

    logger.info('body:' + body);
    var bodybuf = new Buffer(body);

    ctasMessageSt.allocate();

    var proxy = ctasMessageSt.fields;
    proxy.prefix = 'AC';
    proxy.protocolVersion = '02';
    proxy.reqType = '2';
    proxy.command = cmd;
    proxy.resultCode = resCode;
    proxy.bodyLength = utilLib.leadingZeros(bodybuf.length, 8);
    proxy.reserved = ' ';

    var header = ctasMessageSt;
    var headerbuf = header.buffer();
    var packetLen = headerbuf.length + bodybuf.length;

    var buf = new Buffer(headerbuf.length + bodybuf.length);
    headerbuf.copy(buf, 0, 0, headerbuf.length);
    bodybuf.copy(buf, headerbuf.length, 0, body.bodyLength);

    return buf;
}
//#1 End

function makeData(type, data, serviceyn) {

    //#1 Start [2015.7.15] by ywhan
    var body;
    switch (type) {

    	case 'B101' :
    	case 'B103' :
    	case 'B104' :
    		body = makeBodyDataOfService(data, serviceyn);
    		break;
        case 'B200' :   // Service AddVoice
        case 'D200' :   // Room AddVoice
        case 'B201':    // Service DeleteVoice
        case 'D201':    // Room DeleteVoice
            body = makeBodyDataOfVoice(data);
            break;
        case 'B300' :   // Service AddSTB
        case 'D300' :   // Room AddSTB
        case 'B301':    // Service DeleteSTB
        case 'D301':    // Room DeleteSTB
            body = makeBodyDataOfSTB(data);
            break;
        case 'B302' :   // Service AddMobile
        case 'B303' :   // Service DeleteMobile
        	body = makeBodyDataOfMobile(data);
            break;
        case 'B304':    // Start stream
        case 'B305':    // End stream
            body = makeBodyDataOfStream(data);
            break;
		case 'B901':      // Abnormal
            body = makeBodyDataOfAbnormal(data);
			break;
        case 'B210': 	// AR Set up
        case 'B211': 	// AR Start
        case 'B212': 	// AR Feature
        case 'B214':	// AR History
        case 'B215':	// AR Status
        case 'B216': 	// AR Stop
        case 'B230':    // notice write
            body = data;
            break;
        case 'B708':    // notice event
            body = makeBodyDataNotice(data);
            break;
        case 'B306':    // VOD Play
            body = makeBodyDataPlayRTSP(data);
            break;
        case 'B307':    // VOD Pause
            body = makeBodyDataPauseRTSP(data);
            break;
        default :
            body = data;
    }
    //#1 End

    var bodybuf = new Buffer(body);

    ctasMessageSt.allocate();

    var proxy = ctasMessageSt.fields;
    proxy.prefix = 'AC';
    proxy.protocolVersion = '02';
    proxy.reqType = '1';
    proxy.command = type;
    proxy.resultCode = '0000';
    proxy.bodyLength = utilLib.leadingZeros(bodybuf.length, 8);
    proxy.reserved = ' ';

    var header = ctasMessageSt;
    logger.info('send header => ' + JSON.stringify(header));

    var headerbuf = header.buffer();
    var packetLen = headerbuf.length + bodybuf.length;

    logger.info('send body => ' + body);

    var buf = new Buffer(headerbuf.length + bodybuf.length);
    headerbuf.copy(buf, 0, 0, headerbuf.length);
    bodybuf.copy(buf, headerbuf.length, 0, body.bodyLength);

    logger.info('send data => :', buf.toString());

    return buf;
};

function makeBodyDataOfMobileInfo(data) {
    return data;
}

function makeBodyDataOfService(data, serviceyn) {

    var serviceInfo = data;
    var makeServiceInfo1 = 'MOBILE_NUM='+serviceInfo.MOBILE_NUM + '&CTN_DEVICE='+serviceInfo.CTN_DEVICE;
    var makeServiceInfo2 = '&SERVICE=' + serviceyn + '&CONTROL_TEL_NUM=' + serviceInfo.CONTROL_TEL_NUM + '&CONTROL_ID=' + serviceInfo.CONTROL_ID;
    var packetBody = makeServiceInfo1 + makeServiceInfo2;

    logger.info(packetBody);

    return packetBody;
}

function makeBodyDataOfVoice(data) {

    var voiceInfo = data;

    var makeVoiceInfo1 = 'CTN_DEVICE='+voiceInfo.CTN_DEVICE+'&MOBILE_NUM='+voiceInfo.MOBILE_NUM;
    logger.info(makeVoiceInfo1);

    var mobileList = nameList = deptList = arankList = '';
    for (var i = 0; i < voiceInfo.voiceList.length; i++) {
        var mobileList = mobileList + voiceInfo.voiceList[i].ctn + ',';
    }
    mobileList = mobileList.substring(0 ,mobileList.length-1);

    for (var i = 0; i < voiceInfo.voiceList.length; i++) {
        var nameList = nameList + voiceInfo.voiceList[i].name + ',';
    }
    nameList = nameList.substring(0 ,nameList.length-1);

    for (var i = 0; i < voiceInfo.voiceList.length; i++) {
        var deptList = deptList + voiceInfo.voiceList[i].dept + ',';
    }
    deptList = deptList.substring(0 ,deptList.length-1);

    for (var i = 0; i < voiceInfo.voiceList.length; i++) {
        var arankList = arankList + voiceInfo.voiceList[i].arank + ',';
    }
    arankList = arankList.substring(0 ,arankList.length-1);

    var makeVoiceInfo2 = '&F_MOBILE_NUM_COUNT='+voiceInfo.voiceList.length.toString()+'&F_MOBILE_NUM='+mobileList+'&F_CALL_TYPE=1&NAME='+nameList+'&DEPT_NM='+deptList+'&ARANK='+arankList+'&MAX=9';
    logger.info(makeVoiceInfo2);

    var packetBody = makeVoiceInfo1 + makeVoiceInfo2;

    logger.info(packetBody);

    return packetBody;
}

function makeBodyDataOfSTB(data) {

    var stbInfo = data;

    var makeSTBInfo1 = 'CTN_DEVICE='+stbInfo.CTN_DEVICE+'&MOBILE_NUM='+stbInfo.MOBILE_NUM;

    var makeSTBInfo2;
    if (typeof stbInfo.stbList != 'undefined') {

        var macList = nameList = deptList = '';
        for (var i = 0; i < stbInfo.stbList.length; i++) {
            var macList = macList + stbInfo.stbList[i].mac + ',';
        }
        macList = macList.substring(0, macList.length - 1);

        for (var i = 0; i < stbInfo.stbList.length; i++) {
            var nameList = nameList + stbInfo.stbList[i].name + ',';
        }
        nameList = nameList.substring(0, nameList.length - 1);

        for (var i = 0; i < stbInfo.stbList.length; i++) {
            var deptList = deptList + stbInfo.stbList[i].dept + ',';
        }
        deptList = deptList.substring(0, deptList.length - 1);

        makeSTBInfo2 = '&STB_COUNT=' + stbInfo.stbList.length.toString() + '&STB_MAC_ADDR=' + macList + '&STB_NM=' + nameList + '&DEPT_NM=' + deptList + '&MAX=9';
    } else {
        makeSTBInfo2 = '&STB_COUNT=0';
    }

    var packetBody = makeSTBInfo1 + makeSTBInfo2;

    logger.info(packetBody);

    return packetBody;
}

//#2 Start [2015.9.10] by ywhan
function makeBodyDataOfMobile(data) {
	
    var mobileInfo = data;

    var makeMobileInfo1 = 'CTN_DEVICE='+mobileInfo.CTN_DEVICE+'&MOBILE_NUM='+mobileInfo.MOBILE_NUM;
    logger.info(makeMobileInfo1);

	var makeMobileInfo2;
	
    if (typeof mobileInfo.mobileList != 'undefined') {

	    var ctnList = nameList = deptList = arankList = indexList = '';
	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {
	        ctnList += mobileInfo.mobileList[i].ctn + ',';
	    }
	    ctnList = ctnList.substring(0 ,ctnList.length-1);
	
	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {
	        nameList += mobileInfo.mobileList[i].name + ',';
	    }
	    nameList = nameList.substring(0 ,nameList.length-1);
	
	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {
	        deptList += mobileInfo.mobileList[i].dept + ',';
	    }
	    deptList = deptList.substring(0 ,deptList.length-1);

	    for (var i = 0; i < mobileInfo.mobileList.length; i++) {
	    	indexList += mobileInfo.mobileList[i].index + ',';
	    }
	    indexList = indexList.substring(0 ,indexList.length-1);

    	makeMobileInfo2 = '&VIEW_CNT='+mobileInfo.mobileList.length.toString()+'&VIEW_TYPE='+mobileInfo.VIEW_TYPE+'&VIEW_NUM='+ctnList+'&VIEW_INDEX='+indexList+'&VIEW_NM='+nameList+'&VIEW_DEPT_NM='+deptList;
    	
    } else {
    	
        makeMobileInfo2 = '&VIEW_CNT=0';
    }

    var packetBody = makeMobileInfo1 + makeMobileInfo2;

    logger.info(packetBody);

    return packetBody;	
};
//#2 End

function makeBodyDataOfStream(data) {

    var streamInfo = data;
    
    var makeStreamInfo1 = 'CTN_DEVICE=' + streamInfo.CTN_DEVICE + '&MOBILE_NUM='   + streamInfo.MOBILE_NUM;
    var makeStreamInfo2 = '&VIEW_TYPE=' + streamInfo.VIEW_TYPE  + '&VIEW_NUM='     + streamInfo.VIEW_NUM     + '&VIEW_INDEX='      + streamInfo.VIEW_INDEX + '&PLAY_INDEX=' + streamInfo.PLAY_INDEX;
    var makeStreamInfo3 = '&FRAME_CNT=' + streamInfo.FRAME_CNT  + '&BROWSER_NAME=' + streamInfo.BROWSER_NAME + '&BROWSER_VERSION=' + streamInfo.BROWSER_VERSION;
    var makeStreamInfo4 = '&CONTINUE=';//  + streamInfo.CONTINUE   + '&CPU_INFO='     + streamInfo.CPU_INFO     + '&MEM_INFO='  + streamInfo.MEM_INFO;
    //var makeStreamInfo5 = '&CPU_FIND='  + streamInfo.CPU_FIND   + '&MEM_FIND='     + streamInfo.MEM_FIND;

    var packetBody = makeStreamInfo1 + makeStreamInfo2 + makeStreamInfo3 + makeStreamInfo4;// + makeStreamInfo5; 

    logger.info(packetBody);
	
	return packetBody;
}

function makeBodyDataOfAbnormal(data) {

    var streamInfo = data;
    
    var makeStreamInfo1 = 'CTN_DEVICE=' + streamInfo.CTN_DEVICE + '&MOBILE_NUM=' + streamInfo.MOBILE_NUM;
    var makeStreamInfo2 = '&VIEW_TYPE=' + streamInfo.VIEW_TYPE  + '&VIEW_NUM='   + streamInfo.VIEW_NUM  + '&VIEW_INDEX=' + streamInfo.VIEW_INDEX;
    var makeStreamInfo3 = '&FAIL_CODE=' + streamInfo.FAIL_CODE  + '&FAIL_TYPE='  + streamInfo.FAIL_TYPE + '&FAIL_REASON=' + streamInfo.FAIL_REASON;

    var packetBody = makeStreamInfo1 + makeStreamInfo2 + makeStreamInfo3; 

    logger.info(packetBody);

	return packetBody;
}

function makeBodyDataPlayRTSP(data) {
    var packetBody;
    packetBody = 'MOBILE_NUM=' + data.MOBILE_NUM + '&INSERT_DATE=' + data.INSERT_DATE + '&ADMIN_ID=' + data.ADMIN_ID;
    packetBody += '&FILE_NM=' + data.FILE_NM + '&RANGE=' + data.RANGE + '&PLAY_MESSAGE=' + data.PLAY_MESSAGE;
    return packetBody;
}

function makeBodyDataPauseRTSP(data) {
    var packetBody;
    packetBody = 'MOBILE_NUM=' + data.MOBILE_NUM + '&INSERT_DATE=' + data.INSERT_DATE + '&ADMIN_ID=' + data.ADMIN_ID;
    packetBody += '&FILE_NM=' + data.FILE_NM + '&RANGE=' + data.RANGE;
    return packetBody;
}

//#1 Start [2015.7.15] by ywhan
function makeJsonTypeAddVoice(data) {

    var voiceArray = new Array();

    var voiceInfo = new Object();
    voiceInfo.name = data.NM;
    voiceInfo.ctn = data.CTN;
    voiceInfo.dept = data.DEPT_NM;
    voiceInfo.arank = data.ARANK;

    voiceArray.push(voiceInfo);

    var voiceInfoList = new Object();

    voiceInfoList.COMMAND = 'D200';
    voiceInfoList.INSERT_DATE = data.INSERT_DATE;
    voiceInfoList.CTN_DEVICE = data.CTN_DEVICE;
    voiceInfoList.MOBILE_NUM = data.M_MOBILE_NUM;
    voiceInfoList.voiceList = voiceArray;

    return voiceInfoList;
}

//#1 Start [2015.07.14] by ywhan
function makeJsonTypeAddSTB(data) {

    var stbArray = new Array();

    var stbInfo = new Object();
    stbInfo.mac = data.STB_MAC_ADDR;
    stbInfo.name = data.STB_NM;
    stbInfo.dept = data.STB_DEPT_NM;

    logger.info('makeJsonTypeAddSTB : mac  :', data.STB_MAC_ADDR);
    logger.info('makeJsonTypeAddSTB : name :', data.STB_NM);
    logger.info('makeJsonTypeAddSTB : dept :', data.STB_DEPT_NM);

    stbArray.push(stbInfo);

    var stbInfoList = new Object();

    stbInfoList.COMMAND = 'D300';
    stbInfoList.INSERT_DATE = data.INSERT_DATE;
    stbInfoList.CTN_DEVICE = data.CTN_DEVICE;
    stbInfoList.MOBILE_NUM = data.MOBILE_NUM;
    stbInfoList.stbList = stbArray;

    return stbInfoList;
}

function makeBodyDataNotice(data) {    
    return "SEQ=" + data.SEQ + "&CRUD=" + data.CRUD;
}

function makeJsonTypeFullUse(data) {

    var stbInfoList = new Object();

    //stbInfoList.COMMAND = 'D300';
    //stbInfoList.COMMAND = command;
    stbInfoList.INSERT_DATE = data.INSERT_DATE;
    stbInfoList.CTN_DEVICE = data.CTN_DEVICE;
    stbInfoList.MOBILE_NUM = data.MOBILE_NUM;

    return stbInfoList;
}

function getCommandValue(type, data) {

    if (type == 1 || type == 3) {
        return data.COMMAND;
    } else if (typeof type == 'string') {
        return type;
    } else{
        command[type];
    }
}
//#1 End

exports.parsingBodyData = parsingBodyData;
exports.makeData = makeData;
exports.makeJsonTypeAddVoice = makeJsonTypeAddVoice;
exports.makeJsonTypeAddSTB = makeJsonTypeAddSTB;
exports.makeJsonTypeFullUse = makeJsonTypeFullUse;
exports.makeResponseData = makeResponseData;
exports.makeBodyDataOfStream = makeBodyDataOfStream;
exports.makeBodyDataOfAbnormal = makeBodyDataOfAbnormal;
