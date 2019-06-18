/**
 * @author iwsywhan
 */
var i18n = require("i18next");

(function(exports) {

	exports.columnNameToValue = function(column) {
		
		if (typeof column != "string") {
			return '';
		}
		
		column = column.toUpperCase();
		
		var ret;
		switch(column) {
			case 'GUBUN':
				ret = i18n.t('mng_dept.th01');
				break;
			case 'CODE' :
				ret = i18n.t('mng_dept.th02');
				break;
			case 'CODE_NM' :
				ret = i18n.t('mng_dept.th03');
				break;
			//case 'DEPT_NM' :
			case 'STB_DEPT_NM' :
			case 'CUST_DEPT_NM' :
			case 'DEV_DEPT_NM' :
				ret = i18n.t('service_status.th17');
				break;
			case 'CUST_NM' :
				ret = i18n.t('common.fname');
				break;
			case 'NM' :
			case 'ADMIN_NM' :
			case 'DEV_NM' :
				ret = i18n.t('common.fname');
				break;
			case 'CUST_CTN' :
			case 'P_CUST_CTN':
				ret = i18n.t('report.th01');
				break;
			case 'CTL_TEL_NUM' :
			case 'CTN' :
			case 'ADMIN_MOBILE_NUM':
				ret = i18n.t('report_view.th02');
				break;
			case 'RECV_CTN' :
				ret = i18n.t('value.RECV_CNT');
				break;			
			case 'SUBJECT' :
				ret = i18n.t('work_detail.th02');
				break;
			case 'INSERT_DATE' :
			case 'CREATE_DATE' :
			case 'P_INSERT_DATE' :
			case 'SVC_TIME_ST' :
				ret = i18n.t('report.th04');
				break;
			case 'UPDATE_DATE' :
			case 'SVC_TIME_ED' :
				ret = i18n.t('report.th05');
				break;
			case 'CTN_CNT' :
				ret = 'Tel';
				break;
			case 'STB_CNT' :
				ret = 'STB';
				break;
			case 'MOBILE_CNT' :
				ret = 'Mob';
				break;
			case 'PC_CNT' :
				ret = 'PC';
				break;
			case 'UPLOAD_FILE_NM' :
			case 'UPLOAD_FILE' :
				ret = i18n.t('report.th06');
				break;
			case 'STB_STATUS' :
			case 'STATUS' :
			case 'LOGIN_STATUS' :
				ret = i18n.t('report.th07');
				break;
			case 'CTL_NM' :
				ret = i18n.t('mng_control.title01');
				break;
			case 'CODE_01' :
			case 'STB_DEPT_CODE_01' :
			case 'DEPT_CODE_01' :
			case 'DEPT_NM' :
				ret = i18n.t('mng_control.th03');
				break;
			case 'CODE_02' :
			case 'STB_DEPT_CODE_02' :
			case 'DEPT_CODE_02' :
			case 'DEPT_NM2' :
				ret = i18n.t('mng_control.th04');
				break;
			case 'CODE_03' :
			case 'STB_DEPT_CODE_03' :
			case 'DEPT_CODE_03' :
			case 'DEPT_NM3' :
				ret = i18n.t('mng_control.th05');
				break;
			case 'USER_YN' :
				ret = i18n.t('mng_control.useYn');
				break;
			case 'CTL_ADMIN_NM' :
				ret = i18n.t('mng_control.th10');
				break;
			case 'SEQ' :
			case 'C_KEY' :
				ret = i18n.t('mng_control.th09');
				break;
			case 'C_VALUE' :
				ret = i18n.t('value.C_VALUE');
				break;
			case 'C_NAME' :
				ret = i18n.t('value.C_NAME');
				break;
			case 'ARANK' :
				ret = i18n.t('mng_user_list.th02');
				break;
			case 'STB_NM' :
				ret = i18n.t('mng_stb.th01');
				break;
			case 'STB_LOCATION' :
				ret = i18n.t('mng_stb.th02');
				break;
			case 'ADMIN_ID' :
				ret = i18n.t('common.id');
				break;
			case 'AGENT' :
				ret = i18n.t('login_hst.th04');
				break;
			case 'IP_ADDR' :
			case 'SVC_IP' :
				ret = i18n.t('login_hst.th03');
				break;
			case 'CONNECT_DATE' :
				ret = i18n.t('login_hst.th01');
				break;
			case 'SEND_DATE' :
			case 'REQUEST_TIME' :
				ret = i18n.t('value.REQUEST.TIME');
				break;
			case 'RESPONSE_TIME' :
				ret = i18n.t('value.RESPONSE_TIME');
				break;
			case 'ORGADDR' :
				ret = i18n.t('value.ORGADDR');
				break;
			case 'DESTADDR' :
				ret = i18n.t('report_view.th26');
				break;
			case 'TEXT' :
				ret = i18n.t('report_view.th31');
				break;	
			case 'ENDCODE' :
				ret = i18n.t('report_view.th32');
				break;
			case 'TRI_CNT':
				ret = i18n.t('stats.value1');
				break;			
			case 'SUC_CNT':
				ret = i18n.t('stats.value2');
				break;			
			case 'ERR_CNT':
				ret = i18n.t('stats.value3');
				break;
			case 'DEV_MODEL':
			case 'MODEL':
				ret = i18n.t('service_err.th05');
				break;
			case 'DEV_OS':
			case 'VERSION':
				ret = i18n.t('service_err.th06');
				break;
			case 'STB_MAC_ADDR':
				ret = 'STB MAC ADDR';
				break;
			case 'STB_MODEL':
				ret = i18n.t('value.STB_MODEL');
				break;
			case 'CTN_NM':
				ret = i18n.t('value.CTN_NM');
				break;
			case 'CTN_OS':
				ret = i18n.t('value.CTN_OS');
				break;
			case 'DEFECT_CODE':	
				ret = i18n.t('report_view.th10');
				break;
			case 'REASON':	
				ret = i18n.t('report_view.th11');
				break;
			case 'VIEW_CNT':
				ret = 'MOBILE';
				break;
			case 'SUM_TRIAL':
				ret = i18n.t('value.SUM_TRIAL');
				break;
			case 'SUM_SUC':
				ret = i18n.t('value.SUM_TRIAL');
				break;
			case 'SUM_GCM':
				ret = i18n.t('stats.th03');
				break;
			case 'DATE':
				ret = i18n.t('service_err.th01');
				break;
			case 'TM':
				ret = i18n.t('service_err.th01');
				break;
			case 'TOSS_TYPE' :
				ret = i18n.t('common.interlinkType');
				break;
			case 'LCS_FLMGNO' :
				ret = i18n.t('common.LCS_num');
				break;
			case 'LCS_FLMGDV_CD' :
				ret = i18n.t('common.LCS_code');
				break;
			case 'CONS_NO' :
				ret = i18n.t('common.construction.num');
				break;
			case 'CONS_REQNO' :
				ret = i18n.t('common.const_reqnum');
				break;
			case 'PRPSCOBYPTY_ID' :
				ret = i18n.t('common.rel_Id');
				break;
			case 'DEL_PRPSCOBYPTY_ID' :
				ret = i18n.t('common.del_Id');
				break;
			case 'LCS_USE_BIZIDNTNO' :
				ret = i18n.t('common.workNum');
				break;
			case 'DEFAULT_DEVICE' :
				ret = i18n.t('mng_control.th08');
				break;
			case 'ADMIN_LV' :
				ret = i18n.t('admin_confirm.th01');	
				break;
			case 'LOGIN_INSERT_DATE' :
				ret = i18n.t('login_hst.th01');
				break;
			case 'LOGIN_UPDATE_DATE' :
				ret = i18n.t('login_hst.th02');
				break;
			case 'PUSH_TYPE' : 
				ret = 'PUSH Type';
				break;
			case 'PUSH_TITLE' :
				ret = 'PUSH Title';
				break;
			case 'PUSH_MESSAGE' :
				ret = 'PUSH Message';
				break;
			case 'RECEIVE_TIME' :
				ret = i18n.t("common.terminal")+" "+ i18n.t("value.RESPONSE_TIME");
				break;
			case 'GCM_RESULT' :
				ret = i18n.t('stats.th08');
				break;			
			case 'GCM_ERROR' :
			ret = i18n.t('stats.th09');
				break;
			case 'PUSH_STATUS' :
				ret = 'PUSH' + i18n.t('login_hst.th05');
				break;
			case 'RESULT' :
				ret = i18n.t('value.ENDCODE');
				break;
			case 'LPMS_CLASS' :
				ret = i18n.t('LPMS.class');
				break;
			case 'LPMS_REQNO' :
				ret = i18n.t('LPMS.reqno');
				break;
			case 'LPMS_FACTORY' :
				ret = i18n.t('LPMS.factory');
				break;
			case 'LPMS_TEAM' :
				ret = i18n.t('LPMS.team');
				break;
			case 'LPMS_GUBUN' :
				ret = i18n.t('LPMS.gubun');
				break;
			case 'LPMS_CONTENT' :
				ret = i18n.t('LPMS.content');
				break;
			case 'LPMS_COMPANY' :
				ret = i18n.t('LPMS.company');
				break;
			case 'WORKER_NAME' :
				ret = i18n.t('LPMS.name');
				break;
			case 'BLOCK_FLAG' :
				ret = i18n.t('LPMS.block_flag');
				break;
			case 'TOT_BRIGHT_LVL' :
				ret = i18n.t('LPMS.bright_lv');
				break;
			case 'TOT_BRIGHT_RATE' :
				ret = i18n.t('LPMS.bright_rate');
				break;
			case 'TOT_DIFF_LVL' :
				ret = i18n.t('LPMS.diff');
				break;
			case 'TOT_DIFF_RATE' :
				ret = i18n.t('LPMS.diff_rate');
				break;
			case 'DEV_KEY' :
				ret = i18n.t('conn_mng.th02');
				break;
			case 'DEV_KEY' :
				ret = i18n.t('conn_mng.th02');
				break;
			default:
				return column;			
		}
		
		return ret;
	}

	exports.fn_strlen = function(str) { 
		var len = 0;
		for(var i=0;i<str.length;i++) {
			len += (str.charCodeAt(i) > 128) ? 2 : 1;
		}
		return len;
	}

	exports.getCodeToValue = function(column, code) {
		
		switch(column) {
			case 'STATUS' :				
					if (code == 1)
						return i18n.t('value.status.1');
					else if (code == 2)
						return i18n.t('value.status.2');
					else if (code == 3)
						return i18n.t('value.status.3');
					else if (code == 9)
						return i18n.t('value.status.9');
					else
						return i18n.t('value.status.0');
			case 'ADMIN_LV' :
					if (code == "슈퍼관리자")
						return i18n.t('top.auth1');
					else if (code == "제어관리자")
						return i18n.t('top.auth2');
					else if (code == "일반관리자")
						return i18n.t('top.auth3');
			case 'STB_STATUS' :
					if (code == "접속가능")
						return i18n.t('mng_control.th14');
					else if (code == "접속불가")
						return i18n.t('mng_control.th15');
			case 'LOGIN_STATUS'	:
					if (code == "로그인")
						return i18n.t('login_hst.th06');
					else if (code == "로그아웃")
						return i18n.t('login_hst.th07');
			case 'USER_YN' :
					if (code == "사용가능")
						return i18n.t('mng_control.useY')
					else if (code == "사용불가")
						return i18n.t('mng_control.useN')

			case 'TOSS_TYPE' :
					if (code == 1)
						return i18n.t('common.sendHistory');
					else if (code == 2)
						return i18n.t('common.delHistory');
					else
						return '';
			case 'RESULT' :
					if (code == 'Y')
						return i18n.t('value.SUM_SUC');
					else if (code == 'N')
						return i18n.t('value.C_FAIL');
					else
						return i18n.t('report_view.noResponse');
			case 'PUSH_STATUS' :
					if (code == 1)
						return i18n.t('utilLib.reception');
					else if (code == 2)
						return i18n.t('utilLib.close');
					else
						return i18n.t('utilLib.notreception');
			case 'CANONICAL_ID' :
					if (code == 0)
						return i18n.t('utilLib.notoccur');
					else if (code == 1)
						return i18n.t('utilLib.occur');
					else
						return '';
			case 'PUSH_TYPE' :
					if (code == 1)
						return 'VIEW';
					else if (code == 2)
						return i18n.t('notice.title01');
			case 'GCM_RESULT' :
				if (code == 1)
					return i18n.t('value.SUM_SUC');
				else if (code == 2)
					return i18n.t('value.C_FAIL');
				else
					return ''; 
			case 'TOT_BRIGHT_LVL' :
				if (code == 0)
					return i18n.t('opening.normality');
				else if (code == 1)
					return i18n.t('common.dark');
				else if(code == 2)
					return i18n.t('common.bright')
				else	
					return ''; 
			case 'TOT_BRIGHT_RATE' :
				var value = code.split('.');
				return value[0]; 
			case 'TOT_DIFF_LVL' :
				if (code == 0)
					return i18n.t('common.none');
				else if (code == 1)
					return i18n.t('common.exist');
				else	
					return ''; 
			case 'TOT_DIFF_RATE' :
				var value = code.split('.');
				value[0]
				return value[0]; 
			default:
				return code.toString();
		}
	}
})(typeof exports === 'undefined'? this['toValue']={}: exports);

//exports.columnNameToValue = columnNameToValue;
//exports.fn_strlen = fn_strlen;
//exports.getCodeToValue = getCodeToValue;	
	
