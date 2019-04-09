module.exports = LiveCam2UTM;

function LiveCam2UTM (command, packet) {
    this._command = command;
    this._utm = packet;
}

LiveCam2UTM.prototype.toLiveCam = function () {
    var retObject = {};
    switch (this._command) {        
        case 'B207' :   // 영상 시작
            retObject.CTN_DEVICE = '';
            retObject.DEV_TYPE = '4';
            retObject.MOBILE_NUM = this._utm.D_ID;
            switch (this._utm.D_RESOLUTION) {
                case '1' :  // SD
                    retObject.V_WIDTH = '640';
                    retObject.V_HEIGHT = '480';
                    break
                case '2' :  // HD
                    retObject.V_WIDTH = '1280';
                    retObject.V_HEIGHT = '900';
                    break
                case '3' :  // FHD
                    retObject.V_WIDTH = '1920';
                    retObject.V_HEIGHT = '1080';
                    break
                default:
                    retObject.V_WIDTH = '640';
                    retObject.V_HEIGHT = '480';
                    break;
            }
            break;
        case 'B903' :   // 영상 종료
            retObject.DEV_TYPE = '4';       // 4: drone
            retObject.MOBILE_NUM = this._utm.D_ID;
            retObject.CTN_DEVICE = '';
            retObject.SYS_TYPE = '2';       // 1: 직캠, 2: UTM
            break;
        case 'B170' :   // 스탭샷 촬영 시작
            retObject.DEV_TYPE = '4';       // 4: drone
            retObject.MOBILE_NUM = this._utm.D_ID;
            retObject.CTN_DEVICE = '';
            retObject.SYS_TYPE = '2';       // 1: 직캠, 2: UTM
            retObject.IDENTIFICATION = new Date().getTime();
            retObject.SHOT_COUNT = this._utm.SHOT_COUNT;
            retObject.SHOT_PERIOD = this._utm.SHOT_PERIOD;
            retObject.RESET_FLAG = this._utm.RESET_FLAG;
            retObject.JUST_UPLOAD_FLAG = this._utm.RT_UPLOAD_FLAG;
            break;            
        case 'B171' :   // 파일 업로드 시작
            retObject.DEV_TYPE = '4';       // 4: drone
            retObject.MOBILE_NUM = this._utm.D_ID;
            retObject.CTN_DEVICE = '';
            retObject.SYS_TYPE = '2';       // 1: 직캠, 2: UTM
            retObject.IDENTIFICATION = new Date().getTime();
            retObject.UPLOAD_TYPE = this._utm.UPLOAD_TYPE;
            retObject.UPLOAD_DELETE_FLAG = this._utm.UPLOAD_DELETE;
            retObject.UPLOAD_TODAY_FLAG = this._utm.UPLOAD_TODAY;
            break;
        // case 'B605' :   // 파일 업로드 이어 보내기
        //     break;
        // case 'B306' :   // 파일 업로드 취소
        //     break;
    }

    return retObject;
}
