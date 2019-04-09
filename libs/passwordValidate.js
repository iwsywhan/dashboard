module.exports = function (req, res, next) {   
    var check = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,20}$/;
    var consecutiveNumberCheck = /(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)+/ig;
    var pw = req.param('new_pw');
    var inputData = {
        id: req.param('id'),
        tel: req.param('tel')
    };
    var bool = false;
    
    if (pw.length < 8 || pw.length > 20) {
        bool = true;
        res.send(400, '비밀번호는 8자리 이상 20자리 미만입니다.');
    } else if (!check.test(pw)) {
        bool = true;
        res.send(400, '비밀번호는 특수문자+문자+숫자의 조합으로 되어야 합니다.');
    } else if (pw.search(consecutiveNumberCheck) > -1) {
        bool = true;
        res.send(400, '비밀번호에 일련번호가 미포함되어야 합니다.');
    } else {
        for (var key in inputData) {
            if (pw.search(inputData[key]) > -1) {
                bool = true;
                res.send(400, '비밀번호에 회원정보가 미포함되어야 합니다.');
            }
        }
    }
    

    if (!bool) {
        next();
    }
};