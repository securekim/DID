const jwt = require('jsonwebtoken');
const config = require("../../../config/server.json")
const express = require('express');
const router = express.Router();


router.get('/test', async (req, res) => {
  _req = verifyTokenTest(req,res)
  res.json(_req.decoded);
});


function verifyTokenTest(req, res){
  // 인증 완료
  try {
    // 요청 헤더에 저장된 토큰(req.headers.authorization)과 비밀키를 사용하여 토큰 반환
    console.log("Token : "+req.headers.authorization)
    req.decoded = jwt.verify(req.headers.authorization, config.JWT_SECRET);
    return req;
  }

  // 인증 실패
  catch (error) {
    // 유효기간이 초과된 경우
    if (error.name === 'TokenExpiredError') {
      return res.status(419).json({
        code: 419,
        message: '토큰이 만료되었습니다.'
      });
    }

    // 토큰의 비밀키가 일치하지 않는 경우
    return res.status(401).json({
      code: 401,
      message: '유효하지 않은 토큰입니다.'
    });
  }
}

module.exports = router;