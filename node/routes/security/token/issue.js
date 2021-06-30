const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../../../config/server.json')
const router = express.Router();

// 토큰을 발급하는 라우터
router.post('/test', async (req, res) => {
  try {
    id = req.body.id
    nick = req.body.nickname

    // jwt.sign() 메소드: 토큰 발급
    const token = jwt.sign({
      id,
      nick,
    }, config.JWT_SECRET, {
      expiresIn: '3s', // 1분
      issuer: 'issuer',
    });

    return res.json({
      code: 200,
      message: 'Token Issued',
      token,
    });
  }

  catch (error) {
    console.error(error);
    return res.status(500).json({
      code: 500,
      message: 'Internal Server Error',
    });
  }
});


module.exports = router;