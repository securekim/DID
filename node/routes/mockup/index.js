var express = require('express');
var router = express.Router();

/* GET mockup page. */
router.get('/', function(req, res, next) {
  res.sendFile("index.html")
});

module.exports = router;
