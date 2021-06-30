var express = require('express');
var db = require('../database.js')
var router = express.Router();

router.post('/',(req,res)=>{
    res.send(req.body.key)
})

router.get('/',(req,res)=>{
    res.send(req.query.value)
})

router.get('/database',(req,res)=>{
    res.send(req.query.value)
})

router.post('/database',(req,res)=>{
    res.send(req.query.value)
})

router.delete('/database',(req,res)=>{
    res.send(req.query.value)
})

router.put('/database',(req,res)=>{
    res.send(req.query.value)
})

module.exports = router;
