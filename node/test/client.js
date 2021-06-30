
var request = require('request');
var io = require('socket.io-client');
var config = require("../config/server.json")
var tool = require("../utils/tool")

const url = 'http://127.0.0.1:'+config.port

async function post(url){
    return new Promise(function(resolve, reject) {
        request({
            url: url,
            method: "POST",
            headers: {"content-type": "application/json",},
            body: JSON.stringify({"key":"myValue"})
            }, function (err, res, resbody) {
                if(err){ reject(err)} else {
                    console.log('POST :', res.statusCode); 
                    resolve(resbody);
                }
        });
})}

async function get(url){
        return new Promise(function(resolve, reject) {
            request(url+"?value=myValue", function (err, res, resbody) {
                if(err){ reject(err) } else {
                    console.log('GET :', res.statusCode); 
                    resolve(resbody) 
        }});
})}

async function websocket(url){
    var socket = io(url);
    socket.emit("joinRoom", { roomName: "testRoom" });
    socket.emit("reqMsg", { comment: "first Reuqest" });
    socket.on('connect', function() {
        console.log("connected")
    });
    socket.on('recMsg', function (data) {
        console.log(data.comment)
        socket.disconnect();
    });
}

async function jwtIssue(url){
    return new Promise(function(resolve, reject) {
    request({
        url: url+"/security/token/issue/test",
        method: "POST",
        headers: {"content-type": "application/json",},
        body: JSON.stringify({"id":"securekim", "nickname":"SCK"})
        }, function (err, res, resbody) {
            if(err){ reject(err)} else {
                console.log('POST :', res.statusCode); 
                resolve(resbody);
            }
    });
})}


async function jwtVerify(url, token){
        const options = {
            method : "GET",
            url : url+"/security/token/verify/test",
            headers: {authorization : token}
        }
        return new Promise(function(resolve, reject) {
            request(options, function (err, res, resbody) {
                if(err){ reject(err) } else {
                    console.log('GET :', res.statusCode); 
                    resolve(resbody) 
        }});
})}

async function main(){
        console.log("[TEST 1] KEY - VALUE PARSING TEST - GET")
        ret = await get(url+"/test");
        console.log(ret);
        console.log("[TEST 2] KEY - VALUE PARSING TEST - POST")
        ret = await post(url+"/test");
        console.log(ret);
        console.log("[TEST 3] Socket.io TEST")
        await websocket(url);
        console.log("[TEST 4] json web token TEST")
        ret = await jwtIssue(url)
        token = JSON.parse(ret).token
        console.log(token)
        console.log("[TEST 4-1] json web token TEST - Verify Pass")
        ret = await jwtVerify(url,token)
        console.log(ret)
        await tool._sleep(4000);
        console.log("[TEST 4-1] json web token TEST - Verify Fail")
        ret = await jwtVerify(url,token)
        console.log(ret)
}
main();
    