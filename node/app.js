var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var fileTool = require("./utils/tool")
var http = require('http');
var config = require('./config/server.json')
            
var app = express();


/////////////////////////////////////////////////////////////// APP ////////////////////////////////////////////////////////////

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//////// Add All Routes Automatically //////////

// 원래는 하나씩 수동으로 해야됨 //

var routes = fileTool.ls(__dirname + '/routes')

for(var i in routes){
  routePath = routes[i].fullPath.split("routes")[1].split(".")[0]
  console.log("[AutoRoutes] app.use('"+routePath+"', require('"+routes[i].fullPath+"'))")
  app.use(routePath, require(routes[i].fullPath));
}

//////////////////////////////////////////////////

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

////////////////////////////////////////////////////////////////////// WEB SERVER /////////////////////////////////////////////////////////////

 app.set('port', config.port);
 
 /**
  * Create HTTP server.
  */
 
 var server = http.createServer(app);

 server.listen(config.port);
 server.on('error', onError);
 server.on('listening', onListening);
 
 function onError(error) {
   if (error.syscall !== 'listen') {
     throw error;
   }
 
   switch (error.code) {
     case 'EACCES':
       console.error(config.port + ' requires elevated privileges');
       process.exit(1);
     case 'EADDRINUSE':
       console.error(config.port + ' is already in use');
       process.exit(1);
     default:
       throw error;
   }
 }
 
 function onListening() {
   var addr = server.address();
   var bind = typeof addr === 'string'
     ? 'pipe ' + addr
     : 'port ' + addr.port;
    console.log("Listen : "+addr.address+":"+bind)
 }
 
//////////////////////////////////////////////////////////////// WEB SOCKET ////////////////////////////////////////////////////// 

 
var io = require('socket.io')(server);
var roomName;

io.on('connection', function (socket) {
    console.log('connect');
    var instanceId = socket.id;

    socket.on('joinRoom',function (data) {
        console.log(data);
        socket.join(data.roomName);
        roomName = data.roomName;
    });

    socket.on('reqMsg', function (data) {
        console.log(data);
        io.sockets.in(roomName).emit('recMsg', {comment: instanceId + " : " + data.comment+'\n'});
    })
});
