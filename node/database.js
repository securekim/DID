const config = require('./config/database.json')
const uri = config.uri; //'mongodb+srv://coinInvestor:coinInvestor@cluster0.nhoos.mongodb.net/coinInvestor?retryWrites=true&w=majority'

var mongoose = require('mongoose');
const db = mongoose.connection

async function init(){
return new Promise((resolve, reject)=>{
    mongoose.connect(uri, {
        useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
    }).then(() => resolve())
        .catch(error => reject(error))
    })
}

// Set up database event handlers:
db.on('error', function(err) { console.log("Unable to connect to database.  Error: " + err) } )
db.once('open', function() { 
    console.log('Mongoose database connection established.')
    // Load common properties from database:
    // ... [snip]
})
db.on('disconnected', function() {
    console.log('MongoDB disconnected.  Attempting to reconnect...')
})
db.on('reconnected', function() { console.log('Mongoose reconnected.')})


//////////////////////////////// SCHEMA //////////////////////////////////

var sampleSchema = new mongoose.Schema({
    key: mongoose.Schema.Types.Mixed, // key
	value: mongoose.Schema.Types.Mixed, // value
})

var sampleModel = mongoose.model('sample', sampleSchema);


function get(){

}

async function post(key,value){
    timestamp = new Date().toLocaleString('en', {timeZone: "Asia/Seoul"})
    var instance = new sampleModel({
        timestamp : timestamp,
        key : key,
        value : value
    });
    ret = await instance.save()
    return ret;
}

function put(){

}

function del(){

}

module.exports = {
    init,
    get,
    post,
    put,
    del
}