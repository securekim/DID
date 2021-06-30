
var fs = require('fs')
var ls = function(dir) {
    var results = [];
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) { 
            /* Recurse into a subdirectory */
            results = results.concat(ls(file));
        } else { 
            /* Is a file */
            file_type = file.split(".").pop();
            file_name = file.split(/(\\|\/)/g).pop();
            file = file.replace(/\\/gi,"/"); // for windows
            results.push({"fullPath":file, "type":file_type, "filename":file_name});
        }
    });
    return results;
  }

function startInterval(callback, ms) { callback(); return setInterval(callback, ms); }

const _sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay)); // awiat sleep(ms)

module.exports = {
    ls,
    _sleep,
    startInterval
}