var jwtVerify = require('../token/verify.js');

module.exports  = function(token, secretOrKey, options, callback) {
    return jwtVerify(token, secretOrKey, options, callback);
};
