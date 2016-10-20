const crypto = require('crypto');
const algorithm = 'aes-256-ctr';

module.exports = {
    encrypt: function (text, secret) {
        var cipher = crypto.createCipher(algorithm, secret);
        var crypted = cipher.update(text, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    },

    decrypt: function (text, secret) {
        var decipher = crypto.createDecipher(algorithm, secret)
        var dec = decipher.update(text, 'hex', 'utf8')
        dec += decipher.final('utf8');
        return dec;
    }
}
