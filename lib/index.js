'use strict';

module.exports = {
    Strategy: require('./passport-strategy/strategy'),
    ExtractJwt : require('./passport-strategy/extract_jwt.js'),
    Sign: require('./token/sign'),
    Decode: require('./token/decode'),
    Verify: require('./token/verify')
};
