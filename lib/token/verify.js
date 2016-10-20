const decode            = require('./decode');
const jws               = require('jws');
const ms                = require('ms');
const xtend             = require('xtend');
const crypt             = require('../crypt');

module.exports = function (jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (!options) {
    options = {};
  }

  //clone this object since we are going to mutate it.
  options = xtend(options);
  var done;

  if (callback) {
    done = function() {
      var args = Array.prototype.slice.call(arguments, 0);
      return process.nextTick(function() {
        callback.apply(null, args);
      });
    };
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  if(options.isEncrypted != null && options.isEncrypted) {
    try {
      jwtString = crypt.decrypt(jwtString, secretOrPublicKey);
    } catch (e) {
      return done(new Error('Invalid Token.'));
    }
  }

  if (!jwtString){
    return done(new Error('jwt must be provided'));
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new Error('jwt malformed'));
  }

  var hasSignature = parts[2].trim() !== '';

  if (!hasSignature && secretOrPublicKey){
    return done(new Error('jwt signature is required'));
  }

  if (hasSignature && !secretOrPublicKey) {
    return done(new Error('secret or public key must be provided'));
  }

  if (!hasSignature && !options.algorithms) {
    options.algorithms = ['none'];
  }

  if (!options.algorithms) {
    options.algorithms = ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
    ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY') ?
    [ 'RS256','RS384','RS512','ES256','ES384','ES512' ] :
    ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY') ?
    [ 'RS256','RS384','RS512' ] :
    [ 'HS256','HS384','HS512' ];

  }

  var decodedToken;
  try {
    decodedToken = jws.decode(jwtString);
  } catch(err) {
    return done(new Error('invalid token'));
  }

  if (!decodedToken) {
    return done(new Error('invalid token'));
  }

  var header = decodedToken.header;

  if (!~options.algorithms.indexOf(header.alg)) {
    return done(new Error('invalid algorithm'));
  }

  var valid;

  try {
    valid = jws.verify(jwtString, header.alg, secretOrPublicKey);
  } catch (e) {
    return done(e);
  }

  if (!valid)
  return done(new Error('invalid signature'));

  var payload;

  try {
    payload = decode(jwtString);
  } catch(err) {
    return done(err);
  }

  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      return done(new Error('invalid nbf value'));
    }
    if (payload.nbf > Math.floor(Date.now() / 1000) + (options.clockTolerance || 0)) {
      return done(new Error('jwt not active', new Date(payload.nbf * 1000)));
    }
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      return done(new Error('invalid exp value'));
    }
    if (Math.floor(Date.now() / 1000) >= payload.exp + (options.clockTolerance || 0)) {
      return done(new Error('jwt expired', new Date(payload.exp * 1000)));
    }
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];
    var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

    var match = target.some(function(aud) { return audiences.indexOf(aud) != -1; });

    if (!match)
    return done(new Error('jwt audience invalid. expected: ' + audiences.join(' or ')));
  }

  if (options.issuer) {
    var invalid_issuer =
    (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
    (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

    if (invalid_issuer) {
      return done(new Error('jwt issuer invalid. expected: ' + options.issuer));
    }
  }

  if (options.subject) {
    if (payload.sub !== options.subject) {
      return done(new Error('jwt subject invalid. expected: ' + options.subject));
    }
  }

  if (options.jwtid) {
    if (payload.jti !== options.jwtid) {
      return done(new Error('jwt jwtid invalid. expected: ' + options.jwtid));
    }
  }

  if (options.maxAge) {
    var maxAge = ms(options.maxAge);
    if (typeof payload.iat !== 'number') {
      return done(new Error('iat required when maxAge is specified'));
    }
    if (Date.now() - (payload.iat * 1000) > maxAge + (options.clockTolerance || 0) * 1000) {
      return done(new Error('maxAge exceeded', new Date(payload.iat * 1000 + maxAge)));
    }
  }

  return done(null, payload);
};
