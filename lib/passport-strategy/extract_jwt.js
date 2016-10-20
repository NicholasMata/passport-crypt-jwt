"use strict";

var url = require('url');
var header = require('./parse_header');

var AUTH_HEADER = "authorization";
var DEFAULT_AUTH_SCHEME = "JWT";

module.exports = {
    header: function(name) {
        return function(request) {
            return (name in request.headers) ? request.headers[name] : null;
        };
    },

    authHeaderWithScheme: function(auth_scheme) {
        return function (request) {
            var token = null;
            if (request.headers[AUTH_HEADER]) {
                var auth_params = header.parse(request.headers[AUTH_HEADER]);
                if (auth_params && auth_scheme === auth_params.scheme) {
                    token = auth_params.value;
                }
            }
            return token;
        };
    },

    authHeader: function () {
        return this.authHeaderWithScheme(DEFAULT_AUTH_SCHEME);
    },

    bodyField: function(name) {
        return function (request) {
            var token = null;
            if (request.body && name in request.body) {
                token = request.body[name];
            }
            return token;
        };
    },

    urlQuery: function(name) {
        return function (request) {
            var token = null,
            parsed_url = url.parse(request.url, true);
            if (parsed_url.query && name in parsed_url.query) {
                token = parsed_url.query[name];
            }
            return token;
        };
    },

    extractors: function(extractors) {
        if (!Array.isArray(extractors)) {
            throw new TypeError('extractors.fromExtractors expects an array')
        }

        return function (request) {
            var token = null;
            var index = 0;
            while(!token && index < extractors.length) {
                token = extractors[index].call(this, request);
                index ++;
            }
            return token;
        }
    }
};
