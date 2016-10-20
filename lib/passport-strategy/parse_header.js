'use strict';

// Regex for verifying test.
var re = /(\S+)\s+(\S+)/;

module.exports = {
    parse: function (headerValue) {
        // Make sure header value is string.
        if (typeof headerValue !== 'string') {
            return null;
        }
        // Perform regex on header value.
        var matches = headerValue.match(re);
        return matches && { scheme: matches[1], value: matches[2] };
    }
};
