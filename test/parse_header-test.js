var header = require('../lib/passport-strategy/parse_header')


describe('Header Parser', function() {

    it('Should handle single space separated values', function() {
        var res = header.parse("SCHEME VALUE");
        expect(res).to.deep.equal({scheme: "SCHEME", value: "VALUE"});
    });


    it('Should handle CRLF separator', function() {
        var res = header.parse("SCHEME\nVALUE");
        expect(res).to.deep.equal({scheme: "SCHEME", value: "VALUE"});
    });


    it('Should handle malformed authentication headers with no scheme', function() {
        var res = header.parse("SCHEMEVALUE");
        expect(res).to.not.be.ok;
    });


});
