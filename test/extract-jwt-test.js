var ExtractJWT = require('../lib/passport-strategy/extract_jwt'),
Request = require('./fake_request');

describe('Extraction', function() {

    describe('From Header', function() {

        var extractor = ExtractJWT.header('authorization');

        it('should return null no when token is present', function() {
            var req = new Request();

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return the value from the specified header', function() {
            var req = new Request();
            req.headers['authorization'] = 'abcd123'

            var token = extractor(req)

            expect(token).to.equal('abcd123');
        });
    });


    describe('From Body', function() {

        var extractor = ExtractJWT.bodyField('authorization');

        it('should return null when no body is present', function() {
            var req = new Request();

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return null when the specified body field is not present', function() {
            var req = new Request();
            req.body = {};

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return the value from the specified body field', function() {
            var req = new Request();
            req.body = {};
            req.body.authorization = 'abcd123';

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });
    });


    describe('From URL Query', function() {

        var extractor = ExtractJWT.urlQuery('authorization');


        it('should return null when the specified paramter is not present', function() {
            var req = new Request();

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return the value from the specified parameter', function() {
            var req = new Request();
            req.url += '?authorization=abcd123';

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });
    });


    describe('From Authorization Header With Scheme', function() {

        var extractor = ExtractJWT.authHeaderWithScheme('TEST_SCHEME');

        it('should return null when no auth header is present', function() {
            var req = new Request();

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return null when the auth header is present but the auth scheme doesnt match', function() {
            var req = new Request()
            req.headers['authorization'] = "NOT_TEST_SCHEME abcd123";

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return the value from the authorization header with specified auth scheme', function() {
            var req = new Request()
            req.headers['authorization'] = "TEST_SCHEME abcd123";

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });

    });


    describe('From Authorization Header', function() {

        var extractor = ExtractJWT.authHeader();

        it('should return the value from the authorization header with default JWT auth scheme', function() {
            var req = new Request()
            req.headers['authorization'] = "JWT abcd123";

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });


    });

    describe('fromExtractors', function() {

        it('should raise a type error when the extractor is constructed with a non-array argument', function() {
            this_should_throw = function() {
                var extractor = ExtractJWT.extractors({})
            }

            expect(this_should_throw).to.throw(TypeError)
        });


        var extractor = ExtractJWT.extractors([ExtractJWT.authHeader(), ExtractJWT.header('authorization')]);

        it('should return null when no extractor extracts token', function() {
            var req = new Request();

            var token = extractor(req);

            expect(token).to.be.null;
        });


        it('should return token found by least extractor', function() {
            var req = new Request()
            req.headers['authorization'] = "abcd123";

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });


        it('should return token found by first extractor', function() {
            var req = new Request()
            req.headers['authorization'] = "JWT abcd123";

            var token = extractor(req);

            expect(token).to.equal('abcd123');
        });

    });

});
