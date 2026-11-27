'use strict';
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');
// Isolate the actual certificate normalization function from the application.
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const functionStart = server.indexOf('function certFromEnv(v)');
const functionEnd = server.indexOf('\nlet samlReady=', functionStart);
assert(functionStart > 0 && functionEnd > functionStart);
const certFromEnv = new Function('crypto', `${server.slice(functionStart, functionEnd)}\nreturn certFromEnv;`)(crypto);
const fixturePath = process.env.NEXUS_TEST_CERT;
if (!fixturePath) {
  console.log('SKIP certificate-format test: no temporary X.509 fixture provided');
  process.exit(0);
}
const pem = fs.readFileSync(fixturePath, 'utf8').trim();
const normalized = certFromEnv(pem);
assert.equal(new crypto.X509Certificate(normalized).fingerprint, new crypto.X509Certificate(pem).fingerprint);
const escaped = pem.replace(/\n/g, '\\n');
assert.equal(new crypto.X509Certificate(certFromEnv(escaped)).fingerprint, new crypto.X509Certificate(pem).fingerprint);
const raw = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '');
assert.equal(new crypto.X509Certificate(certFromEnv(raw)).fingerprint, new crypto.X509Certificate(pem).fingerprint);
assert.throws(() => certFromEnv(Buffer.from(pem).toString('base64')), /error|certificate|wrong tag|header|encoded|Invalid|DER/i);
assert.throws(() => certFromEnv('-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'));
console.log('PASS: complete PEM, literal-\\n PEM and raw DER Base64 accepted; double-encoded PEM and malformed values rejected.');
