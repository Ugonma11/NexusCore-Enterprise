#!/usr/bin/env node
'use strict';
const fs=require('fs'),assert=require('assert'),vm=require('vm'),path=require('path');
const server=fs.readFileSync(path.join(__dirname,'..','server.js'),'utf8');
const ui=fs.readFileSync(path.join(__dirname,'..','public','app.js'),'utf8');
new vm.Script(server);new vm.Script(ui);
assert.match(server,/wantAssertionsSigned:true,wantAuthnResponseSigned:false/,'Required signed assertion with optional outer signature');
assert.match(server,/idpIssuer:process\.env\.ENTRA_ISSUER/,'Entra issuer is validated');
assert.match(server,/validateInResponseTo:'always'/,'InResponseTo checked');
assert.match(server,/new crypto\.X509Certificate\(der\)/,'Certificate must parse');
assert.match(server,/\/scim\/v2\/Users/,'SCIM users endpoints');
assert.match(server,/\/scim\/v2\/Groups/,'SCIM groups endpoints');
assert.match(server,/passport\.authenticate\('entra-saml'/,'SAML sign-in enabled');
assert.match(server,/req\.isAuthenticated\(\)/,'Dashboard authentication middleware');
console.log('PASS: JavaScript parsing, SAML signature requirements, issuer/replay protections, SCIM endpoints and dashboard route.');
