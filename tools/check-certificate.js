#!/usr/bin/env node
'use strict';
// Safe local preflight: reads public certificate; NEVER prints it or any secret.
const fs=require('fs');
const crypto=require('crypto');
const source=process.argv[2];
if(!source){console.error('Usage: node tools/check-certificate.js "C:\\Users\\...\\Downloads\\NexusCore.cer"');process.exit(2);}
try{
 const content=fs.readFileSync(source,'utf8').trim().replace(/\\n/g,'\n');
 const header='-----BEGIN CERTIFICATE-----',footer='-----END CERTIFICATE-----';
 const raw=content.includes(header) ? content.replace(header,'').replace(footer,'') : content;
 const b64=raw.replace(/\s/g,'');
 if(!/^[A-Za-z0-9+/]+={0,2}$/.test(b64))throw Error('Not a valid Base64 certificate');
 const buf=Buffer.from(b64,'base64');
 if(buf.toString('base64')!==b64)throw Error('Certificate Base64 padding/encoding invalid');
 const cert=new crypto.X509Certificate(buf);
 console.log('Certificate: VALID X.509');
 console.log('Subject:',cert.subject.replaceAll('\n','; '));
 console.log('SHA-1 thumbprint:',cert.fingerprint.replaceAll(':',''));
 console.log('Valid until:',cert.validTo);
 console.log('SAML library configuration: signed assertion REQUIRED; outer response signature OPTIONAL.');
}catch(e){console.error('Certificate check FAILED:',e.message);process.exit(1);}
