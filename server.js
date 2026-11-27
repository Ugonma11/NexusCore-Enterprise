'use strict';
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const helmet = require('helmet');
const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3000);
const BASE = String(process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const ISSUER = `${BASE}/saml/metadata`; // One canonical Entity ID; no second issuer variable to configure.
const SCIM = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCIM = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const ERROR_SCIM = 'urn:ietf:params:scim:api:messages:2.0:Error';
const LIST_SCIM = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const PATCH_SCIM = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const FILE = path.join(DATA_DIR, 'directory.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
function load() {
  try { const j=JSON.parse(fs.readFileSync(FILE,'utf8')); return {users:j.users||[],groups:j.groups||[]}; }
  catch(e) { if(e.code !== 'ENOENT') console.error('Directory file read failed:',e.message); return {users:[],groups:[]}; }
}
let db=load();
function save(){ const temp=FILE+'.tmp'; fs.writeFileSync(temp,JSON.stringify(db,null,2)); fs.renameSync(temp,FILE); }
function now(){return new Date().toISOString();}
function uid(){return crypto.randomUUID();}
function safeEq(a,b){const A=Buffer.from(String(a||''));const B=Buffer.from(String(b||''));return A.length===B.length && crypto.timingSafeEqual(A,B);}
function asBool(v){return v === true || v === 'true' || v === 1;}
function errorSCIM(res,status,detail){return res.status(status).type('application/scim+json').json({schemas:[ERROR_SCIM],status:String(status),detail});}
const configSaml = !!(process.env.ENTRA_LOGIN_URL && process.env.ENTRA_ISSUER && process.env.ENTRA_CERT_BASE64);
const configScim = !!process.env.SCIM_BEARER_TOKEN && !process.env.SCIM_BEARER_TOKEN.startsWith('REPLACE_');
const sessionSecret=process.env.SESSION_SECRET;
if (isProd && !configSaml) throw new Error('SAML environment variables missing: ENTRA_LOGIN_URL, ENTRA_ISSUER, ENTRA_CERT_BASE64');
if (isProd && (!sessionSecret || sessionSecret.startsWith('REPLACE_') || sessionSecret.length<32)) throw new Error('SESSION_SECRET must be a strong random string in production');
if (isProd && !BASE.startsWith('https://')) throw new Error('APP_BASE_URL must be HTTPS in production');
app.set('trust proxy', 1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'"], styleSrcAttr:["'unsafe-inline'"], imgSrc:["'self'","data:"], connectSrc:["'self'"], fontSrc:["'self'"], objectSrc:["'none'"], upgradeInsecureRequests:isProd?[]:null}}}));
app.use(express.json({limit:'256kb',type:['application/json','application/scim+json']}));
app.use(express.urlencoded({extended:false,limit:'128kb'}));
app.use(session({secret:sessionSecret && !sessionSecret.startsWith('REPLACE_') ? sessionSecret : crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:isProd,maxAge:8*60*60*1000}}));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((u,done)=>done(null,u));
passport.deserializeUser((u,done)=>done(null,u));
function certFromEnv(v) {
  // Accept a standard PEM .cer, PEM with literal \n escapes, or DER Base64.
  // Reject a second Base64 layer around the PEM and fail during startup.
  const raw = String(v || '').replace(/\\n/g, '\n').trim();
  if (!raw) throw new Error('ENTRA_CERT_BASE64 is empty');
  const header = '-----BEGIN CERTIFICATE-----';
  const footer = '-----END CERTIFICATE-----';
  let derBase64;
  if (raw.includes(header) || raw.includes(footer)) {
    if (!raw.startsWith(header) || !raw.endsWith(footer)) throw new Error('Incomplete PEM certificate');
    derBase64 = raw.slice(header.length, -footer.length).replace(/\s/g, '');
  } else {
    derBase64 = raw.replace(/\s/g, '');
  }
  if (!derBase64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(derBase64)) {
    throw new Error('Certificate must be PEM text or raw DER Base64, not double-encoded PEM');
  }
  const der = Buffer.from(derBase64, 'base64');
  if (der.toString('base64') !== derBase64) throw new Error('Certificate has invalid Base64 encoding');
  if (der.toString('utf8', 0, 28).includes('BEGIN CERTIFICATE')) {
    throw new Error('Double-encoded PEM detected: paste the original certificate text');
  }
  // This validates that the content is an actual X.509 certificate, not just Base64 text.
  new crypto.X509Certificate(der);
  return `${header}\n${derBase64.match(/.{1,64}/g).join('\n')}\n${footer}`;
}
let samlReady=false;
if(configSaml){
  try{
    const cert=certFromEnv(process.env.ENTRA_CERT_BASE64);
    const strategy=new SamlStrategy({entryPoint:process.env.ENTRA_LOGIN_URL,issuer:ISSUER,callbackUrl:`${BASE}/saml/acs`,idpCert:cert,idpIssuer:process.env.ENTRA_ISSUER,validateInResponseTo:'always',disableRequestedAuthnContext:true,wantAssertionsSigned:true,wantAuthnResponseSigned:false,acceptedClockSkewMs:30000}, (profile,done)=>{
      if(!profile || !profile.nameID) return done(new Error('Missing SAML NameID'));
      const email=profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] || profile.nameID;
      return done(null,{name:profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']||email,email,nameID:profile.nameID,loggedInAt:now()});
    });
    passport.use('entra-saml',strategy); samlReady=true;
  }catch(e){console.error('SAML startup config invalid:',e.message); if (isProd) throw e;}
}
app.get('/health',(req,res)=>res.json({ok:true,app:'NexusCore Enterprise',samlConfigured:samlReady,scimConfigured:configScim,storage:'local-json'}));
app.use('/assets',express.static(path.join(__dirname,'public'),{maxAge:isProd?'1h':0}));
app.get('/',(req,res)=>res.redirect(req.isAuthenticated()?'/dashboard':'/login'));
app.get('/login',(req,res)=>res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/preview',(req,res)=>res.sendFile(path.join(__dirname,'public','preview.html')));
app.get('/saml/login',(req,res,next)=>{
  if(!samlReady) return res.status(503).send('SAML not configured yet. Set ENTRA_LOGIN_URL, ENTRA_ISSUER, and ENTRA_CERT_BASE64. Use /preview to inspect the UI.');
  passport.authenticate('entra-saml')(req,res,next);
});
app.post('/saml/acs',(req,res,next)=>{
  if(!samlReady) return res.status(503).send('SAML is not configured');
  passport.authenticate('entra-saml',{failureRedirect:'/login?error=saml'},(err,user)=>{
    if(err||!user){console.error('SAML ACS failure:',err?.message||'no user');return res.status(401).send('SAML validation failed. Check signing certificate, NameID, ACS URL and Entra sign-in logs.');}
    req.logIn(user,(loginError)=>{if(loginError)return next(loginError);res.redirect('/dashboard');});
  })(req,res,next);
});
app.get('/saml/metadata',(req,res)=>{
  const esc=s=>String(s).replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
  res.type('application/samlmetadata+xml').send(`<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${esc(ISSUER)}"><SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(BASE+'/saml/acs')}" index="0" isDefault="true"/></SPSSODescriptor></EntityDescriptor>`);
});
function mustAuth(req,res,next){if(req.isAuthenticated())return next();return res.status(401).json({error:'Sign in with Entra ID first'});}
app.get('/dashboard',(req,res)=>{if(!req.isAuthenticated())return res.redirect('/login');res.sendFile(path.join(__dirname,'public','dashboard.html'));});
app.get('/api/me',mustAuth,(req,res)=>res.json({user:req.user}));
app.get('/api/directory',mustAuth,(req,res)=>res.json({users:db.users.map(u=>({id:u.id,userName:u.userName,displayName:u.displayName,active:u.active,title:u.title,department:u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']?.department||'',lastModified:u.meta?.lastModified})),groups:db.groups.map(g=>({id:g.id,displayName:g.displayName,members:g.members?.length||0}))}));
app.post('/logout',mustAuth,(req,res)=>req.logout(()=>req.session.destroy(()=>res.json({ok:true}))));

// Token auth for all SCIM routes (including /ServiceProviderConfig).
app.use('/scim/v2',(req,res,next)=>{if(!configScim)return errorSCIM(res,503,'SCIM token is not configured');const authorization=req.get('authorization')||'';if(!authorization.startsWith('Bearer ')||!safeEq(authorization.slice(7),process.env.SCIM_BEARER_TOKEN))return errorSCIM(res,401,'Invalid SCIM bearer token');res.set('Cache-Control','no-store');next();});
function canonicalUser(u){ const created=u.meta?.created||now(); const id=u.id||uid(); const userName=String(u.userName||u.emails?.[0]?.value||'').trim();return {...u,schemas:[SCIM,...(u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']?['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']:[])],id,userName,active:u.active===undefined?true:asBool(u.active),meta:{resourceType:'User',created,lastModified:now(),location:`${BASE}/scim/v2/Users/${id}`}}; }
function sendUser(res,u,status=200){res.status(status).type('application/scim+json').json(u);}
function getFilter(filter){ if(!filter) return null;const m=String(filter).match(/^\s*(userName|externalId|id|displayName)\s+eq\s+"([^"]+)"\s*$/i); if(!m)return null;return {field:m[1],value:m[2]};}
function respondList(res,rows,req){const start=Math.max(1,Number(req.query.startIndex)||1),count=Math.max(0,Math.min(200,Number(req.query.count)||100));res.type('application/scim+json').json({schemas:[LIST_SCIM],totalResults:rows.length,startIndex:start,itemsPerPage:rows.slice(start-1,start-1+count).length,Resources:rows.slice(start-1,start-1+count)});}
app.get('/scim/v2/ServiceProviderConfig',(req,res)=>res.type('application/scim+json').json({schemas:['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],patch:{supported:true},bulk:{supported:false,maxOperations:0,maxPayloadSize:0},filter:{supported:true,maxResults:200},changePassword:{supported:false},sort:{supported:false},etag:{supported:false},authenticationSchemes:[{type:'oauthbearertoken',name:'Bearer Token',description:'Static bearer token for training lab',primary:true}]}));
app.get('/scim/v2/Schemas',(req,res)=>respondList(res,[{id:SCIM,name:'User',description:'SCIM core User',schemas:['urn:ietf:params:scim:schemas:core:2.0:Schema']},{id:GROUP_SCIM,name:'Group',description:'SCIM core Group',schemas:['urn:ietf:params:scim:schemas:core:2.0:Schema']}],req));
app.get('/scim/v2/ResourceTypes',(req,res)=>respondList(res,[{schemas:['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],id:'User',name:'User',endpoint:'/Users',schema:SCIM},{schemas:['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],id:'Group',name:'Group',endpoint:'/Groups',schema:GROUP_SCIM}],req));
app.get('/scim/v2/Users',(req,res)=>{const f=getFilter(req.query.filter);if(req.query.filter&&!f)return errorSCIM(res,400,'Supported filters: userName, externalId, id or displayName eq "value"');const rows=f?db.users.filter(u=>String(u[f.field]||'').toLowerCase()===f.value.toLowerCase()):db.users;respondList(res,rows,req);});
app.get('/scim/v2/Users/:id',(req,res)=>{const u=db.users.find(u=>u.id===req.params.id);if(!u)return errorSCIM(res,404,'User not found');sendUser(res,u);});
app.post('/scim/v2/Users',(req,res)=>{const body=req.body||{};if(!body.userName)return errorSCIM(res,400,'userName is required');if(db.users.some(u=>u.userName.toLowerCase()===String(body.userName).toLowerCase()))return errorSCIM(res,409,'userName already exists');const u=canonicalUser(body);db.users.push(u);save();sendUser(res,u,201);});
app.put('/scim/v2/Users/:id',(req,res)=>{const i=db.users.findIndex(u=>u.id===req.params.id);if(i<0)return errorSCIM(res,404,'User not found');const body=req.body||{};if(body.userName&&db.users.some(u=>u.id!==req.params.id&&u.userName.toLowerCase()===String(body.userName).toLowerCase()))return errorSCIM(res,409,'userName already exists');db.users[i]=canonicalUser({...body,id:req.params.id,meta:{created:db.users[i].meta.created},userName:body.userName||db.users[i].userName});save();sendUser(res,db.users[i]);});
function setPath(obj,pathExpr,value){let p=String(pathExpr||'').trim();if(!p)return;const emailMatch=p.match(/^emails\[type eq "([^"]+)"\]\.value$/i);if(emailMatch){const arr=Array.isArray(obj.emails)?obj.emails:[];const idx=arr.findIndex(e=>e.type===emailMatch[1]);if(idx>=0)arr[idx].value=value;else arr.push({type:emailMatch[1],value,primary:true});obj.emails=arr;return;}
  const pieces=p.split('.');let target=obj;for(let i=0;i<pieces.length-1;i++){target[pieces[i]]=target[pieces[i]]&&typeof target[pieces[i]]==='object'?target[pieces[i]]:{};target=target[pieces[i]];}target[pieces.at(-1)]=value;
}
function patchObject(original,operations){const target=structuredClone(original);for(const op of operations){const action=String(op.op||'').toLowerCase();const p=op.path;if(!['add','replace','remove'].includes(action))throw Error('Unsupported SCIM PATCH operation');if(!p){if(action==='remove')throw Error('Remove requires path');if(typeof op.value!=='object'||!op.value||Array.isArray(op.value))throw Error('Value must be an object for no-path patch');Object.entries(op.value).forEach(([k,v])=>setPath(target,k,v));continue;}if(action==='remove'){if(p==='active')target.active=false;else setPath(target,p,null);continue;}setPath(target,p,op.value);}return target;}
app.patch('/scim/v2/Users/:id',(req,res)=>{const i=db.users.findIndex(u=>u.id===req.params.id);if(i<0)return errorSCIM(res,404,'User not found');if(!Array.isArray(req.body?.Operations))return errorSCIM(res,400,'Operations array required');try{const obj=patchObject(db.users[i],req.body.Operations);obj.id=req.params.id;db.users[i]=canonicalUser(obj);save();sendUser(res,db.users[i]);}catch(e){return errorSCIM(res,400,e.message);}});
app.delete('/scim/v2/Users/:id',(req,res)=>{const i=db.users.findIndex(u=>u.id===req.params.id);if(i<0)return errorSCIM(res,404,'User not found');db.users[i].active=false;db.users[i].meta.lastModified=now();save();res.status(204).end();});
function canonGroup(obj){const id=obj.id||uid();return {...obj,id,schemas:[GROUP_SCIM],members:Array.isArray(obj.members)?obj.members:[],meta:{resourceType:'Group',created:obj.meta?.created||now(),lastModified:now(),location:`${BASE}/scim/v2/Groups/${id}`}};}
app.get('/scim/v2/Groups',(req,res)=>{const f=getFilter(req.query.filter);if(req.query.filter&&!f)return errorSCIM(res,400,'Unsupported group filter');const rows=f?db.groups.filter(g=>String(g[f.field]||'').toLowerCase()===f.value.toLowerCase()):db.groups;respondList(res,rows,req);});
app.get('/scim/v2/Groups/:id',(req,res)=>{const g=db.groups.find(g=>g.id===req.params.id);if(!g)return errorSCIM(res,404,'Group not found');res.type('application/scim+json').json(g);});
app.post('/scim/v2/Groups',(req,res)=>{if(!req.body?.displayName)return errorSCIM(res,400,'displayName required');if(db.groups.some(g=>g.displayName.toLowerCase()===String(req.body.displayName).toLowerCase()))return errorSCIM(res,409,'Group already exists');const g=canonGroup(req.body);db.groups.push(g);save();res.status(201).type('application/scim+json').json(g);});
app.put('/scim/v2/Groups/:id',(req,res)=>{const i=db.groups.findIndex(g=>g.id===req.params.id);if(i<0)return errorSCIM(res,404,'Group not found');db.groups[i]=canonGroup({...req.body,id:req.params.id,meta:db.groups[i].meta});save();res.type('application/scim+json').json(db.groups[i]);});
app.patch('/scim/v2/Groups/:id',(req,res)=>{const i=db.groups.findIndex(g=>g.id===req.params.id);if(i<0)return errorSCIM(res,404,'Group not found');try{const g=structuredClone(db.groups[i]);for(const op of req.body?.Operations||[]){const action=String(op.op).toLowerCase();const p=String(op.path||'');if(p==='displayName'){if(action!=='remove')g.displayName=op.value;continue;}if(p===''&&op.value?.displayName)g.displayName=op.value.displayName;const incoming=Array.isArray(op.value?.members)?op.value.members:Array.isArray(op.value)?op.value:[];if(p.startsWith('members')||(!p&&op.value?.members)){if(action==='add'){for(const m of incoming){if(!g.members.some(x=>x.value===m.value))g.members.push(m);}}else if(action==='replace')g.members=incoming;else if(action==='remove'){const filter=p.match(/members\[value eq "([^"]+)"\]/i);if(filter)g.members=g.members.filter(m=>m.value!==filter[1]);else g.members=g.members.filter(m=>!incoming.some(x=>x.value===m.value));}}}db.groups[i]=canonGroup(g);save();res.type('application/scim+json').json(db.groups[i]);}catch(e){return errorSCIM(res,400,e.message);}});
app.delete('/scim/v2/Groups/:id',(req,res)=>{const i=db.groups.findIndex(g=>g.id===req.params.id);if(i<0)return errorSCIM(res,404,'Group not found');db.groups.splice(i,1);save();res.status(204).end();});
app.use((err,req,res,next)=>{console.error('Request error:',err.message);if(req.path.startsWith('/scim/'))return errorSCIM(res,500,'Internal SCIM service error');res.status(500).send('Application error. Review server logs.');});
app.listen(PORT,()=>console.log(`NexusCore Enterprise listening on port ${PORT} | SAML configured: ${samlReady} | SCIM token: ${configScim} | base: ${BASE}`));
