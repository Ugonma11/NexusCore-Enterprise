'use strict';
const fs = require('fs'), assert = require('assert'), path = require('path');
const js = fs.readFileSync(path.join(__dirname,'..','public','app.js'),'utf8');
const html = fs.readFileSync(path.join(__dirname,'..','public','preview.html'),'utf8');
const css = fs.readFileSync(path.join(__dirname,'..','public','style.css'),'utf8');
for (const keyword of ['Connectivity','Investigations','Topology','Identity']) {
 assert(js.toLowerCase().includes(keyword.toLowerCase()), `${keyword} section missing`);
}
assert(html.includes('app.js'),'Preview loads dashboard JS');
assert(css.length>1000,'Dashboard styles present');
console.log('PASS: Network dashboard preview files, clickable section text and styles present.');
