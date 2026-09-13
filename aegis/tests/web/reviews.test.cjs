const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function harness() {
 const elements=new Map(), requests=[]; let pending=null, fail=false;
 const get=id=>{if(!elements.has(id)) elements.set(id,{value:'',textContent:'',hidden:false,disabled:false,listeners:{},addEventListener(k,v){this.listeners[k]=v;}});return elements.get(id);};
 const context={document:{getElementById:get},window:{addEventListener(){}},fetch:async(url,opts)=>{
  requests.push({url,opts});
  if(pending) await pending;
  if(fail) throw Error('connection lost');
  return {ok:true,json:async()=>url.endsWith('/me')?{subject:'human:reviewer',tenant:'acme'}:url.endsWith('/preview')?{intent:{action:'<img onerror=alert(1)>'},max_uses:1}:{approval_id:'approval:test',expires_at:2000000000}};
 }};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../web/reviews.js'),'utf8'),context);
 return {get,requests,pause:()=>{let resolve;pending=new Promise(r=>resolve=r);return ()=>{pending=null;resolve();};},fail:()=>{fail=true;},
 async connect(){get('review-token').value='test-reviewer';await get('review-connect').listeners.click();},
 async preview(){get('review-proposal').value=JSON.stringify({capability_token:'sample',intent:{action:'read'}});await get('review-preview').listeners.click();}};
}
test('review has no authority until explicit approval and submits the reviewed snapshot once',async()=>{
 const h=harness();assert.equal(h.get('review-approve').disabled,true);await h.connect();await h.preview();
 assert.match(h.get('review-identity').textContent,/human:reviewer/);
 assert.match(h.get('review-summary').textContent,/<img/);
 assert.equal(h.requests.filter(r=>r.url.endsWith('/approve')).length,0);
 const snapshot=h.requests.at(-1).opts.body;
 await h.get('review-approve').listeners.click();await h.get('review-approve').listeners.click();
 const approvals=h.requests.filter(r=>r.url.endsWith('/approve'));assert.equal(approvals.length,1);assert.equal(approvals[0].opts.body,snapshot);
 assert.match(h.get('review-result').textContent,/No action was executed/);
});
test('editing invalidates review and disconnect rejects late responses',async()=>{
 const h=harness();await h.connect();await h.preview();h.get('review-proposal').listeners.input();
 assert.equal(h.get('review-approve').disabled,true);
 const resume=h.pause();const request=h.preview();h.get('review-disconnect').listeners.click();resume();await request;
 assert.equal(h.get('review-approve').disabled,true);assert.equal(h.get('review-details').hidden,true);assert.equal(h.get('review-proposal').value,'');
});
test('uncertain approval never retries or claims success',async()=>{
 const h=harness();await h.connect();await h.preview();h.fail();await h.get('review-approve').listeners.click();await h.get('review-approve').listeners.click();
 assert.equal(h.requests.filter(r=>r.url.endsWith('/approve')).length,1);assert.match(h.get('review-status').textContent,/unknown/);assert.equal(h.get('review-result').textContent,'');
});
