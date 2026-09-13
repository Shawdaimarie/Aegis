const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function harness() {
 const nodes=new Map(),requests=[];let jobs=[],lost=false,hold=null;
 const element=()=>({value:'',textContent:'',disabled:false,hidden:false,children:[],listeners:{},addEventListener(k,v){this.listeners[k]=v;},append(...x){this.children.push(...x);},replaceChildren(){this.children=[];}});
 const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};get('work-role').value='operator';
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../web/work.js'),'utf8'),{
 document:{getElementById:get,createElement:element},window:{addEventListener(){}},crypto:{randomUUID:()=> 'unique-request-0001'},
 fetch:async(url,opts)=>{requests.push({url,opts});if(hold)await hold;if(opts.method==='POST'&&url.endsWith('/jobs')){
  const request=JSON.parse(opts.body);if(!jobs.length)jobs=[{id:'work-test',tenant:'acme',requested_by:'human:op',request,status:'pending',revision:0}];
  if(lost){lost=false;throw Error('response lost');}return {ok:true,json:async()=>jobs[0]};
 }return {ok:true,json:async()=>jobs};}
 });
 const tick=()=>new Promise(r=>setImmediate(r));
 return {get,requests,jobs:()=>jobs,lose:()=>{lost=true;},pause:()=>{let resume;hold=new Promise(r=>resume=r);return ()=>{hold=null;resume();};},
 async connect(){get('work-token').value='test-credential';get('work-connect').listeners.click();await tick();},
 async submit(){get('work-repository').value='owner/repo';get('work-purpose').value='<script>untrusted</script>';get('work-submit').listeners.click();await tick();},tick};
}
test('saving work does not run it and source text remains text',async()=>{
 const h=harness();await h.connect();await h.submit();assert.equal(h.jobs().length,1);
 assert.equal(h.requests.filter(r=>r.url.endsWith('/run')).length,0);
 const card=h.get('work-items').children[0];assert.equal(card.children[1].textContent,'<script>untrusted</script>');
 assert.equal(h.get('work-token').value,'');
});
test('lost create response retains the idempotency key for an explicit retry',async()=>{
 const h=harness();await h.connect();h.lose();await h.submit();
 assert.match(h.get('work-status').textContent,/No automatic retry/);
 h.get('work-submit').listeners.click();await h.tick();
 const requests=h.requests.filter(r=>r.opts.method==='POST');assert.equal(requests.length,2);assert.equal(requests[0].opts.body,requests[1].opts.body);assert.equal(h.jobs().length,1);
});
test('disconnect suppresses a late response and clears private state',async()=>{
 const h=harness();await h.connect();const resume=h.pause();h.get('work-refresh').listeners.click();h.get('work-disconnect').listeners.click();resume();await h.tick();
 assert.equal(h.get('work-items').children.length,0);assert.equal(h.get('work-refresh').disabled,true);assert.match(h.get('work-status').textContent,/Disconnected/);
});
