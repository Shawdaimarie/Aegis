/* A saved request is data, never authority to run source instructions. */
(() => {
 'use strict';
 const el = id => document.getElementById(id);
 let token='', role='operator', generation=0, busy=false, items=[], pending=null;
 const status=text=>{el('work-status').textContent=text;};
 const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
 async function api(path, body) {
  const version=generation;
  const response=await fetch('/v1/work/'+path,{method:body===undefined?'GET':'POST',cache:'no-store',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
  if(version!==generation)throw Error('Connection changed.');
  if(!response.ok){const error=Error('Queue request unavailable or declined ('+response.status+'). Refresh to verify saved state.');error.status=response.status;throw error;}
  const data=await response.json();if(version!==generation)throw Error('Connection changed.');return data;
 }
 function disconnect() {
  generation++;token='';busy=false;items=[];pending=null;
  el('work-token').value='';el('work-repository').value='';el('work-purpose').value='';
  status('Disconnected. Saved work remains in the queue. An inspection already started may still finish.');render();
 }
 async function perform(action) {
  if(!token||busy)return;
  const version=generation;busy=true;render();
  try {const message=await action();if(version!==generation)return;status(message);}
  catch(error){if(version===generation)status(error.message+' No automatic retry was made.');}
  finally {if(version===generation){busy=false;render();}}
 }
 async function refresh() {const version=generation;const result=await api(role+'/jobs');if(version===generation)items=result;}
 function render() {
  el('work-connect').disabled=busy;el('work-disconnect').disabled=!token;
  el('work-refresh').disabled=!token||busy;el('work-submit').disabled=!token||busy;
  el('work-role').disabled=!!token;el('work-token').disabled=!!token;
  el('work-new').hidden=!token||role!=='operator';
  el('work-repository').disabled=busy||!!pending;el('work-purpose').disabled=busy||!!pending;
  const target=el('work-items');target.replaceChildren();
  for(const item of items){
   const card=node('article','');card.className='work-card';
   card.append(node('h3',item.request.repository+' · '+item.status));
   card.append(node('p',item.request.purpose));card.append(node('p','Requested by '+item.requested_by+' · '+item.tenant+' · '+item.id));
   if(item.reviewer)card.append(node('p','Reviewer: '+item.reviewer+' · '+item.decision_reason));
   if(item.approval_expires_at)card.append(node('p','Approval expires: '+new Date(item.approval_expires_at*1000).toISOString()));
   if(item.result)card.append(node('pre',JSON.stringify(item.result,null,2)));
   if(item.error)card.append(node('p',item.error));
   if(item.status==='running')card.append(node('p','Inspection started. If interrupted, this item is not automatically retried.'));
   function action(label,handler){const b=node('button',label);b.type='button';b.disabled=busy;b.addEventListener('click',handler);card.append(b);}
   if(role==='reviewer'&&(item.status==='pending'||item.status==='approved')){
    const label=node('label','Decision reason');const reason=document.createElement('input');reason.maxLength=500;reason.minLength=3;label.append(reason);card.append(label);
    for(const decision of (item.status==='pending'?['approved','rejected']:['rejected'])) action(decision==='approved'?'Approve inspection for five minutes':'Reject / withdraw approval',()=>{
     const explanation=reason.value.trim();if(explanation.length<3){status('Add a reason before deciding.');return;}
     perform(async()=>{await api('jobs/'+encodeURIComponent(item.id)+'/decision',{decision,reason:explanation,expected_revision:item.revision});await refresh();return 'Decision saved for '+item.id;});
    });
   }
   if(role==='operator'&&item.status==='approved')action('Run approved inspection',()=>perform(async()=>{const result=await api('jobs/'+encodeURIComponent(item.id)+'/run',{});await refresh();return 'Inspection '+result.status+'. Result retained for '+item.id;}));
   target.append(card);
  }
  if(token&&!items.length)target.append(node('p','No saved requests in this tenant.'));
 }
 el('work-connect').addEventListener('click',()=>{
  const supplied=el('work-token').value.trim(), selected=el('work-role').value;disconnect();
  if(!supplied){status('Enter your queue access credential.');return;}
  token=supplied;role=selected;el('work-token').value='';
  perform(async()=>{await refresh();return 'Connected as '+role+'. Saved work loaded.';});
 });
 el('work-disconnect').addEventListener('click',disconnect);
 el('work-refresh').addEventListener('click',()=>perform(async()=>{await refresh();return 'Saved work refreshed.';}));
 el('work-submit').addEventListener('click',()=>perform(async()=>{
  if(!pending)pending={repository:el('work-repository').value.trim(),purpose:el('work-purpose').value.trim(),request_key:crypto.randomUUID()};
  let result;try{result=await api('jobs',pending);}catch(error){if([400,401,403,409,422].includes(error.status))pending=null;throw error;}pending=null;el('work-repository').value='';el('work-purpose').value='';await refresh();return 'Request saved: '+result.id+'. Awaiting human review.';
 }));
 window.addEventListener('pagehide',disconnect);render();
})();
