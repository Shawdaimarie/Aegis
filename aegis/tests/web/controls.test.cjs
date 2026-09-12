const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness(permissions = ['automation_enabled', 'require_human_approval']) {
  const elements = new Map();
  function element() { return { value: '', textContent: '', disabled: false, attrs: {}, listeners: {}, children: [],
    setAttribute(k,v) { this.attrs[k]=v; }, addEventListener(k,v) { this.listeners[k]=v; },
    replaceChildren() { this.children=[]; }, append(v) { this.children.push(v); }, focus() {} }; }
  const get = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  let settings = { automation_enabled:false, require_human_approval:true, revision:0, tenant:'test' };
  const requests = []; let fail = false;
  const context = { document:{ getElementById:get, createElement:element }, window:{addEventListener() {}},
    fetch:async (url, opts) => {
      requests.push({url, opts});
      if (fail) return { ok:false, status:409, json:async()=>({detail:'settings changed'}) };
      if (opts.method === 'PATCH') { const p=JSON.parse(opts.body); assert.equal(p.expected_revision, settings.revision);
        settings={...settings,[p.setting]:p.enabled,revision:settings.revision+1}; }
      return {ok:true, json:async()=>url.endsWith('/history') ? [] : { settings:{...settings}, subject:'human:test', role:'user', permissions }};
    }};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../web/controls.js'),'utf8'), context);
  return {get,requests,fail:()=>{fail=true;},settings:()=>settings,
    async connect() { get('control-token').value='disposable-test-credential'; await get('control-connect').listeners.click(); }};
}

test('two switches submit independent explicit changes and retain the other value', async()=>{
  const h=harness(); assert.equal(h.get('automation-switch').disabled,true);
  await h.connect(); assert.equal(h.get('control-token').value,'');
  h.get('control-reason').value='Resume testing'; await h.get('automation-switch').listeners.click();
  assert.equal(h.settings().automation_enabled,true); assert.equal(h.settings().require_human_approval,true);
  h.get('control-reason').value='Use scoped policy'; await h.get('approval-switch').listeners.click();
  assert.equal(h.settings().automation_enabled,true); assert.equal(h.settings().require_human_approval,false);
  h.get('control-disconnect').listeners.click(); assert.equal(h.get('automation-switch').disabled,true);
  assert.equal(h.get('approval-switch').textContent,'Unknown');
});
test('permissions and required reason prevent unauthorized or unexplained UI changes', async()=>{
  const h=harness(['automation_enabled']); await h.connect();
  assert.equal(h.get('approval-switch').disabled,true);
  await h.get('approval-switch').listeners.click(); await h.get('automation-switch').listeners.click();
  assert.equal(h.requests.filter(r=>r.opts.method==='PATCH').length,0);
  assert.match(h.get('control-status').textContent,/reason/);
});
test('conflict disables controls and never reports an unconfirmed switch state', async()=>{
  const h=harness(); await h.connect(); h.fail();
  h.get('control-reason').value='Stale decision'; await h.get('automation-switch').listeners.click();
  assert.equal(h.get('automation-switch').disabled,true);
  assert.equal(h.get('automation-switch').textContent,'Unknown');
  assert.match(h.get('control-status').textContent,/Reconnect/);
});
