'use strict';
const assert = require('assert');
const {dashboardHtml, dashboardScript} = require('./_dashboard_source.js');
const dom = require('./_dom_stub.js');
const html = dashboardHtml(), script = dashboardScript();
for(const id of ['tabZhanlu','accountsRealmZhanlu','zhanluAccountsSection','zhanluAuthFile','zhanluKeyFile','zhanluEnabled','nextGatewayRealmZhanlu']){
  assert.ok(html.includes('id="' + id + '"'), id);
}
assert.ok(script.includes("/zhanlu/accounts/import"));
assert.ok(script.includes("postJSON('/settings/save', {zhanlu:"));
assert.ok(script.includes("['zhanlu', '固定 Zhanlu 出口']"));
const calls = [];
dom.installDom({confirm:()=>true, fetch:(url, opts)=>{
  calls.push({url, opts});
  const r = url.includes('/zhanlu/accounts/import') ? {ok:true,added:1,updated:0,skipped:0} : url.includes('/zhanlu/overview') ? {configured:true,stats:{total:1,healthy:1},accounts:[]} : {current:'intl',options:['intl','cn','zhanlu'],data:[],accounts:[],rows:[]};
  return Promise.resolve({status:200,ok:true,json:()=>Promise.resolve(r),text:()=>Promise.resolve(JSON.stringify(r))});
}});
const log = console.log; console.log = ()=>{};
const api = new Function(script + '; return {updateUI, realmLabel, importZhanluAuth, setZhanluEnabled};')();
console.log = log;
window.updateUI = api.updateUI;
window.REALM_OPTIONS = ['intl','cn','zhanlu'];
window.VIEW_REALM = 'zhanlu'; window.ACTIVE_GATEWAY_REALM = 'zhanlu';
api.updateUI();
assert.equal(document.getElementById('zhanluAccountsSection').style.display, '');
assert.equal(document.getElementById('workbuddyAccountsSection').style.display, 'none');
assert.equal(document.getElementById('codeartsAccountsSection').style.display, 'none');
assert.equal(document.getElementById('activeGatewayName').textContent, 'Zhanlu');
assert.equal(api.realmLabel('zhanlu'), 'Zhanlu');
window.VIEW_REALM = 'intl'; api.updateUI();
assert.equal(document.getElementById('zhanluAccountsSection').style.display, 'none');
assert.equal(document.getElementById('workbuddyAccountsSection').style.display, '');
(async()=>{
  const input = document.getElementById('zhanluAuthFile');
  const key = document.getElementById('zhanluKeyFile');
  input.files = [{size:20,text:async()=>'{"accounts":{}}'}];
  key.files = [{size:32,arrayBuffer:async()=>new Uint8Array(32).fill(1).buffer}];
  const btn = {disabled:false};
  await api.importZhanluAuth(btn);
  const imported = calls.find(c=>c.url.includes('/zhanlu/accounts/import'));
  assert.ok(imported, 'import form sends to panel endpoint');
  const payload = JSON.parse(imported.opts.body);
  assert.ok(payload.auth.accounts);
  assert.equal(payload.master_key.length,44);
  assert.equal(input.value,''); assert.equal(key.value,''); assert.equal(btn.disabled,false);
  await api.setZhanluEnabled({checked:true});
  assert.ok(calls.some(c=>c.url.includes('/settings/save') && JSON.parse(c.opts.body).zhanlu.enabled));
  console.log('zhanlu UI assertions passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
