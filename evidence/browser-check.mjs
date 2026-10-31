import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const origin = fs.readFileSync(path.join(root, 'browser-ready.txt'), 'utf8').trim();
assert.equal(new URL(origin).hostname, 'localhost', 'only the local synthetic fixture is allowed');
const results = path.join(root, 'results');
fs.mkdirSync(results, {recursive:true});
const profile = fs.mkdtempSync(path.join(root, 'chrome-qa-'));
const executable = process.env.CHROME_BIN || (process.platform === 'win32'
  ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' : 'google-chrome');
const chrome = spawn(executable, [
  '--headless=new', '--disable-background-networking', '--disable-sync', '--no-first-run',
  '--no-default-browser-check', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, 'about:blank'
], { windowsHide: true, stdio: ['ignore','ignore','pipe'] });
const stderr = fs.createWriteStream(path.join(results,'chrome-stderr.log'));
chrome.stderr.pipe(stderr);
let chromeError;
chrome.on('error', error => { chromeError = error; });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let ws, sequence = 0;
const pending = new Map();
const sessions = [], network = [];
function safeUrl(value) {
  try { const u = new URL(value); return u.origin+u.pathname; } catch { return value; }
}
function call(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 20000);
    pending.set(id, { resolve, reject, timeout });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
async function page(context) {
  const {targetId} = await call('Target.createTarget', {url:'about:blank',browserContextId:context});
  const {sessionId} = await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);
  await call('Network.enable',{},sessionId);
  sessions.push(sessionId);
  return sessionId;
}
async function evaluate(sessionId, expression) {
  const v = await call('Runtime.evaluate',{expression,returnByValue:true},sessionId);
  if(v.exceptionDetails) throw new Error(JSON.stringify(v.exceptionDetails));
  return v.result.value;
}
async function navigate(sessionId,url,title) {
  const n = await call('Page.navigate',{url},sessionId);
  assert.ok(!n.errorText, n.errorText);
  await waitTitle(sessionId,title);
}
async function waitTitle(sessionId,title) {
  let lastError;
  for(let i=0;i<120;i++) {
    try { if(await evaluate(sessionId,'document.title')===title) return; } catch(error) { lastError = String(error); }
    await pause(100);
  }
  const actual = await evaluate(sessionId,'({title:document.title,type:document.contentType,url:location.origin+location.pathname})');
  throw new Error(`Expected title ${title}; got ${JSON.stringify(actual)}; last evaluation error: ${lastError || 'none'}`);
}
async function finishFromIdp(sessionId) {
  // Follow the link in the IdP document. A fresh CDP navigation would not
  // establish the cross-site initiator needed to exercise SameSite behavior.
  await evaluate(sessionId,'document.querySelector("#finish").click()');
  await waitTitle(sessionId,'Signed in');
}
async function count() { return (await (await fetch(origin+'/__qa/count')).json()).token_requests; }
async function capture(sessionId,name) {
  const {data} = await call('Page.captureScreenshot',{format:'png'},sessionId);
  fs.writeFileSync(path.join(root,name),Buffer.from(data,'base64'));
}
const checks=[];
try {
  const active = path.join(profile,'DevToolsActivePort');
  for(let i=0;i<200&&!fs.existsSync(active);i++) {
    if(chromeError) throw chromeError;
    if(chrome.exitCode!==null) throw new Error(`Chrome exited before CDP: ${chrome.exitCode}`);
    await pause(100);
  }
  const [port,endpoint] = fs.readFileSync(active,'utf8').trim().split(/\r?\n/);
  ws = new WebSocket(`ws://127.0.0.1:${port}${endpoint}`);
  await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
  ws.addEventListener('message',e=>{
    const data=JSON.parse(e.data), item=pending.get(data.id);
    if(!item) {
      const p=data.params;
      if(data.method==='Network.responseReceived' && p.type==='Document') {
        network.push({sessionId:data.sessionId,event:data.method,url:safeUrl(p.response.url),status:p.response.status,mimeType:p.response.mimeType});
      } else if(data.method==='Network.loadingFailed') {
        network.push({sessionId:data.sessionId,event:data.method,errorText:p.errorText,blockedReason:p.blockedReason});
      }
      if(network.length>100)network.shift();
      return;
    }
    pending.delete(data.id);clearTimeout(item.timeout);
    if(data.error)item.reject(new Error(JSON.stringify(data.error)));else item.resolve(data.result);
  });
  const version=await call('Browser.getVersion');
  const a=(await call('Target.createBrowserContext')).browserContextId;
  const b=(await call('Target.createBrowserContext')).browserContextId;
  const pa=await page(a), pb=await page(b);
  await navigate(pa,origin+'/gw/oidc/login/corp','Mock IdP');
  const cookies=(await call('Storage.getCookies',{browserContextId:a})).cookies.filter(c=>c.name.startsWith('zc_oidc_'));
  assert.equal(cookies.length,1);assert.equal(cookies[0].httpOnly,true);assert.equal(cookies[0].sameSite,'Lax');assert.equal(cookies[0].path,'/');
  await finishFromIdp(pa);
  assert.ok((await evaluate(pa,'document.body.innerText')).includes('synthetic-browser-token'));
  assert.equal(await count(),1);
  checks.push('same browser: cross-site IdP return and prefixed callback succeed; one exchange');
  assert.equal((await call('Storage.getCookies',{browserContextId:a})).cookies.filter(c=>c.name.startsWith('zc_oidc_')).length,0);
  checks.push('HttpOnly/Lax/root cookie accepted by Chromium and cleared on success');
  await capture(pa,'browser-same-context.png');
  await navigate(pa,origin+'/gw/oidc/login/corp','Mock IdP');
  const stolen=await evaluate(pa,'document.querySelector("#finish").href');
  await navigate(pb,stolen,'Sign-in not completed');
  assert.ok(!(await evaluate(pb,'document.body.innerText')).includes('synthetic-browser-token'));
  assert.equal(await count(),1);
  checks.push('different browser context: copied callback refused; zero extra exchanges');
  await capture(pb,'browser-other-context.png');
  await navigate(pa,stolen,'Sign-in not completed');assert.equal(await count(),1);
  checks.push('original browser: replay after foreign-context refusal also refused');
  const tab=await page(a);
  await navigate(pa,origin+'/gw/oidc/login/corp','Mock IdP');
  await navigate(tab,origin+'/gw/oidc/login/corp','Mock IdP');
  await finishFromIdp(pa);await finishFromIdp(tab);assert.equal(await count(),3);
  checks.push('two concurrent tabs: both flows finish; each exchanges once');
  const result={timestamp:new Date().toISOString(),browser:version.product,protocol:version.protocolVersion,checks,passed:checks.length,transport:'loopback HTTP; gateway localhost, mock IdP 127.0.0.1; no production accounts'};
  fs.writeFileSync(path.join(root,'browser-receipt.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify(result,null,2));
} catch(error) {
  const pages=[];
  for(const [index,sessionId] of sessions.entries()) {
    try {
      pages.push(await evaluate(sessionId,'({title:document.title,type:document.contentType,url:location.origin+location.pathname,body:document.body?.innerText.slice(0,4000)})'));
      await capture(sessionId,`browser-failure-${index}.png`);
    } catch(diagnosticError) { pages.push({diagnosticError:String(diagnosticError)}); }
  }
  fs.writeFileSync(path.join(results,'browser-failure.json'),JSON.stringify({error:String(error),network,pages,checks},null,2)+'\n');
  throw error;
} finally {
  try { await fetch(origin+'/__qa/stop'); } catch {}
  try { await call('Browser.close'); } catch {}
  if(ws)ws.close();
  if(chrome.exitCode===null)chrome.kill();
}
