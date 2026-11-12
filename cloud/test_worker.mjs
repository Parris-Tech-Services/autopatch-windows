import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
// Workers expose Web Crypto globally; older Node runners may not.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import worker from './worker.js';

// In-memory, zero-network D1 imitation covering the actual SQL used by Worker.
class D1 {
  constructor() { this.devices = new Map(); this.rates = new Map(); }
  prepare(sql) {
    const db = this;
    return {
      async first() { return this.bind().first(); },
      async all() {
        if (sql.includes('FROM device_registrations ORDER BY created_utc DESC LIMIT 200')) {
          return { results: Array.from(db.devices.values()).map(d=>({
            device_id:d.device_id,hostname:d.hostname,device_class:'windows',
            registration_state:d.registration_state,owner_attested:d.owner_attested||0,
            owner_attested_utc:d.owner_attested_utc||null,created_utc:d.created_utc,last_seen_utc:d.last_seen_utc
          })).slice(0,200) };
        }
        throw Error('Unhandled all query: '+sql);
      },
      bind(...values) {
        return {
          async first() {
            if (sql.includes('FROM device_registrations WHERE device_id=? AND credential_sha256=?')) {
              const found = db.devices.get(values[0]);
              if (!found || found.credential_sha256 !== values[1]) return null;
              return {device_id: found.device_id, hostname: found.hostname,
                registration_state: found.registration_state,owner_attested:found.owner_attested||0,
                created_utc: found.created_utc, last_seen_utc: found.last_seen_utc};
            }
            if (sql.includes('SELECT credential_sha256,hostname,registration_state')) {
              const found = db.devices.get(values[0]);
              return found ? {credential_sha256: found.credential_sha256,
                hostname: found.hostname, registration_state: found.registration_state} : null;
            }
            if (sql.includes('SELECT requests FROM daily_rate_counts')) {
              return {requests: db.rates.get(values.join(':')) || 0};
            }
            if (sql.includes('SELECT count(*) AS n FROM device_registrations')) {
              return {n: db.devices.size};
            }
            throw Error('Unhandled query: ' + sql);
          },
          async run() {
            if (sql.startsWith('INSERT INTO daily_rate_counts')) {
              const key = values.join(':'); db.rates.set(key, (db.rates.get(key)||0)+1); return {};
            }
            if (sql.startsWith('INSERT INTO device_registrations')) {
              db.devices.set(values[0],{device_id:values[0],hostname:values[1],
                registration_state:'unverified',owner_attested:0,credential_sha256:values[3],
                created_utc:'2026-11-11',last_seen_utc:'2026-11-11'});
              return {};
            }
            if (sql.startsWith('UPDATE device_registrations SET last_seen_utc='))return {};
            if (sql.startsWith('UPDATE device_registrations SET owner_attested=')) {
              const d=db.devices.get(values[0]);
              if(!d||d.registration_state!=='unverified')return {meta:{changes:0}};
              d.owner_attested=1;d.owner_attested_utc='2026-11-13';
              return {meta:{changes:1}};
            }
            throw Error('Unhandled update: ' + sql);
          }
        };
      }
    };
  }
}
const base = 'https://autopatch-cloud-enrolment.example.test';
const secret = 'X'.repeat(48);
const data = {device_id:'windows-local0123',hostname:'PERSONAL-DESKTOP',
              device_class:'windows',credential:secret};
const request = (path, method='GET', payload, extra={}) => {
  const headers = {...extra};
  let body;
  if (payload) {headers['Content-Type']='application/json'; body=JSON.stringify(payload);}
  return new Request(base+path,{method,headers,body});
};
const call = (db,path,method='GET',payload,extra={},ctx,ownerEmail) =>
  worker.fetch(request(path,method,payload,extra),{DB:db,OWNER_EMAIL:ownerEmail},ctx);

test('cloud health and public docs do not expose admin access', async () => {
  const db=new D1();
  let r=await call(db,'/healthz');
  assert.equal(r.status,200,await r.clone().text());
  assert.equal((await r.json()).patching_enabled,false);
  r=await call(db,'/v1/devices');
  assert.equal(r.status,403);
  r=await call(db,'/admin');
  assert.equal(r.status,403);
  r=await call(db,'/');
  assert.equal(r.status,200);
  const page=await r.text();
  assert.match(page,/Cloud service online/);
  assert.doesNotMatch(page,/credential_sha256/);
});

test('registration is read-only; idempotent with same credential, mismatch rejected', async () => {
  const db=new D1();
  let r=await call(db,'/v1/enrol','POST',data);
  assert.equal(r.status,200,await r.clone().text());
  let first=await r.json();
  assert.equal(first.status,'CLOUD_REGISTERED_UNVERIFIED');
  assert.equal(first.auto_patch,false);
  assert.equal(first.remote_control,false);
  assert.equal(first.owner_verified,false);
  assert.equal(db.devices.size,1);
  assert.notEqual(db.devices.get(data.device_id).credential_sha256,secret);
  r=await call(db,'/v1/enrol','POST',data);
  assert.equal(r.status,200,await r.clone().text());
  assert.equal(db.devices.size,1);
  r=await call(db,'/v1/enrol','POST',{...data,credential:'Y'.repeat(48)});
  assert.equal(r.status,409);
  assert.equal(db.devices.size,1);
});

test('device status and heartbeat require its random bearer credential',async()=>{
  const db=new D1();
  await call(db,'/v1/enrol','POST',data);
  let r=await call(db,'/v1/device');
  assert.equal(r.status,401);
  r=await call(db,'/v1/device','GET',undefined,
    {'X-AutoPatch-Device-ID':data.device_id,Authorization:'Bearer '+'Y'.repeat(48)});
  assert.equal(r.status,401);
  const headers={'X-AutoPatch-Device-ID':data.device_id,Authorization:'Bearer '+secret};
  r=await call(db,'/v1/device','GET',undefined,headers);
  assert.equal(r.status,200);
  const st=await r.json();
  assert.equal(st.status,'CLOUD_REGISTERED_UNVERIFIED');
  assert.equal(st.owner_verified,false);
  assert.equal(st.auto_patch,false);
  assert.ok(!JSON.stringify(st).includes(secret));
  r=await call(db,'/v1/heartbeat','POST',{},headers);
  assert.equal(r.status,200);
});

test('reject cross-site/browser registration and privileged injected fields',async()=>{
  const db=new D1();
  let r=await call(db,'/v1/enrol','POST',data,{'Origin':'https://evil.test'});
  assert.equal(r.status,403);
  r=await call(db,'/v1/enrol','POST',{...data,auto_patch:true});
  assert.equal(r.status,422);
  r=await call(db,'/v1/enrol','POST',{...data,device_class:'linux'});
  assert.equal(r.status,422);
  assert.equal(db.devices.size,0);
});

test('registration rate limit blocks after 20 new registrations per source IP',async()=>{
  const db=new D1();
  for(let i=0;i<20;i++){
    const r=await call(db,'/v1/enrol','POST',{...data,device_id:'windows-test'+String(i).padStart(4,'0')});
    assert.equal(r.status,200);
  }
  const extra=await call(db,'/v1/enrol','POST',{...data,device_id:'windows-extra999'});
  assert.equal(extra.status,429);
  assert.equal(db.devices.size,20);
});

test('dashboard fails closed without Access identity and owner secret',async()=>{
  const db=new D1();
  await call(db,'/v1/enrol','POST',data);
  const trusted={access:{getIdentity:async()=>({email:'owner@example.test'})}};
  for(const path of ['/dashboard','/v1/admin/devices']){
    let r=await call(db,path);
    assert.equal(r.status,403);
    r=await call(db,path,'GET',undefined,{},trusted);
    assert.equal(r.status,403,'without owner secret must fail closed');
    r=await call(db,path,'GET',undefined,{},trusted,'someoneelse@example.test');
    assert.equal(r.status,403,'wrong owner email must fail closed');
    const forged={'Cf-Access-Jwt-Assertion':'forged','Cf-Access-Authenticated-User-Email':'owner@example.test'};
    r=await call(db,path,'GET',undefined,forged,undefined,'owner@example.test');
    assert.equal(r.status,403,'untrusted request headers must never authorise');
  }
});

test('verified Access owner sees read-only fleet without credential hashes',async()=>{
  const db=new D1();
  await call(db,'/v1/enrol','POST',data);
  const context={access:{getIdentity:async()=>({email:'owner@example.test'})}};
  let r=await call(db,'/dashboard','GET',undefined,{},context,'owner@example.test');
  assert.equal(r.status,200);
  assert.match(r.headers.get('Content-Security-Policy'),/default-src 'none'/);
  assert.match(r.headers.get('Cache-Control'),/no-store/);
  const page=await r.text();
  assert.match(page,/PERSONAL-DESKTOP/);
  assert.match(page,/Automatic patching/);
  assert.match(page,/Off/);
  assert.doesNotMatch(page,/credential_sha256/);
  assert.doesNotMatch(page,/X{48}/);
  r=await call(db,'/v1/admin/devices','GET',undefined,{},context,'owner@example.test');
  assert.equal(r.status,200);
  const inventory=await r.json();
  assert.equal(inventory.count,1);
  assert.equal(inventory.patching_enabled,false);
  assert.equal(inventory.devices[0].registration_state,'unverified');
  assert.equal('credential_sha256' in inventory.devices[0],false);
});

test('unsafe hostnames are escaped in private dashboard',async()=>{
  const db=new D1();
  db.devices.set('windows-safe',{device_id:'windows-safe',hostname:'<script>alert(1)</script>',
    registration_state:'unverified',created_utc:'2026-11-11',last_seen_utc:'2026-11-11',
    credential_sha256:'stored-secret'});
  const ctx={access:{getIdentity:async()=>({email:'owner@example.test'})}};
  const response=await call(db,'/dashboard','GET',undefined,{},ctx,'owner@example.test');
  assert.equal(response.status,200);
  const html=await response.text();
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>alert/);
  assert.doesNotMatch(html,/stored-secret/);
});
