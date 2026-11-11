/** AutoPatch Cloud: free-tier read-only device registration.
 * IMPORTANT: Cloud registration does not imply owner verification, fleet
 * authorisation, automatic patching, unattended execution or remote access.
 * Device credentials are random and hashed server-side. No global device list.
 */
const VERSION = "2026-11-11-cloud-v1";
const ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const TOKEN = /^[A-Za-z0-9_-]{40,100}$/;
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: {"Content-Type":"application/json; charset=utf-8",
    "Cache-Control":"no-store", "X-Content-Type-Options":"nosniff",
    "Referrer-Policy":"no-referrer", "Access-Control-Allow-Origin":"null"}
});
const err = (message, status) => json({error:message}, status);
async function sha256(s) {
  const bytes = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b=>b.toString(16).padStart(2,"0")).join("");
}
const html = `<!doctype html><html lang="en"><head>
<meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'">
<title>AutoPatch Cloud</title>
<style>body{background:#0d1423;color:#e8f1ff;font:16px/1.6 system-ui,Segoe UI,sans-serif;margin:0}
main{max-width:720px;margin:7vh auto;padding:2rem}
.card{background:#172338;border:1px solid #30435d;border-radius:22px;padding:2rem}
h1{font-size:2rem;line-height:1.15;margin:0 0 1rem}h2{font-size:1.15rem;margin:1.7rem 0 .3rem}
p{color:#aec0d8}a{color:#91b8ff}small{color:#91a6c3}
.pill{display:inline-block;border-radius:99px;padding:.2rem .75rem;background:#213b48;color:#80dbbe;font-size:.8rem;margin-bottom:1rem}
</style></head><body><main><div class="card"><span class="pill">Cloud service online</span>
<h1>AutoPatch Cloud</h1><p>Your personal device registration service, hosted on Cloudflare.</p>
<h2>Enrol a Windows PC</h2><p>Open the latest AutoPatch Windows app on your own PC, confirm ownership and select <b>Enrol this PC</b>. No phone, Termux or JSON file transfers.</p>
<h2>Safety comes first</h2><p>Device registration is read-only and unverified. It does not start automatic updates, remote access or restarts.</p>
<h2>Dashboard access</h2><p>The private fleet dashboard is not enabled yet. Owner authentication through Cloudflare Access must be configured before any shared device list or patch approvals are available.</p>
<p><a href="https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest">Download AutoPatch Windows</a></p>
<small>AutoPatch Cloud v1 · No remote commands or patch endpoint</small></div></main></body></html>`;
async function readJson(request) {
  const contentType=(request.headers.get("Content-Type")||"").split(";")[0].toLowerCase();
  if(contentType!=="application/json")throw new Error("JSON required");
  if(Number(request.headers.get("Content-Length")||"0")>4096)throw new Error("Payload too large");
  const raw=await request.text();
  if(raw.length>4096)throw new Error("Payload too large");
  const body=JSON.parse(raw);
  if(!body||typeof body!=="object"||Array.isArray(body))throw new Error("Invalid request");
  return body;
}
async function auth(request, env) {
  const id=request.headers.get("X-AutoPatch-Device-ID")||"";
  const authorization=request.headers.get("Authorization")||"";
  const token=authorization.startsWith("Bearer ")?authorization.slice(7):"";
  if(!ID.test(id)||!TOKEN.test(token))return null;
  const digest=await sha256(token);
  const row=await env.DB.prepare("SELECT device_id, hostname, registration_state, created_utc, last_seen_utc FROM device_registrations WHERE device_id=? AND credential_sha256=?").bind(id,digest).first();
  return row||null;
}
export default {
  async fetch(request,env) {
    const u=new URL(request.url);
    if(!env.DB)return err("Cloud database not configured",503);
    if(request.method==="GET"&&(u.pathname==="/"||u.pathname==="/index.html"))
      return new Response(html,{headers:{"Content-Type":"text/html; charset=utf-8",
        "Cache-Control":"no-store", "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options":"nosniff", "Referrer-Policy":"no-referrer"}});
    if(request.method==="GET"&&u.pathname==="/healthz")
      return json({status:"ok",service:"autopatch-cloud",version:VERSION,patching_enabled:false});
    if(request.method==="GET"&&u.pathname==="/v1/device") {
      const row=await auth(request,env);
      if(!row)return err("Device not registered or credential invalid",401);
      return json({device_id:row.device_id,hostname:row.hostname,
        status:row.registration_state==="revoked"?"REVOKED":"CLOUD_REGISTERED_UNVERIFIED",
        cloud_connected:row.registration_state!=="revoked",owner_verified:false,
        auto_patch:false,remote_control:false,created_utc:row.created_utc,last_seen_utc:row.last_seen_utc});
    }
    if(request.method==="POST"&&u.pathname==="/v1/heartbeat") {
      const row=await auth(request,env);
      if(!row||row.registration_state!=="unverified")return err("Device not registered",401);
      await env.DB.prepare("UPDATE device_registrations SET last_seen_utc=datetime('now') WHERE device_id=?").bind(row.device_id).run();
      return json({status:"CLOUD_REGISTERED_UNVERIFIED",auto_patch:false});
    }
    if(request.method==="POST"&&u.pathname==="/v1/enrol") {
      try {
        // The Windows app sends no browser Origin; disallow cross-site
        // browser POSTs to limit CSRF and unwanted browser registrations.
        if(request.headers.has("Origin"))return err("Browser-origin enrolment is not permitted",403);
        const b=await readJson(request);
        if(Object.keys(b).sort().join(",")!=="credential,device_class,device_id,hostname")
          return err("Unsupported fields",422);
        if(!ID.test(b.device_id)||b.device_class!=="windows"||!HOST.test(b.hostname)||!TOKEN.test(b.credential))
          return err("Invalid device identity or credential",422);
        const digest=await sha256(b.credential);
        const found=await env.DB.prepare("SELECT credential_sha256,hostname,registration_state FROM device_registrations WHERE device_id=?").bind(b.device_id).first();
        if(found) {
          if(found.credential_sha256!==digest||found.hostname.toLowerCase()!==b.hostname.toLowerCase()||found.registration_state!=="unverified")
            return err("This device ID is already registered with a different credential",409);
          await env.DB.prepare("UPDATE device_registrations SET last_seen_utc=datetime('now') WHERE device_id=?").bind(b.device_id).run();
        } else {
          const ip=request.headers.get("CF-Connecting-IP")||"unknown";
          const ipHash=await sha256(ip);
          const date=new Date().toISOString().slice(0,10);
          await env.DB.prepare("INSERT INTO daily_rate_counts (date_key,ip_sha256,requests) VALUES (?,?,1) ON CONFLICT(date_key,ip_sha256) DO UPDATE SET requests=requests+1").bind(date,ipHash).run();
          const count=await env.DB.prepare("SELECT requests FROM daily_rate_counts WHERE date_key=? AND ip_sha256=?").bind(date,ipHash).first();
          if(!count||count.requests>20)return err("Daily enrolment limit reached",429);
          const daily=await env.DB.prepare("SELECT count(*) AS n FROM device_registrations WHERE date(created_utc)=date('now')").first();
          if(daily&&daily.n>=500)return err("Enrolment service registration limit reached",429);
          await env.DB.prepare("INSERT INTO device_registrations (device_id,hostname,device_class,credential_sha256) VALUES (?,?,?,?)").bind(b.device_id,b.hostname,b.device_class,digest).run();
        }
        return json({status:"CLOUD_REGISTERED_UNVERIFIED",device_id:b.device_id,
          owner_verified:false,auto_patch:false,remote_control:false,
          dashboard_url:new URL("/",request.url).toString()});
      } catch(ex) {
        if(ex instanceof SyntaxError)return err("Invalid JSON",400);
        if(ex instanceof Error&&/Payload too large/.test(ex.message))return err(ex.message,413);
        if(ex instanceof Error&&/JSON required|Invalid request/.test(ex.message))return err(ex.message,422);
        if(env.TEST_MODE===true)return err("TEST_DIAGNOSTIC: "+(ex instanceof Error?ex.message:String(ex)),503);
        return err("Could not enrol this device",503);
      }
    }
    if(u.pathname.startsWith("/admin")||u.pathname==="/v1/devices")
      return err("Fleet administration is disabled until owner authentication is configured",403);
    return err("Not found",404);
  }
};
