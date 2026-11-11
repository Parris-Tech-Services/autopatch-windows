"""Local status page: one static HTML shell that polls /api/state. All device data is written with
textContent in the browser, never interpolated into HTML, so a hostile PC name cannot inject markup."""

TITLES = {
    "os_supported": ("Windows version still supported", "Windows 10 stopped getting regular security updates on 14 October 2025. Upgrade to Windows 11 if this PC qualifies, or ask your IT team about extended updates."),
    "defender_on": ("Antivirus (Microsoft Defender)", "Turn on Microsoft Defender in Windows Security."),
    "defender_realtime": ("Real-time protection", "Turn on real-time protection in Windows Security."),
    "defender_signatures_fresh": ("Virus definitions up to date", "Open Windows Security and run Check for updates."),
    "firewall_on": ("Firewall", "Turn the Windows firewall on for all networks."),
    "bitlocker_on": ("Disk encryption (BitLocker)", "Turn on BitLocker or Device encryption in Settings."),
    "secure_boot": ("Secure Boot", "Enable Secure Boot in the firmware (BIOS) settings."),
    "tpm_present": ("Security chip (TPM)", "Enable the TPM in the firmware (BIOS) settings."),
    "smbv1_off": ("Old file-sharing protocol (SMBv1) off", "Turn off SMB 1.0 in Windows Features."),
    "uac_on": ("User Account Control", "Turn User Account Control on in Windows Security."),
    "rdp_closed": ("Remote Desktop closed", "Turn off Remote Desktop unless you use it."),
    "apps_current": ("Apps up to date", "Run winget upgrade --all, or update your apps."),
}
UNKNOWN_HINT = "Not verified, so it lowers the score until confirmed. Close the app and run it again with Run as administrator to check it."


def page(patcher):
    """The page for one platform: names the tool that does the real patching."""
    return PAGE.replace("{{PATCHER}}", patcher)


def view(status, score, inventory, gate, titles=None, unknown_hint=None):
    """JSON view model for the page (display labels live here, not in the shared status contract)."""
    checks = []
    for c in status.get("checks", []):
        title, fix = (titles or TITLES).get(c["id"], (c["id"], ""))
        checks.append({"title": title, "state": c["state"], "detail": c["detail"],
                       "fix": (unknown_hint or UNKNOWN_HINT) if c["state"] == "unknown" else fix})
    pending = status["updates"].get("pending_security")
    return {
        "host": inventory.get("hostname") or "this PC", "os": inventory.get("os") or "this system",
        "patch": inventory.get("patch_level") or "unknown", "pending": pending,
        "reboot": status["updates"].get("reboot_required"), "score": score, "checks": checks,
        "gate": {"decision": gate["decision"], "reasons": gate["reasons"]},
    }


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoPatch</title><style>
:root{--bg:#f4f6fa;--card:#fff;--text:#1b2433;--muted:#5d6b82;--line:#e3e8f0;--ok:#168a45;--warn:#b7791f;--bad:#c53030;--unk:#6b7a90;--accent:#1a56db}
@media(prefers-color-scheme:dark){:root{--bg:#0f1624;--card:#18223a;--text:#e8eef9;--muted:#9fb0cc;--line:#26324d;--ok:#4cc38a;--warn:#e0b050;--bad:#f27070;--unk:#8fa0bb;--accent:#6ea0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:46rem;margin:0 auto;padding:1.5rem 1rem 3rem}h1{font-size:1.4rem;margin:0}.sub{color:var(--muted);margin:.2rem 0 1.2rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.1rem 1.2rem;margin:0 0 1rem}
.hero{display:flex;gap:1.2rem;align-items:center;flex-wrap:wrap}.ring{width:7rem;height:7rem;border-radius:50%;display:grid;place-items:center;font-size:2rem;font-weight:700;border:.5rem solid var(--unk);flex:none}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.8rem;flex:1}.fact b{display:block;font-size:1.25rem}.fact span{color:var(--muted);font-size:.85rem}
h2{font-size:1rem;margin:0 0 .6rem}.row{display:flex;gap:.7rem;padding:.55rem 0;border-top:1px solid var(--line)}.row:first-of-type{border-top:0}
.dot{flex:none;width:1.4rem;height:1.4rem;border-radius:50%;display:grid;place-items:center;color:#fff;font-size:.85rem;font-weight:700}
.pass{background:var(--ok)}.fail{background:var(--bad)}.unknown{background:var(--unk)}.fix{color:var(--muted);font-size:.9rem}
.steps li{list-style:none;padding:.25rem 0;color:var(--muted)}.steps li.on{color:var(--text);font-weight:600}.steps li.done{color:var(--ok)}
.spin{display:inline-block;width:1rem;height:1rem;border:.2rem solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:s 1s linear infinite;vertical-align:-.15rem;margin-right:.5rem}@keyframes s{to{transform:rotate(360deg)}}
.btn{font:inherit;font-weight:600;padding:.7rem 1.1rem;border:0;border-radius:10px;background:var(--accent);color:#fff;cursor:pointer}.btn:disabled{opacity:.7;cursor:default}
.pill{display:inline-block;padding:.15rem .6rem;border-radius:99px;font-size:.85rem;font-weight:600;background:var(--line)}

.enrol{position:relative;overflow:hidden;border-color:var(--accent);background:linear-gradient(145deg,var(--card),var(--bg))}
.enrol:before{content:"";position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,var(--accent),var(--ok))}
.enrol h2{font-size:1.18rem;margin-bottom:.1rem}
.enrol .lead{color:var(--muted);margin:.2rem 0 1rem}
.enrol .phase{border-top:1px solid var(--line);padding:1rem 0 .5rem}
.enrol .phase strong{display:block;margin-bottom:.35rem}
.enrol .num{display:inline-grid;place-items:center;background:var(--accent);color:#fff;width:1.6rem;height:1.6rem;border-radius:50%;font-weight:700;font-size:.85rem;margin-right:.35rem}
.enrol .help{font-size:.88rem;color:var(--muted);line-height:1.55;margin:.35rem 0 .7rem}
.enrol code{display:block;font: .78rem/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-word;padding:.6rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);white-space:pre-wrap;margin:.4rem 0}
.enrol label{display:flex;gap:.65rem;align-items:flex-start;cursor:pointer;font-size:.93rem;line-height:1.5}
.enrol label input{width:1.1rem;height:1.1rem;margin-top:.2rem;flex:none;accent-color:var(--accent)}
.enrol input[type=file]{max-width:100%;display:block;margin:.5rem 0}
.enrol button{margin:.3rem .5rem .3rem 0}
.enrol .outline{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.enrol .hint{border-radius:10px;background:var(--bg);padding:.65rem .8rem;color:var(--text);font-size:.88rem}
.enrol .ok-text{color:var(--ok)}.enrol .error-text{color:var(--bad)}
.enrol .phase a{color:var(--accent)}
@media(max-width:440px){.enrol .btn{width:100%;margin:.3rem 0}}
footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:1.5rem}ul{margin:.4rem 0 0;padding-left:1.2rem}
</style></head><body><main>
<h1>AutoPatch</h1><p class="sub" id="sub">Checking this computer. Nothing is changed.</p>

<section class="card enrol" id="enrol" aria-label="Enrol this PC" hidden>
  <h2>Enrol this PC <span class="pill">Read-only</span></h2>
  <p class="lead">Connect your personal Windows computer to your private AutoPatch inventory. No updates, reboots or system settings are changed.</p>
  <p class="hint" id="enrolStatus" role="status" aria-live="polite">Checking enrolment…</p>
  <div class="phase">
    <strong><span class="num">1</span> Confirm ownership and prepare</strong>
    <p class="help">This computer's enrolment ID: <b id="enrolId"></b>. Use this same ID on your trusted phone.</p>
    <label><input type="checkbox" id="ownThisPc">I personally own this PC, am authorised to enrol it, and it is not employer-, school- or client-managed.</label>
    <button class="btn" id="prepareEnrol" disabled>Download enrolment file</button>
  </div>
  <div class="phase">
    <strong><span class="num">2</span> Approve on your trusted phone</strong>
    <p class="help">Move the downloaded inventory JSON to your trusted phone. From the existing private AutoPatch AI folder in Termux, run these steps. Keep the invitation token private.</p>
    <code id="phoneSteps"></code>
    <button class="btn outline" id="copySteps">Copy phone steps</button>
    <p class="help">For the <code style="display:inline;padding:0;border:0;background:none">approve</code> step, substitute your locally generated one-time invitation token and the path where you put the downloaded inventory file. The phone must approve; this PC cannot approve itself.</p>
  </div>
  <div class="phase">
    <strong><span class="num">3</span> Import your approved receipt</strong>
    <p class="help">Copy the phone's <b>approved-device.json</b> back to this PC. Import it here; the app saves only this PC's read-only receipt in your Windows profile.</p>
    <input type="file" id="approvalFile" accept=".json,application/json" aria-label="Approved device receipt">
    <button class="btn" id="importApproval" disabled>Import approval</button>
    <p class="help">An imported receipt is checked against this device, but not cryptographically verified with your phone. Your phone remains the authoritative registry. Automatic patching stays disabled.</p>
    <p class="help"><a href="https://github.com/Parris-Tech-Services/autopatch-windows/blob/main/PATCH_ENROLMENT.md" target="_blank" rel="noopener noreferrer">Full enrolment guide</a></p>
  </div>
  <p id="enrolAction" class="hint" aria-live="polite">Ready to prepare.</p>
</section>
<div class="card" id="scan"><h2><span class="spin"></span>Scanning</h2><ul class="steps" id="steps"></ul><div id="live" class="fix"></div><p class="fix">The update check can take a minute or two. This page updates by itself.</p></div>
<div id="out" hidden></div>
<footer><div id="ver"></div>The security scan reads only. Enrolment only saves a local read-only approval file. No patches or restarts. {{PATCHER}} does the patching.</footer>
</main><script>
const $=id=>document.getElementById(id);
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}

async function enrolPost(path,body){
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const data=await response.json();
  if(!response.ok)throw Error(data.error||"Enrolment request failed");
  return data;
}
function enrolNotice(message,isError){
  const p=$("enrolAction");p.textContent=message;p.className="hint "+(isError?"error-text":"ok-text");
}
function phoneCommands(id){
  return "python3 devices/enroll.py invite --device-id "+id+" --device-class windows --owner joshualparris\n"+
         "python3 devices/enroll.py approve --token '<YOUR_LOCAL_TOKEN>' --inventory ./inventory.json\n"+
         "python3 devices/enroll.py export --device-id "+id+" --out ./approved-device.json";
}
async function initEnrol(){
  let data;
  try{
    const res=await fetch("/api/enrol",{cache:"no-store"});
    if(!res.ok)return;data=await res.json();
  }catch(e){return}
  $("enrol").hidden=false;
  $("enrolId").textContent=data.device_id;
  $("phoneSteps").textContent=phoneCommands(data.device_id);
  const status=$("enrolStatus");
  if(data.status==="LOCAL_RECEIPT_IMPORTED"){
    status.textContent="Approval receipt imported for "+data.hostname+". Read-only inventory only; phone authenticity not independently verified.";
    status.className="hint ok-text";
  }else{
    status.textContent="Not enrolled yet · "+data.hostname+" · No automatic patching";
    status.className="hint";
  }
  const owner=$("ownThisPc"),prepare=$("prepareEnrol"),pick=$("approvalFile"),upload=$("importApproval");
  const update=()=>{prepare.disabled=!owner.checked;upload.disabled=!owner.checked||!pick.files.length};
  owner.addEventListener("change",update);pick.addEventListener("change",update);
  prepare.addEventListener("click",async()=>{
    prepare.disabled=true;enrolNotice("Collecting a read-only device inventory…",false);
    try{
      const result=await enrolPost("/api/enrol/request",{confirmed_personal:owner.checked});
      const blob=new Blob([JSON.stringify(result.inventory,null,2)+"\n"],{type:"application/json"});
      const url=URL.createObjectURL(blob),a=document.createElement("a");
      a.href=url;a.download=result.filename;document.body.append(a);a.click();a.remove();
      setTimeout(()=>URL.revokeObjectURL(url),2000);
      enrolNotice("Inventory downloaded. Transfer it privately to your phone for approval.",false);
    }catch(e){enrolNotice(e.message,true)}
    finally{update()}
  });
  upload.addEventListener("click",async()=>{
    upload.disabled=true;enrolNotice("Checking this device's approval receipt…",false);
    try{
      const file=pick.files[0];if(!file||file.size>16384)throw Error("Choose an approved-device.json file under 16 KB.");
      const receipt=JSON.parse(await file.text());
      const result=await enrolPost("/api/enrol/import",{confirmed_personal:owner.checked,receipt});
      status.textContent="Read-only approval receipt imported for "+result.hostname+". Automatic patching remains disabled.";
      status.className="hint ok-text";
      enrolNotice("Saved to this computer's user profile. Your phone remains the authoritative enrolment record.",false);
      pick.value="";
    }catch(e){enrolNotice(e.message,true)}
    finally{update()}
  });
  $("copySteps").addEventListener("click",async()=>{
    try{await navigator.clipboard.writeText($("phoneSteps").textContent);
      enrolNotice("Phone commands copied. Keep the one-time token private.",false);
    }catch(e){enrolNotice("Clipboard unavailable. Select and copy the commands above.",true)}
  });
  if(location.hash==="#enrol")setTimeout(()=>$("enrol").scrollIntoView({behavior:"smooth",block:"start"}),150);
}
initEnrol();

function render(v){
  const out=$("out");out.textContent="";
  const col=v.score==null?"var(--unk)":v.score>=80?"var(--ok)":v.score>=50?"var(--warn)":"var(--bad)";
  const hero=el("div","card hero"),ring=el("div","ring",v.score==null?"?":String(v.score));ring.style.borderColor=col;
  const facts=el("div","facts");
  for(const [a,b] of [["Computer",v.host],["System",v.os.replace("Microsoft ","").replace(/ 10\.0\.\d+/,"")],["Security updates waiting",v.pending==null?"Could not read":String(v.pending)],["Restart needed",v.reboot==null?"Could not read":v.reboot?"Yes":"No"]]){
    const f=el("div","fact");f.append(el("b","",b),el("span","",a));facts.append(f)}
  hero.append(ring,facts);out.append(hero);
  const groups=[["fail","Needs attention"],["unknown","Could not read"],["pass","Looks good"]];
  for(const [s,t] of groups){const items=v.checks.filter(c=>c.state===s);if(!items.length)continue;
    const card=el("div","card");card.append(el("h2","",t+" ("+items.length+")"));
    for(const c of items){const r=el("div","row");r.append(el("div","dot "+s,s==="pass"?"✓":s==="fail"?"✕":"?"));
      const b=el("div");b.append(el("div","",c.title));if(s!=="pass"){if(c.detail)b.append(el("div","fix","What I read: "+c.detail));if(c.fix)b.append(el("div","fix",c.fix))}r.append(b);card.append(r)}
    out.append(card)}
  if(v.checks.some(c=>c.state==="unknown")&&!window.__admin&&window.__can!==false){
    const a=el("div","card");a.append(el("h2","","Check the items it could not read"));
    a.append(el("p","fix","Some checks need administrator rights. Windows will ask you to approve. The app still only reads and changes nothing."));
    const b=el("button","btn","Re-check with administrator rights");
    b.onclick=async()=>{b.disabled=true;b.textContent="Waiting for you to answer the Windows permission prompt...";
      try{await fetch("/api/elevate",{method:"POST"});
        for(let i=0;i<180;i++){await new Promise(r=>setTimeout(r,1000));const s=await (await fetch("/api/state")).json();
          if(s.elevation==="started"){b.textContent="Approved: the new results open in a new browser tab";return}
          if(s.elevation==="declined"){b.textContent="Not approved, so nothing changed. You can also right-click the exe and choose Run as administrator.";return}}
        b.textContent="Still waiting. Check for a Windows permission prompt behind other windows."
      }catch(e){b.textContent="Could not start. Right-click the exe and choose Run as administrator."}};
    a.append(b);out.append(a)}
  const g=el("div","card");g.append(el("h2","","Automatic patching"));
  g.append(el("span","pill",v.gate.decision==="ALLOW"?"Safe to run now":"Not switched on yet"));
  const ul=el("ul");for(const r of v.gate.reasons)ul.append(el("li","",r));g.append(ul);out.append(g);
  out.hidden=false;$("scan").hidden=true;$("sub").textContent="Scan finished. Nothing was changed.";
}
async function poll(){
  try{const s=await (await fetch("/api/state")).json();
    window.__admin=!!s.admin;window.__can=s.can_elevate;if(s.admin)$("sub").textContent="Running with elevated rights. Reading only.";if(s.version)$("ver").textContent=(s.product||"AutoPatch")+", version "+s.version;const ul=$("steps");ul.textContent="";for(const st of s.steps){ul.append(el("li",st.state,(st.state==="done"?"✓ ":st.state==="on"?"… ":"")+st.name))}
    const live=$("live");live.textContent="";
    if(s.current){live.append(el("div","",("Now running: "+s.current.label+" ("+s.current.seconds+" s)")),el("code","fix",s.current.cmd))}
    for(const h of (s.history||[]).slice().reverse()){live.append(el("div","fix",(h.rc===0||h.rc===100?"✓ ":h.rc===124?"⏱ timed out: ":h.rc===127?"– not installed: ":"· ")+h.label+" ("+h.seconds+" s)"))}
    if(s.log_file&&(s.current||(s.history||[]).length))live.append(el("div","fix","Log file: "+s.log_file))
    if(s.error){$("scan").textContent="";$("scan").append(el("h2","","Something went wrong"),el("p","",s.error),el("p","fix","Close this window and run it again. If it keeps happening, tell Claude the message above."));return}
    if(s.view){render(s.view);return}
  }catch(e){}
  setTimeout(poll,1500)}
poll();
</script></body></html>"""
