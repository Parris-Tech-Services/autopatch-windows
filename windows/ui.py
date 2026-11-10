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
        "host": inventory.get("hostname") or "this PC", "os": inventory.get("os") or "Windows",
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
footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:1.5rem}ul{margin:.4rem 0 0;padding-left:1.2rem}
</style></head><body><main>
<h1>AutoPatch</h1><p class="sub" id="sub">Checking this PC. Nothing is changed.</p>
<div class="card" id="scan"><h2><span class="spin"></span>Scanning</h2><ul class="steps" id="steps"></ul><p class="fix">The Windows Update check can take a minute or two. This page updates by itself.</p></div>
<div id="out" hidden></div>
<footer><div id="ver"></div>Read-only. Nothing is installed or changed. {{PATCHER}} does the patching. This page only works on this PC.</footer>
</main><script>
const $=id=>document.getElementById(id);
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function render(v){
  const out=$("out");out.textContent="";
  const col=v.score==null?"var(--unk)":v.score>=80?"var(--ok)":v.score>=50?"var(--warn)":"var(--bad)";
  const hero=el("div","card hero"),ring=el("div","ring",v.score==null?"?":String(v.score));ring.style.borderColor=col;
  const facts=el("div","facts");
  for(const [a,b] of [["Computer",v.host],["Windows",v.os.replace("Microsoft ","").replace(/ 10\.0\.\d+/,"")],["Security updates waiting",v.pending==null?"Could not read":String(v.pending)],["Restart needed",v.reboot==null?"Could not read":v.reboot?"Yes":"No"]]){
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
    b.onclick=async()=>{b.disabled=true;try{const r=await (await fetch("/api/elevate",{method:"POST"})).json();
      b.textContent=r.started?"Approved: the new results open in a new browser tab":"Not approved or not available. You can also right-click the exe and choose Run as administrator."}catch(e){b.textContent="Could not start. Right-click the exe and choose Run as administrator."}};
    a.append(b);out.append(a)}
  const g=el("div","card");g.append(el("h2","","Automatic patching"));
  g.append(el("span","pill",v.gate.decision==="ALLOW"?"Safe to run now":"Not switched on yet"));
  const ul=el("ul");for(const r of v.gate.reasons)ul.append(el("li","",r));g.append(ul);out.append(g);
  out.hidden=false;$("scan").hidden=true;$("sub").textContent="Scan finished. Nothing was changed.";
}
async function poll(){
  try{const s=await (await fetch("/api/state")).json();
    window.__admin=!!s.admin;window.__can=s.can_elevate;if(s.admin)$("sub").textContent="Running with elevated rights. Reading only.";if(s.version)$("ver").textContent=(s.product||"AutoPatch")+", version "+s.version;const ul=$("steps");ul.textContent="";for(const st of s.steps){ul.append(el("li",st.state,(st.state==="done"?"✓ ":st.state==="on"?"… ":"")+st.name))}
    if(s.error){$("scan").textContent="";$("scan").append(el("h2","","Something went wrong"),el("p","",s.error),el("p","fix","Close this window and run it again. If it keeps happening, tell Claude the message above."));return}
    if(s.view){render(s.view);return}
  }catch(e){}
  setTimeout(poll,1500)}
poll();
</script></body></html>"""
