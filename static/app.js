const SUPABASE_URL="https://ubldspvbpejtnxniqvne.supabase.co";
const SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVibGRzcHZicGVqdG54bmlxdm5lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI5ODU2OTEsImV4cCI6MjA5ODU2MTY5MX0.p9XbrjMnQuHmdk1erB5wWrpnw4D5APpdxoe-M0S2-10";
const sb=supabase.createClient(SUPABASE_URL,SUPABASE_ANON_KEY);
let session=null,currentPid=null;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const AH=(json=true)=>{const h={"Authorization":"Bearer "+session.access_token};if(json)h["Content-Type"]="application/json";return h;};

function tab(t){
  document.getElementById("tab-file").style.display=t==="file"?"block":"none";
  document.getElementById("tab-text").style.display=t==="text"?"block":"none";
  document.getElementById("tab-github").style.display=t==="github"?"block":"none";
}

document.getElementById("btnTabFile").addEventListener("click",()=>tab("file"));
document.getElementById("btnTabText").addEventListener("click",()=>tab("text"));
document.getElementById("btnTabGithub").addEventListener("click",()=>tab("github"));
document.getElementById("btnDemo").addEventListener("click",()=>runText(false));
document.getElementById("saveBtn").addEventListener("click",()=>runText(true));
document.getElementById("btnGithub").addEventListener("click",()=>runGithub());

async function refresh(){
  const {data}=await sb.auth.getSession();session=data.session;
  const bar=document.getElementById("authbar");
  if(session){bar.innerHTML=`<div class="muted">Signed in as ${esc(session.user.email)} <button class="sm" id="lo">Logout</button></div>`;
    document.getElementById("lo").onclick=logout;
    document.getElementById("saveBtn").innerText="Generate + Save";}
  else{bar.textContent="";document.getElementById("saveBtn").innerText="Sign in to Save + Review";}
}
async function login(){await sb.auth.signInWithOAuth({provider:"google",options:{redirectTo:location.origin}});}
async function logout(){await sb.auth.signOut();currentPid=null;refresh();
  document.getElementById("results").innerHTML="";document.getElementById("dashboard").innerHTML="";}

const drop=document.getElementById("drop"),fileInput=document.getElementById("fileInput");
drop.onclick=()=>fileInput.click();
drop.ondragover=e=>{e.preventDefault();drop.style.background="#f0f8ff";};
drop.ondragleave=()=>drop.style.background="";
drop.ondrop=e=>{e.preventDefault();drop.style.background="";handleFile(e.dataTransfer.files[0]);};
fileInput.onchange=e=>handleFile(e.target.files[0]);

async function handleFile(file){
  if(!file)return;
  if(!session){alert("Sign in to analyze your config.");return login();}
  const fs=document.getElementById("fstatus");fs.textContent="Analyzing "+file.name+"...";
  const fd=new FormData();fd.append("file",file);
  const nm=document.getElementById("fname").value||file.name;
  const res=await fetch(`/api/generate-from-file?name=${encodeURIComponent(nm)}`,
    {method:"POST",headers:{"Authorization":"Bearer "+session.access_token},body:fd});
  if(!res.ok){const e=await res.json().catch(()=>({}));fs.textContent="Error: "+(e.detail||res.status);return;}
  const out=await res.json();currentPid=out.project_id;fs.textContent="Done.";await loadProject();
}

async function runText(save){
  const body={name:document.getElementById("name").value||"Untitled",
    architecture_description:document.getElementById("desc").value};
  if(save&&!session)return login();
  const url=save?"/api/generate":"/api/demo";
  const headers=save?AH():{"Content-Type":"application/json"};
  document.getElementById("results").textContent="Generating...";
  const res=await fetch(url,{method:"POST",headers,body:JSON.stringify(body)});
  if(!res.ok){const e=await res.json().catch(()=>({}));document.getElementById("results").textContent="Error: "+(e.detail||res.status);return;}
  const out=await res.json();currentPid=out.project_id||null;
  if(currentPid)await loadProject();else renderThreats(out.threat_model,null);
}

async function runGithub(){
  if(!session){alert("Sign in to import from GitHub.");return login();}
  const gs=document.getElementById("ghstatus");
  const url=document.getElementById("ghurl").value.trim();
  const name=document.getElementById("ghname").value||"Untitled";
  if(!url){gs.textContent="Enter a GitHub repo URL.";return;}
  gs.textContent="Importing and analyzing...";
  const res=await fetch("/api/generate-from-github",
    {method:"POST",headers:AH(),body:JSON.stringify({name,repo_url:url})});
  if(!res.ok){const e=await res.json().catch(()=>({}));gs.textContent="Error: "+(e.detail||res.status);return;}
  const out=await res.json();currentPid=out.project_id;gs.textContent="Done.";await loadProject();
}

async function loadProject(){
  if(!currentPid)return;
  const [pRes,sRes]=await Promise.all([
    fetch(`/api/projects/${currentPid}`,{headers:AH(false)}),
    fetch(`/api/projects/${currentPid}/stats`,{headers:AH(false)})]);
  const data=await pRes.json();const stats=await sRes.json();
  renderDashboard(stats,currentPid);
  renderThreats({system_summary:data.project.system_summary,threats:data.threats},currentPid);
}

function renderDashboard(s,pid){
  const open=s.open_risk;
  document.getElementById("dashboard").innerHTML=`
  <div class="card">
    <div class="row" style="justify-content:space-between">
      <h3 style="margin:0">Compliance Readiness</h3>
      <button class="primary" data-pdf="${esc(pid)}">Download Audit PDF</button>
    </div>
    <div class="bar"><span style="width:${s.readiness_score}%"></span></div>
    <p class="muted">${s.readiness_score}% of approved risks resolved
      ${s.accepted===0?'(approve threats below to begin)':''}</p>
    <div class="dash">
      <div class="metric"><b>${s.total_threats}</b>total</div>
      <div class="metric"><b style="color:#f39c12">${s.pending}</b>pending review</div>
      <div class="metric"><b>${s.accepted}</b>approved</div>
      <div class="metric"><b>${s.resolved}</b>resolved</div>
      <div class="metric"><b style="color:#c0392b">${open.Critical}</b>open critical</div>
      <div class="metric"><b style="color:#e67e22">${open.High}</b>open high</div>
    </div>
    <p class="muted">SOC2 controls covered: ${s.soc2_controls_covered.map(esc).join(", ")||"none yet"}</p>
  </div>`;
}

function renderThreats(model,pid){
  let html=`<div class="card"><b>Summary:</b> ${esc(model.system_summary)}</div><h3>Threats</h3>`;
  model.threats.forEach(t=>{
    const canReview=pid&&t.id;
    const st=t.status||'pending';
    html+=`<div class="card threat ${esc(t.severity).toLowerCase()} ${esc(st)}">
      <div class="row"><b>${esc(t.title)}</b>
        <span class="badge b-${esc(st)}">${esc(st)}</span></div>
      <div class="muted">${esc(t.category)} | ${esc(t.severity)} | ${esc(t.affected_component)}</div>
      <div class="soc2">SOC2: ${esc(t.soc2_control||'')}${t.iso27001_control?(' | ISO: '+esc(t.iso27001_control)):''}</div>
      <p>${esc(t.description)}</p>
      <ul>${(t.mitigations||[]).map(m=>`<li>${esc(m.description)}</li>`).join("")}</ul>`;
    if(canReview){
      html+=`<div class="row">
        <button class="sm" data-accept="${esc(t.id)}">Approve</button>
        <button class="sm" data-reject="${esc(t.id)}">Reject</button>
        <select class="sm" data-remediate="${esc(t.id)}">
          <option value="not_started" ${t.remediation_status==='not_started'?'selected':''}>Not started</option>
          <option value="in_progress" ${t.remediation_status==='in_progress'?'selected':''}>In progress</option>
          <option value="resolved" ${t.remediation_status==='resolved'?'selected':''}>Resolved</option>
        </select></div>`;
    }
    html+=`</div>`;
  });
  document.getElementById("results").innerHTML=html;
}

document.addEventListener("change",async e=>{
  const sel=e.target.closest("select[data-remediate]");
  if(sel&&session){
    await fetch(`/api/threats/${encodeURIComponent(sel.dataset.remediate)}/remediation`,
      {method:"PATCH",headers:AH(),body:JSON.stringify({status:sel.value})});
    loadProject();
  }
});

document.addEventListener("click",async e=>{
  const t=e.target;
  if(t.dataset.pdf&&session){
    const res=await fetch(`/api/projects/${encodeURIComponent(t.dataset.pdf)}/pdf`,{headers:AH(false)});
    if(!res.ok){alert("PDF failed");return;}
    const b=await res.blob();const a=document.createElement("a");
    a.href=URL.createObjectURL(b);a.download="audit-threat-model.pdf";a.click();return;
  }
  const status=t.dataset.accept?"accepted":t.dataset.reject?"rejected":null;
  const sid=t.dataset.accept||t.dataset.reject;
  if(status&&sid){
    await fetch(`/api/threats/${encodeURIComponent(sid)}/status`,
      {method:"PATCH",headers:AH(),body:JSON.stringify({status})});
    loadProject();
  }
});

sb.auth.onAuthStateChange(()=>refresh());refresh();