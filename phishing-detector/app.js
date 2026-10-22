const $=i=>document.getElementById(i);
const SAMPLES=[['Normal HTTPS','https://www.example.com/about'],['Keywords','http://example.com/secure-login/verify-account.php'],['IP address','http://192.168.1.20/login/update'],['Subdomains','https://secure.login.account-verify.example.com/signin'],['@ symbol','https://www.paypal.com@example.net/verify'],['Long / combined','http://example-secure-bank.example.org:8080/account/verify/login/update/password/confirm/session?token=%41%42%43%44&redirect=%2F%2Fexample.net']];
const STAGES=[['Input Validation & Normalization','The system first checks whether the submitted value is a valid URL and separates it into its main components.'],['URL Feature Extraction','The system extracts measurable characteristics that may help distinguish legitimate-looking URLs from phishing attempts.'],['Security Heuristic Analysis','The detector checks for patterns commonly associated with phishing. Individual indicators are not proof of malicious intent.'],['Risk Scoring & Decision Logic','The system combines the detected signals into an overall risk estimate and determines the classification.'],['Final Classification & Explanation','The detector presents its decision together with the evidence so the user can understand why the URL was flagged.']];
const CANCEL={};let runId=0,t0=0,wake=null,cur=0,hist=[];
try{hist=JSON.parse(localStorage.getItem('nsc_hist')||'[]')}catch(e){}
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e};
const sleep=ms=>new Promise(r=>setTimeout(r,ms)),auto=()=>$('mode').value==='auto',dly=()=>+$('delay').value||0;
const chk=id=>{if(id!==runId)throw CANCEL};
function setStatus(t,c){$('status').textContent=t;$('status').className='pill '+(c||'')}
function log(st,msg,s='info'){const ms=performance.now()-t0,t=Math.floor(ms/1000),d=el('div','ln '+s,`[${String(Math.floor(t/60)).padStart(2,'0')}:${String(t%60).padStart(2,'0')}.${String(Math.floor(ms%1000)).padStart(3,'0')}] [${st}] ${s.toUpperCase()}: ${msg}`);$('log').append(d);$('log').scrollTop=1e9}
function setStage(i,s){document.querySelectorAll('#stages li')[i].className=s;$('prog').style.width=document.querySelectorAll('#stages li.done').length*20+'%'}
const line=(i,t,c)=>$('d'+i).append(el('div',c,t));
function initUI(){
  STAGES.forEach((s,i)=>{const li=el('li');const b=el('b','',s[0]);b.dataset.n=i+1;li.append(b,el('div','ex',s[1]),el('div','d'));li.lastChild.id='d'+i;$('stages').append(li)});
  SAMPLES.forEach(s=>{const b=el('button','smp',s[0]);b.onclick=()=>{runId++;if(wake)wake();clearRun();$('url').value=s[1]};$('samples').append(b)});
  renderHist();
}
function clearRun(){
  document.querySelectorAll('#stages li').forEach((l,i)=>{l.className='';$('d'+i).textContent=''});$('prog').style.width='0';
  $('log').textContent='';$('feat').innerHTML='<tr><td colspan="4" class="mu">Appears during Stage 2.</td></tr>';
  $('why').className='mu';$('why').textContent='Evidence appears after Stage 5. Only signals actually detected are listed.';
  $('score').textContent='--';$('fill').style.width='0';$('fill').style.background='';$('cls').textContent='Not analyzed';$('cls').className='pill';
  $('sig').textContent='Signals: -';$('dur').textContent='Duration: -';$('expl').textContent='Enter a URL and click Analyze URL.';$('msg').textContent='';$('next').disabled=true;setStatus('Ready');
}
async function stage(id,i,fn){
  cur=i;setStage(i,'active');if(auto())await sleep(dly());chk(id);await fn();chk(id);setStage(i,'done');
  if(!auto()&&i<4){$('next').disabled=false;await new Promise(r=>wake=r);$('next').disabled=true;chk(id)}
}
async function analyze(){
  const id=++runId;if(wake)wake();clearRun();t0=performance.now();setStatus('Analyzing','run');
  const raw=$('url').value,C={};
  try{
    await stage(id,0,()=>{
      log('Stage 1',`URL received (${raw.length} characters)`);
      const p=parseInput(raw);line(0,'Submitted: '+(raw.trim()||'(empty)'));
      if(!p.ok){line(0,'Parsing failed: '+p.error,'bad');throw{fail:p.error}}
      C.p=p;line(0,'Parsing: succeeded','ok');
      if(p.assumed)line(0,'No scheme given: http:// assumed for analysis only (shown, not hidden).','warn');
      const u=p.u;line(0,'Normalized: '+u.href);line(0,`Protocol=${u.protocol} Host=${u.hostname} Port=${u.port||'default'} Path=${u.pathname} Query=${u.search||'(none)'}`);
      log('Stage 1','URL components extracted',p.assumed?'warn':'ok');
    });
    await stage(id,1,async()=>{
      const f=C.f=extract(C.p);$('feat').textContent='';
      for(const r of f.rows){chk(id);const tr=el('tr');tr.append(el('td','',r[0]),el('td','v',String(r[1])),el('td',r[2],r[2]),el('td','mu',r[3]));$('feat').append(tr);
        log('Stage 2',`${r[0]} = ${r[1]} [${r[2]}]`,r[2]==='Normal'?'info':'warn');if(auto())await sleep(dly()/8)}
      log('Stage 2','Feature extraction completed','ok');
    });
    await stage(id,2,async()=>{
      C.trig=[];
      for(const r of RULES){chk(id);const o=r.test(C.f);
        if(o===null){line(2,'✓ passed: '+r.name,'ok');log('Stage 3',`Rule "${r.name}" passed`)}
        else{const w=r.w(C.f);C.trig.push({name:r.name,observed:o,weight:w,why:r.why,limit:r.limit});line(2,`⚠ triggered: ${r.name} (${o}) +${w}`,'warn');log('Stage 3',`Rule "${r.name}" triggered, +${w}`,'warn')}
        if(auto())await sleep(dly()/10)}
      log('Stage 3',`${C.trig.length} of ${RULES.length} rules triggered`,'ok');
    });
    await stage(id,3,()=>{
      const sum=C.trig.reduce((a,t)=>a+t.weight,0);C.score=Math.min(100,sum);C.cls=classify(C.score);
      C.trig.forEach(t=>line(3,`+${t.weight}  ${t.name}`));
      line(3,`Sum = ${sum}${sum>100?' (capped at 100)':''}  ->  Risk score ${C.score}/100 (heuristic, not a probability)`,'ok');
      line(3,'Thresholds: <25 Low Risk, 25-49 Suspicious, >=50 High Risk');
      $('score').textContent=C.score;$('fill').style.width=C.score+'%';
      log('Stage 4',`Risk score calculated: ${C.score}/100`,'ok');
    });
    await stage(id,4,()=>{
      const col=C.cls==='High Risk'?'r':C.cls==='Suspicious'?'a':'g',cv={r:'--r',a:'--a',g:'--g'}[col];
      const top=[...C.trig].sort((a,b)=>b.weight-a.weight).slice(0,3).map(t=>t.name);
      const dur=Math.round(performance.now()-t0);
      C.recs=C.cls==='Low Risk'?['No strong phishing indicators found, but this is not a guarantee. Still check the sender and domain spelling.']:['Do not enter passwords or personal data.','Do not click the link; type the official site address manually.','Report it to your IT/security team or email provider.'];
      $('cls').textContent=C.cls;$('cls').className='pill '+col;$('fill').style.background=`var(${cv})`;
      $('sig').textContent='Signals: '+C.trig.length;$('dur').textContent='Duration: '+dur+' ms';
      $('expl').textContent=C.trig.length?`Flagged mainly because of: ${top.join('; ')}. Each signal is a hint, not proof.`:'None of the implemented heuristic checks were triggered.';
      renderWhy({trig:C.trig,recs:C.recs,cls:C.cls,score:C.score});
      line(4,`Result: ${C.cls} (${C.score}/100) in ${dur} ms`,'ok');C.recs.forEach(r=>line(4,'• '+r));
      hist.unshift({time:new Date().toLocaleString(),url:C.p.input,cls:C.cls,score:C.score,trig:C.trig,recs:C.recs});hist=hist.slice(0,50);
      try{localStorage.setItem('nsc_hist',JSON.stringify(hist))}catch(e){}
      renderHist();log('Stage 5','Final classification generated and saved to browser history','ok');
    });
    setStatus('Completed','ok');
  }catch(e){
    if(e===CANCEL)return;
    const m=e&&e.fail||(e&&e.message)||'Unexpected error';setStage(cur,'error');setStatus('Error','err');$('msg').textContent=m;log('Error',m,'error');
    $('cls').textContent='Analysis failed';$('expl').textContent='No result: '+m;
  }
}
function renderWhy(r){
  const w=$('why');w.className='';w.textContent='';
  w.append(el('p','',`Final classification (heuristic interpretation): ${r.cls}, score ${r.score}/100.`));
  if(!r.trig.length)w.append(el('p','mu','No indicators were triggered, so there is nothing to list.'));
  r.trig.forEach(t=>{const d=el('div','sig');d.append(el('b','',t.name),el('p','','Observed value: '+t.observed+'   |   Risk contribution: +'+t.weight),el('p','',t.why),el('p','mu','Limitation: '+t.limit));w.append(d)});
  const rc=el('div','');rc.append(el('b','','Recommended actions'));r.recs.forEach(x=>rc.append(el('p','',x)));w.append(rc);
}
function renderHist(){
  const b=$('hist');b.textContent='';
  hist.forEach(h=>{const tr=el('tr'),v=el('button','ghost','View Details');v.onclick=()=>renderWhy(h);const td=el('td');td.append(v);
    tr.append(el('td','',h.time),el('td','v',h.url.length>60?h.url.slice(0,57)+'...':h.url),el('td','',h.cls),el('td','',h.score),el('td','',h.trig.length),td);b.append(tr)});
  $('s1').textContent=hist.length;$('s2').textContent=hist.filter(h=>h.cls!=='Low Risk').length;$('s3').textContent=hist.filter(h=>h.cls==='Low Risk').length;$('s4').textContent=hist[0]?hist[0].cls:'-';
}
$('analyze').onclick=analyze;$('url').onkeydown=e=>{if(e.key==='Enter')analyze()};
$('clear').onclick=()=>{runId++;if(wake)wake();$('url').value='';clearRun()};
$('reset').onclick=()=>{runId++;if(wake)wake();$('url').value='';$('mode').value='auto';$('delay').value=700;clearRun()};
$('clrlog').onclick=()=>{$('log').textContent=''};
$('next').onclick=()=>{if(wake){const w=wake;wake=null;w()}};
$('clrhist').onclick=()=>{hist=[];try{localStorage.removeItem('nsc_hist')}catch(e){}renderHist()};
initUI();
