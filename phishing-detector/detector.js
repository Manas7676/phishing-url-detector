/* Heuristic phishing-URL detector. Pure logic, no DOM. Not a trained ML model. */
const KW=['login','signin','verify','account','update','secure','bank','password','confirm','suspend','wallet','paypal','invoice'];
const THRESH={suspicious:25,high:50};
function parseInput(raw){
  const s=(raw||'').trim();
  if(!s)return{ok:false,error:'Input is empty. Enter a URL such as https://www.example.com'};
  if(/\s/.test(s))return{ok:false,error:'URL contains spaces, which are not valid in a URL.'};
  const assumed=!/^[a-z][a-z0-9+.-]*:\/\//i.test(s);
  try{
    const u=new URL(assumed?'http://'+s:s);
    if(!/^https?:$/.test(u.protocol))return{ok:false,error:'Only http:// and https:// URLs are supported.'};
    if(!u.hostname)return{ok:false,error:'No hostname found in the URL.'};
    return{ok:true,u,input:s,assumed};
  }catch(e){return{ok:false,error:'Could not parse this as a URL.'}}
}
function extract(p){
  const u=p.u,host=u.hostname,labels=host.split('.');
  const ip=/^\d{1,3}(\.\d{1,3}){3}$/.test(host)||host.startsWith('[');
  const hay=(host+u.pathname+u.search).toLowerCase();
  const f={len:p.input.length,https:u.protocol==='https:',host,ip,
    subs:ip?0:Math.max(0,labels.length-2),at:p.input.includes('@'),
    hy:(host.match(/-/g)||[]).length,digits:(host.match(/\d/g)||[]).length,
    kw:KW.filter(k=>hay.includes(k)),puny:labels.some(l=>l.startsWith('xn--')),
    pathLen:u.pathname.length,port:u.port,enc:(p.input.match(/%[0-9a-f]{2}/gi)||[]).length};
  f.domain=ip?host:labels.slice(-2).join('.');
  const S=(c,w,b)=>c?b:w;
  f.rows=[
    ['URL length',f.len,f.len>100?'Suspicious':f.len>75?'Warning':'Normal','Very long URLs can hide the real destination.'],
    ['Protocol',f.https?'HTTPS':'HTTP',f.https?'Normal':'Warning','HTTP is unencrypted. HTTPS alone does not prove a site is safe.'],
    ['Hostname',host,'Normal','Registered domain (simple estimate): '+f.domain],
    ['Subdomains',f.subs,f.subs>=3?'Suspicious':f.subs==2?'Warning':'Normal','Many subdomains can imitate trusted names.'],
    ['IP address as host',f.ip?'Yes':'No',f.ip?'Suspicious':'Normal','Legitimate sites usually use a domain name.'],
    ['@ symbol',f.at?'Yes':'No',f.at?'Suspicious':'Normal','Text before @ is ignored by browsers and can disguise the real host.'],
    ['Hyphens in host',f.hy,f.hy>=4?'Suspicious':f.hy>=2?'Warning':'Normal','Hyphenated look-alike domains are common in phishing.'],
    ['Digits in host',f.digits,!f.ip&&f.digits>=4?'Warning':'Normal','Digit-heavy hostnames can indicate generated domains.'],
    ['Suspicious keywords',f.kw.length?f.kw.join(', '):'None',f.kw.length>=3?'Suspicious':f.kw.length?'Warning':'Normal','Words like login/verify are used to create urgency.'],
    ['Punycode (xn--)',f.puny?'Yes':'No',f.puny?'Suspicious':'Normal','Can encode look-alike international characters.'],
    ['Path length',f.pathLen,f.pathLen>40?'Warning':'Normal','Long paths may bury deceptive keywords.'],
    ['Port',f.port||'default',f.port&&!['80','443'].includes(f.port)?'Warning':'Normal','Unusual ports are rare on normal websites.'],
    ['Percent-encoded chars',f.enc,f.enc>=3?'Warning':'Normal','Encoding can obfuscate the real content.']];
  return f;
}
const RULES=[
 {id:'http',name:'No HTTPS',w:()=>12,test:f=>f.https?null:'http://',why:'Unencrypted connection.',limit:'Many legitimate sites still exist on HTTP; HTTPS is also common on phishing sites.'},
 {id:'ip',name:'IP address in hostname',w:()=>25,test:f=>f.ip?f.host:null,why:'Phishing URLs often use raw IPs instead of recognizable domains.',limit:'IP-based URLs can be legitimate (routers, internal tools).'},
 {id:'at',name:'@ symbol in URL',w:()=>20,test:f=>f.at?'@ present':null,why:'Browsers ignore text before @, so it can fake a trusted name.',limit:'Rare in legitimate links, but not impossible.'},
 {id:'puny',name:'Punycode hostname',w:()=>15,test:f=>f.puny?f.host:null,why:'Look-alike Unicode characters can imitate real brands.',limit:'Legitimate international domains also use punycode.'},
 {id:'subs',name:'Many subdomains (3+)',w:()=>15,test:f=>f.subs>=3?f.subs+' subdomains':null,why:'Deep subdomain chains can imitate trusted domains.',limit:'Large organisations sometimes use deep subdomains.'},
 {id:'hy',name:'Multiple hyphens in host (2+)',w:()=>10,test:f=>f.hy>=2?f.hy+' hyphens':null,why:'Look-alike domains often chain words with hyphens.',limit:'Plenty of genuine domains contain hyphens.'},
 {id:'kw',name:'Suspicious keywords',w:f=>Math.min(24,8*f.kw.length),test:f=>f.kw.length?f.kw.join(', '):null,why:'Urgency/credential words are common in phishing (8 points each, capped at 24).',limit:'Real login pages also contain these words.'},
 {id:'len',name:'Long URL (>75 chars)',w:()=>10,test:f=>f.len>75?f.len+' chars':null,why:'Long URLs can hide the true destination.',limit:'Tracking parameters make many safe URLs long.'},
 {id:'path',name:'Long path (>40 chars)',w:()=>6,test:f=>f.pathLen>40?f.pathLen+' chars':null,why:'Long paths can bury deceptive words.',limit:'Some sites have deep, legitimate paths.'},
 {id:'port',name:'Unusual port',w:()=>10,test:f=>f.port&&!['80','443'].includes(f.port)?':'+f.port:null,why:'Normal websites rarely use non-standard ports.',limit:'Development and internal servers often do.'},
 {id:'enc',name:'Percent-encoding (3+)',w:()=>5,test:f=>f.enc>=3?f.enc+' encoded chars':null,why:'Encoding can obfuscate content.',limit:'Encoding is normal in query strings.'},
 {id:'dig',name:'Many digits in hostname (4+)',w:()=>6,test:f=>!f.ip&&f.digits>=4?f.digits+' digits':null,why:'Digit-heavy hosts can indicate generated domains.',limit:'Some real brands include numbers.'}];
function classify(s){return s>=THRESH.high?'High Risk':s>=THRESH.suspicious?'Suspicious':'Low Risk'}
