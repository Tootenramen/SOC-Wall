(() => {
'use strict';
/* ===== seeded rng (deterministic alert stream) ===== */
function mulberry32(a){return function(){a|=0;a=a+0x6D2B79F5|0;let t=Math.imul(a^a>>>15,1|a);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296}}
const hashSeed=()=>{const m=/seed=(\d+)/.exec(location.hash);return m?parseInt(m[1],10)>>>0:1337};
let seed=hashSeed(), rng=mulberry32(seed);

const C={bg:'#07080b',y:'#ffd400',c:'#00e5ff',m:'#ff2e88',d:'#7c8493'};
const SIMRATE=6;               // 1 real second at 1x = 6 simulated seconds
const $=id=>document.getElementById(id);
const cv=$('c'), ctx=cv.getContext('2d');
let W=0,H=0,DPR=1;

/* ===== pipeline graph ===== */
const R='https://github.com/Tootenramen/';
const NODES=[
 {id:'email',lab:'EMAIL GW',kind:'SOURCE',x:.07,y:.20,col:C.c,w:'Where much of the real world starts: a mail gateway flags a link or an attachment that looks wrong.',sim:'Emits synthetic phishing-style alerts with example.com domains.',link:[R+'ResumeAI','ResumeAI','Unrelated to mail, but the same "one idea, shipped as a polished static site" approach used here.']},
 {id:'edr',lab:'ENDPOINT EDR',kind:'SOURCE',x:.07,y:.40,col:C.c,w:'Software on laptops and servers that notices odd behavior, such as a document spawning a shell.',sim:'Emits synthetic process and credential-theft style alerts for wkstn-NN.example.com hosts.',link:[R+'NeatBook-Toolkit','NeatBook-Toolkit','A browser toolkit for analysts who investigate endpoint and web indicators every day.']},
 {id:'cloud',lab:'CLOUD LOGS',kind:'SOURCE',x:.07,y:.60,col:C.c,w:'Audit trails from cloud accounts: new keys, odd logins, changed permissions.',sim:'Emits synthetic identity and storage-permission alerts.',link:[R+'NeatBook-Toolkit','NeatBook-Toolkit','Quick links to the lookup sites analysts reach for while reading logs like these.']},
 {id:'ids',lab:'NETWORK IDS',kind:'SOURCE',x:.07,y:.80,col:C.c,w:'A sensor watching traffic patterns for scans, tunnelling and beacon-like timing.',sim:'Emits synthetic network alerts using documentation-only IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).',link:[R+'NeatBook-Toolkit','NeatBook-Toolkit','IP, domain and hash lookups in one place.']},
 {id:'siem',lab:'SIEM',kind:'COLLECT + CORRELATE',x:.27,y:.50,col:C.y,w:'The central inbox for security events. It normalizes everything, correlates related events and decides what is worth an alert.',sim:'Every alert funnels through here, gets an ID and a severity, and moves on to triage.',link:[R+'NeatBook-Toolkit','NeatBook-Toolkit','Templated links from an investigation into a SIEM search (placeholder hosts, bring your own).']},
 {id:'soar',lab:'SOAR TRIAGE',kind:'AUTOMATION PLAYBOOK',x:.45,y:.50,col:C.y,w:'SOAR runs a written playbook the moment an alert lands, so a person does not repeat the same boring first steps.',sim:'Each alert dwells here while the "playbook" runs: dedupe, classify, decide what context to fetch.',link:[R+'OTTO','OTTO','An overview of an automation suite built on the same principle: automation under rules, guards and proof gates.']},
 {id:'enrich',lab:'ENRICH',kind:'CONTEXT + VERDICT',x:.63,y:.50,col:C.c,w:'Add context: is the address known bad, is the host a crown jewel, has this user done this before? Then reach a verdict.',sim:'Rolls a seeded verdict: benign (about 55%), malicious (about 20%) or ambiguous (about 25%).',link:[R+'NeatBook-Toolkit','NeatBook-Toolkit','The manual version of this step: one-click lookups across common investigation sites.']},
 {id:'contain',lab:'AUTO-CONTAIN',kind:'RESPONSE',x:.84,y:.22,col:C.m,w:'For clear-cut malicious activity, act immediately: isolate the host, disable the account, block the indicator.',sim:'Malicious verdicts end here and close within seconds. Fast, but only safe for high-confidence cases.',link:[R+'OTTO','OTTO','OTTO treats automatic action seriously: kill switch, structural guard and a proof gate before anything counts as done.']},
 {id:'ticket',lab:'HUMAN TICKET',kind:'ANALYST QUEUE',x:.84,y:.50,col:C.y,w:'Anything ambiguous goes to a person with the context already attached. Automation should hand over cleanly, not guess.',sim:'Ambiguous alerts wait here for a simulated analyst. This is what drives the slow tail of MTTR.',link:[R+'OTTO','OTTO','Mission Control in OTTO is built around "what waits on you".']},
 {id:'closed',lab:'AUTO-CLOSE',kind:'RESOLUTION',x:.84,y:.78,col:C.c,w:'Benign and duplicate alerts are closed with a note, no human minutes spent.',sim:'Benign verdicts end here. A high auto-close rate is what frees analysts for the hard cases.',link:[R+'ResumeAI','ResumeAI','Another small, finished thing from the same author.']}
];
const NB={};NODES.forEach(n=>{NB[n.id]=n;n.pulse=0;n.count=0});
const EDGES=[['email','siem'],['edr','siem'],['cloud','siem'],['ids','siem'],['siem','soar'],['soar','enrich'],['enrich','contain'],['enrich','ticket'],['enrich','closed']];

/* ===== alert content (all synthetic) ===== */
const TYPES={
 email:['Phishing URL clicked','Suspicious attachment opened','Spoofed sender detected'],
 edr:['Unsigned binary spawns shell','Credential dump attempt','Ransom-note file pattern'],
 cloud:['Impossible-travel login','Storage ACL made public','New access key created'],
 ids:['Port scan burst','DNS tunnelling pattern','Beacon-like callback cadence']
};
const SRC=Object.keys(TYPES);
const RANGES=['192.0.2.','198.51.100.','203.0.113.'];
const pick=a=>a[Math.floor(rng()*a.length)];
const pad=(n,l)=>String(n).padStart(l,'0');

/* ===== state ===== */
let parts=[], simTime=0, nextId=1, spawnT=0.4, storm=0, glitch=0, flash=0, paused=false, speed=1;
let spawnTimes=[], mttr=[], autoClosed=0, totalClosed=0, hover=null, selected=null;

function reset(){
 seed=hashSeed(); rng=mulberry32(seed); $('seedv').textContent=seed;
 parts=[];simTime=0;nextId=1;spawnT=0.4;storm=0;spawnTimes=[];mttr=[];autoClosed=0;totalClosed=0;
 NODES.forEach(n=>{n.pulse=0;n.count=0});
 $('log').innerHTML='';
 for(let i=0;i<1500;i++)step(1/60); // warm start so the wall is never empty
}

function spawn(hostile){
 const src=pick(SRC), id=nextId++;
 const r=rng();
 const pm=hostile?0.45:0.20, pa=hostile?0.3:0.25;
 const truth=r<pm?'malicious':(r<pm+pa?'ambiguous':'benign');
 const a={id,src,type:pick(TYPES[src]),ip:pick(RANGES)+(1+Math.floor(rng()*253)),host:'wkstn-'+pad(Math.floor(rng()*90)+1,2)+'.example.com',
  sev:truth==='malicious'?(rng()<.5?'CRITICAL':'HIGH'):truth==='ambiguous'?'MEDIUM':'LOW',truth,born:simTime,
  path:[src,'siem','soar','enrich',truth==='malicious'?'contain':truth==='ambiguous'?'ticket':'closed'],
  leg:0,t:0,state:'move',timer:0,trail:[],jit:rng()*6.283,dur:0.9+rng()*0.7,x:0,y:0,dead:false,fade:1};
 a.col=truth==='malicious'?C.m:truth==='ambiguous'?C.y:C.c;
 parts.push(a);spawnTimes.push(simTime);
 NB[src].pulse=1;
 log('ALERT-'+pad(id,4)+' '+a.sev.padEnd(8)+' '+a.type+' '+a.host+' ('+a.ip+')',a.sev==='CRITICAL'||a.sev==='HIGH'?'hi':'');
 return a;
}

function fmt(s){s=Math.max(0,Math.round(s));return Math.floor(s/60)+':'+pad(s%60,2)}
const stamp=()=>'['+fmt(simTime)+']';
const logEl=$('log');
function log(msg,cls){
 const d=document.createElement('div');d.textContent=stamp()+' '+msg;if(cls)d.className=cls;
 logEl.appendChild(d);while(logEl.children.length>7)logEl.removeChild(logEl.firstChild);
}

/* ===== geometry ===== */
let PX=0,PY=0,PW=0,PH=0,NR=24;
const nx=x=>PX+((x-.07)/(.84-.07))*PW;
function layout(){
 W=innerWidth;H=innerHeight;DPR=Math.min(devicePixelRatio||1,2);
 cv.width=Math.round(W*DPR);cv.height=Math.round(H*DPR);
 const top=Math.max(64,$('top').offsetHeight+6), bot=$('bar').offsetHeight+120;
 PX=Math.max(48,W*.07);PW=W-PX*2;PY=top+26;PH=Math.max(220,H-top-bot-10);
 NR=Math.max(15,Math.min(32,Math.min(W,H)*.032));
 NODES.forEach(n=>{n.px=nx(n.x);n.py=PY+PH*n.y});
 for(const p of parts)p.trail.length=0;
}
function bez(a,b,t){
 const dx=(b.px-a.px)*.5, u=1-t;
 const x=u*u*u*a.px+3*u*u*t*(a.px+dx)+3*u*t*t*(b.px-dx)+t*t*t*b.px;
 const y=u*u*u*a.py+3*u*u*t*a.py+3*u*t*t*b.py+t*t*t*b.py;
 return [x,y];
}
const ease=t=>t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;

/* ===== simulation step (fixed dt) ===== */
function step(dt){
 simTime+=dt*SIMRATE;
 spawnT-=dt;
 if(spawnT<=0){
  if(storm>0){spawn(true);storm--;spawnT=0.07+rng()*0.1}
  else{spawn(false);spawnT=0.22+rng()*0.5}
 }
 for(const p of parts){
  if(p.dead)continue;
  const from=NB[p.path[p.leg]], to=NB[p.path[p.leg+1]];
  if(p.state==='move'&&to){
   p.t+=dt/p.dur;
   const xy=bez(from,to,ease(Math.min(p.t,1)));p.x=xy[0];p.y=xy[1];
   p.trail.push(p.x,p.y);if(p.trail.length>26)p.trail.splice(0,2);
   if(p.t>=1)arrive(p,to);
  }else if(p.state==='dwell'){
   p.timer-=dt;
   const n=NB[p.path[p.leg]];
   p.jit+=dt*(p.leg===4?1.2:2.4);
   const rr=NR+8+(p.id%4)*4;
   p.x=n.px+Math.cos(p.jit)*rr;p.y=n.py+Math.sin(p.jit)*rr;
   p.trail.length=0;
   if(p.timer<=0){
    if(p.leg>=p.path.length-1)finish(p);
    else{p.state='move';p.t=0;p.dur=0.9+rng()*0.7}
   }
  }else if(p.state==='fade'){p.fade-=dt*2.5;if(p.fade<=0)p.dead=true}
 }
 parts=parts.filter(p=>!p.dead);
 for(const n of NODES)n.pulse=Math.max(0,n.pulse-dt*2.2);
 glitch=Math.max(0,glitch-dt*0.5);flash=Math.max(0,flash-dt*3);
}
function arrive(p,to){
 p.leg++;to.pulse=1;to.count++;p.state='dwell';
 const id='ALERT-'+pad(p.id,4);
 if(to.id==='siem')p.timer=.2+rng()*.4;
 else if(to.id==='soar')p.timer=.5+rng()*.9;
 else if(to.id==='enrich'){p.timer=.7+rng()*.9;log(id+' enriched: '+p.ip+' reputation, host criticality, user history','')}
 else if(to.id==='contain'){p.timer=.8;log(id+' verdict MALICIOUS -> isolate '+p.host+', block '+p.ip,'hi')}
 else if(to.id==='ticket'){p.timer=11+rng()*9;log(id+' verdict AMBIGUOUS -> analyst queue, context attached','hm')}
 else if(to.id==='closed'){p.timer=.5;log(id+' verdict BENIGN -> auto-closed with note','ok')}
}
function finish(p){
 p.state='fade';totalClosed++;
 if(p.path[4]!=='ticket')autoClosed++;
 mttr.push(simTime-p.born);if(mttr.length>40)mttr.shift();
 if(p.path[4]==='ticket')log('ALERT-'+pad(p.id,4)+' closed by analyst after '+fmt(simTime-p.born),'hm');
}
function chaos(){
 storm+=36;glitch=1;flash=1;log('!!! CHAOS: simulated incident storm injected !!!','hi');
}

/* ===== drawing ===== */
function glowLine(a,b,col,al,wd){
 ctx.beginPath();ctx.moveTo(a.px,a.py);
 const dx=(b.px-a.px)*.5;ctx.bezierCurveTo(a.px+dx,a.py,b.px-dx,b.py,b.px,b.py);
 ctx.strokeStyle=col;ctx.globalAlpha=al;ctx.lineWidth=wd;ctx.stroke();
}
function hex(x,y,r){ctx.beginPath();for(let i=0;i<6;i++){const a=Math.PI/3*i+Math.PI/6;const px=x+Math.cos(a)*r,py=y+Math.sin(a)*r;i?ctx.lineTo(px,py):ctx.moveTo(px,py)}ctx.closePath()}
function queueLen(){let q=0;for(const p of parts)if(p.path[4]==='ticket'&&p.leg===4&&p.state==='dwell')q++;return q}
function draw(){
 ctx.setTransform(DPR,0,0,DPR,0,0);
 ctx.globalCompositeOperation='source-over';ctx.globalAlpha=1;
 ctx.fillStyle=C.bg;ctx.fillRect(0,0,W,H);
 const sh=glitch*8;ctx.save();if(sh>.2)ctx.translate((Math.random()-.5)*sh,(Math.random()-.5)*sh);
 // grid
 ctx.strokeStyle='#10141b';ctx.lineWidth=1;ctx.beginPath();
 for(let x=0;x<W;x+=48){ctx.moveTo(x,0);ctx.lineTo(x,H)}
 for(let y=0;y<H;y+=48){ctx.moveTo(0,y);ctx.lineTo(W,y)}
 ctx.stroke();
 // stage captions
 ctx.font="700 10px 'JetBrains Mono',monospace";ctx.fillStyle='#4a5363';ctx.textAlign='center';
 [['SOURCES',.07],['COLLECT',.27],['PLAYBOOK',.45],['ENRICH',.63],['OUTCOME',.84]].forEach(function(s){ctx.fillText('// '+s[0],nx(s[1]),PY-12)});
 // edges
 ctx.globalCompositeOperation='lighter';
 for(const e of EDGES){const A=NB[e[0]],B=NB[e[1]];glowLine(A,B,C.y,.07,9);glowLine(A,B,'#ffffff',.2,1)}
 // particles
 for(const p of parts){
  const al=Math.max(0,p.fade);
  if(p.trail.length>3){
   ctx.beginPath();ctx.moveTo(p.trail[0],p.trail[1]);
   for(let i=2;i<p.trail.length;i+=2)ctx.lineTo(p.trail[i],p.trail[i+1]);
   ctx.strokeStyle=p.col;ctx.globalAlpha=.55*al;ctx.lineWidth=2.5;ctx.stroke();
  }
  ctx.globalAlpha=.25*al;ctx.fillStyle=p.col;ctx.beginPath();ctx.arc(p.x,p.y,8,0,6.283);ctx.fill();
  ctx.globalAlpha=al;ctx.fillStyle='#fff';ctx.beginPath();ctx.arc(p.x,p.y,2.6,0,6.283);ctx.fill();
  ctx.fillStyle=p.col;ctx.globalAlpha=.9*al;ctx.beginPath();ctx.arc(p.x,p.y,4,0,6.283);ctx.fill();
 }
 // nodes
 ctx.globalCompositeOperation='source-over';
 const q=queueLen();
 for(const n of NODES){
  const hot=hover===n||selected===n;
  const r=NR*(1+n.pulse*.18);
  ctx.globalAlpha=1;
  ctx.shadowColor=n.col;ctx.shadowBlur=(hot?28:10)+n.pulse*24;
  hex(n.px,n.py,r);ctx.fillStyle='rgba(7,8,11,.92)';ctx.fill();
  ctx.lineWidth=hot?3:2;ctx.strokeStyle=hot?'#fff':n.col;ctx.stroke();
  ctx.shadowBlur=0;
  ctx.globalAlpha=.12+n.pulse*.5;ctx.fillStyle=n.col;hex(n.px,n.py,r*.62);ctx.fill();ctx.globalAlpha=1;
  ctx.font='700 '+Math.max(9,Math.min(13,NR*.42))+"px 'JetBrains Mono',monospace";ctx.fillStyle=hot?'#fff':'#d6dae3';ctx.textAlign='center';
  ctx.fillText(n.lab,n.px,n.py+r+Math.max(15,NR*.6));
  if(n.id==='ticket'){ctx.fillStyle=C.y;ctx.font='700 '+Math.max(12,NR*.55)+"px 'Space Grotesk'";ctx.fillText(q,n.px,n.py+5)}
 }
 ctx.restore();
 // glitch slice displacement
 if(glitch>.03){
  const nsl=Math.floor(3+glitch*12);
  for(let i=0;i<nsl;i++){
   const y=Math.random()*H, h=6+Math.random()*50*glitch, dx=(Math.random()-.5)*110*glitch;
   ctx.drawImage(cv,0,y*DPR,cv.width,h*DPR,dx*DPR,y*DPR,cv.width,h*DPR);
  }
 }
 if(flash>0){ctx.globalAlpha=flash*.18;ctx.fillStyle=C.m;ctx.fillRect(0,0,W,H);ctx.globalAlpha=1}
 if(Math.random()<.004)glitch=Math.max(glitch,.25);
}

/* ===== metrics + panel ===== */
function metrics(){
 const m=mttr.length?mttr.reduce((a,b)=>a+b,0)/mttr.length:0;
 $('mMttr').textContent=mttr.length?fmt(m):'--';
 const cut=simTime-60;while(spawnTimes.length&&spawnTimes[0]<cut)spawnTimes.shift();
 $('mRate').textContent=simTime>5?Math.round(spawnTimes.length*(60/Math.min(60,simTime))):'--';
 $('mAuto').textContent=totalClosed?Math.round(100*autoClosed/totalClosed)+'%':'--';
 let open=0;for(const p of parts)if(p.state!=='fade')open++;
 $('mOpen').textContent=open;$('mQ').textContent=queueLen();
 if(selected)fillStats(selected);
}
function fillStats(n){
 const q=n.id==='ticket'?'<div><b>'+queueLen()+'</b>waiting now</div>':'';
 $('pStats').innerHTML='<div><b>'+n.count+'</b>alerts through</div>'+q;
}
function openPanel(n){
 selected=n;$('panel').hidden=false;
 $('pKind').textContent=n.kind;$('pTitle').textContent=n.lab;$('pWhat').textContent=n.w;$('pSim').textContent=n.sim;
 const l=$('pLink');l.href=n.link[0];l.textContent=n.link[1]+' ↗';$('pNote').textContent=n.link[2];
 fillStats(n);
}
function closePanel(){selected=null;$('panel').hidden=true}

/* ===== input ===== */
function nodeAt(x,y){for(const n of NODES){if(Math.hypot(x-n.px,y-n.py)<=NR+6)return n}return null}
cv.addEventListener('mousemove',e=>{hover=nodeAt(e.clientX,e.clientY);cv.style.cursor=hover?'pointer':'default'});
cv.addEventListener('click',e=>{const n=nodeAt(e.clientX,e.clientY);n?openPanel(n):closePanel()});
$('pClose').onclick=closePanel;
function setPause(v){paused=v;$('bPause').textContent=paused?'Resume':'Pause'}
$('bPause').onclick=()=>setPause(!paused);
$('bChaos').onclick=chaos;
$('bSeed').onclick=()=>{location.hash='seed='+Math.floor(Math.random()*99999)};
$('bFull').onclick=toggleFull;
function toggleFull(){if(document.fullscreenElement)document.exitFullscreen();else if(document.documentElement.requestFullscreen)document.documentElement.requestFullscreen()}
function setSpeed(s){speed=s;document.querySelectorAll('#speed button').forEach(b=>b.classList.toggle('on',parseFloat(b.dataset.s)===s))}
document.querySelectorAll('#speed button').forEach(b=>b.onclick=()=>setSpeed(parseFloat(b.dataset.s)));
addEventListener('keydown',e=>{
 const k=e.key.toLowerCase();
 if(k===' '){e.preventDefault();setPause(!paused)}
 else if(k==='c')chaos();else if(k==='f')toggleFull();else if(k==='escape')closePanel();
 else if(k>='1'&&k<='4')setSpeed([.5,1,2,4][+k-1]);
});
addEventListener('hashchange',reset);
addEventListener('resize',layout);

/* ===== main loop ===== */
let last=performance.now(),acc=0,mt=0,frames=0,fpsT=0;
function frame(now){
 const rd=Math.min(.1,(now-last)/1000);last=now;
 if(!paused){acc+=rd*speed;let n=0;while(acc>=1/60&&n<10){step(1/60);acc-=1/60;n++}if(n>=10)acc=0}
 draw();
 mt+=rd;if(mt>.25){mt=0;metrics()}
 frames++;fpsT+=rd;if(fpsT>=1){window.__fps=frames/fpsT;frames=0;fpsT=0}
 requestAnimationFrame(frame);
}
$('seedv').textContent=seed;
layout();reset();metrics();
if(/storm/.test(location.hash)){chaos();glitch=.5;for(let i=0;i<70;i++)step(1/60);}
const nm=/node=(\w+)/.exec(location.hash);if(nm&&NB[nm[1]])openPanel(NB[nm[1]]); // #seed=N&storm : start mid-incident (used for screenshots)
window.__soc={chaos:chaos,parts:()=>parts.length,fps:()=>window.__fps};
requestAnimationFrame(frame);
})();
