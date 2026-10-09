const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),url=require('url');
const {Pool}=require('pg');
const ROOT=__dirname;
const PUBLIC=ROOT;
const DBFILE=path.join(ROOT,'data.json');
const PORT=Number(process.env.PORT||10000);
const seed={users:[],jobs:[],applications:[],messages:[],saved:[],sessions:[],audit:[]};
const databaseUrl=process.env.DATABASE_URL;
const pool=databaseUrl?new Pool({connectionString:databaseUrl,ssl:databaseUrl.includes('localhost')||databaseUrl.includes('127.0.0.1')?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||10),connectionTimeoutMillis:10000,idleTimeoutMillis:30000}):null;
async function load(){
 if(!pool){try{return JSON.parse(fs.readFileSync(DBFILE,'utf8'))}catch(e){fs.writeFileSync(DBFILE,JSON.stringify(seed,null,2));return JSON.parse(JSON.stringify(seed))}}
 await pool.query(`CREATE TABLE IF NOT EXISTS enginex_state (id integer PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
 const r=await pool.query('SELECT data FROM enginex_state WHERE id=1');
 if(r.rowCount)return r.rows[0].data;
 const d=JSON.parse(JSON.stringify(seed));await pool.query('INSERT INTO enginex_state(id,data) VALUES(1,$1)',[d]);return d;
}
let db=null;
async function save(){if(pool)await pool.query('UPDATE enginex_state SET data=$1,updated_at=now() WHERE id=1',[db]);else fs.writeFileSync(DBFILE,JSON.stringify(db,null,2));}
/* ---------- credentials ----------
   The browser sends SHA-256('enginex|' + password). The server never stores that value as-is:
   it is wrapped with scrypt + a random salt before being saved. */
const sha256=s=>crypto.createHash('sha256').update(s).digest('hex');
const clientHash=pw=>sha256('enginex|'+pw);
const HEX64=/^[a-f0-9]{64}$/;
const EMAIL_RE=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function hashStored(h){const salt=crypto.randomBytes(16).toString('hex');return 'scrypt$'+salt+'$'+crypto.scryptSync(h,salt,32).toString('hex')}
function verifyHash(stored,h){
 if(typeof stored!=='string'||typeof h!=='string')return false;
 if(stored.startsWith('scrypt$')){const [,salt,hex]=stored.split('$');const a=Buffer.from(hex||'','hex'),b=crypto.scryptSync(h,salt||'',32);return a.length===b.length&&crypto.timingSafeEqual(a,b)}
 const a=Buffer.from(stored),b=Buffer.from(h);return a.length===b.length&&crypto.timingSafeEqual(a,b);
}
function credential(d){const c=String((d&&(d.hash||d.pass))||'');if(HEX64.test(c))return c;const pw=String((d&&d.password)||'');return pw?clientHash(pw):''}

/* ---------- tiny in-memory rate limiter ---------- */
const hits=new Map();
function limited(key,max,windowMs){const t=Date.now(),h=hits.get(key);if(!h||t-h.t>windowMs){hits.set(key,{n:1,t});return false}h.n++;return h.n>max}
setInterval(()=>{const t=Date.now();for(const [k,h] of hits)if(t-h.t>36e5)hits.delete(k)},6e5).unref();
const clientIp=req=>String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
const id=p=>p+'_'+crypto.randomBytes(6).toString('hex');const now=()=>Date.now();
function normalizeDb(){
 for(const k of ['users','jobs','applications','messages','saved','sessions','audit','listings','apps','threads','tickets','news'])if(!Array.isArray(db[k]))db[k]=[];
 if(!db.saves||typeof db.saves!=='object'||Array.isArray(db.saves))db.saves={};
 if(typeof db.tcount!=='number')db.tcount=1000;
}
async function seedAdmin(){
 normalizeDb();
 const email=(process.env.ADMIN_EMAIL||'').trim().toLowerCase(),password=process.env.ADMIN_PASSWORD||'';
 if(!email||!password){if(!db.users.some(u=>u.role==='admin'))console.warn('ADMIN_EMAIL/ADMIN_PASSWORD not set; no administrator was seeded.');await save();return;}
 const h=clientHash(password);const a=db.users.find(u=>u.email===email);
 if(!a){db.users.push({id:id('u'),name:'ENGINEX Administrator',email,pass:hashStored(h),role:'admin',status:'active',plan:'ent',created:now()});await save();return;}
 // The ADMIN_PASSWORD environment variable is the source of truth for the admin account.
 let changed=false;
 if(a.role!=='admin'){a.role='admin';changed=true}
 if(!verifyHash(a.pass,h)){a.pass=hashStored(h);changed=true}
 if(changed)await save();
}
function send(res,code,data,headers={}){res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(data))}
function readBody(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e6){reject(new Error('Payload too large'));req.destroy()}});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}})})}
function auth(req){const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'');return db.sessions.find(s=>s.token===token&&s.expires>now())?.userId}
function user(req){const uid=auth(req);const u=db.users.find(x=>x.id===uid);return u&&(u.status===undefined||u.status==='active')?u:undefined}
function safeUser(u){if(!u)return null;const {pass,...x}=u;return x}
function requireUser(req,res,roles){const u=user(req);if(!u){send(res,401,{error:'Authentication required'});return null}if(roles&&!roles.includes(u.role)){send(res,403,{error:'Administrator permission required'});return null}return u}
function log(u,action,entity,entityId){db.audit.unshift({id:id('log'),userId:u?.id||null,action,entity,entityId,t:now()});db.audit=db.audit.slice(0,3000)}
function validateJob(d){if(!d.title||d.title.trim().length<5)return 'Job title is required.';if(!d.description||d.description.trim().length<30)return 'Description must be at least 30 characters.';if(!d.discipline)return 'Engineering discipline is required.';if(!d.location)return 'Location is required.';return null}
function listing(j){return {...j,owner:db.users.find(u=>u.id===j.ownerId)?.name||'Employer',ownerId:undefined}}
/* ---------- shared state for the single-page app ----------
   Visitors get public data only. Logged-in users also get their own applications, messages and tickets.
   Writes are merged on the server so one user can never overwrite another user's private data. */
const isObj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const str=(x,n)=>String(x==null?'':x).slice(0,n);
function cap(o,n){try{return JSON.stringify(o).length<=n}catch(e){return false}}
function pubUser(x,viewer){const {pass,...o}=x;if(!viewer||(viewer.role!=='admin'&&viewer.id!==x.id)){delete o.email;delete o.phone}return o}
const listingOwner=lid=>db.listings.find(l=>l.id===lid)?.owner;
function stateFor(u){
 const admin=u?.role==='admin';
 const seeApp=a=>u&&(admin||a.userId===u.id||listingOwner(a.listingId)===u.id);
 return {
  users:db.users.filter(x=>x.status===undefined||x.status==='active'||admin).map(x=>pubUser(x,u)),
  listings:db.listings,
  apps:db.apps.map(a=>seeApp(a)?a:{id:a.id,listingId:a.listingId,userId:'',stub:true}),
  threads:u?db.threads.filter(t=>Array.isArray(t.users)&&t.users.includes(u.id)):[],
  tickets:u?db.tickets.filter(t=>admin||t.userId===u.id||t.email===u.email):[],
  saves:u?{[u.id]:db.saves[u.id]||[]}:{},
  news:admin?db.news:[],
  tcount:db.tcount,
  seed:2
 };
}
const bad=(error,code=400)=>({code,error});
const byId=arr=>new Map(arr.filter(x=>isObj(x)&&typeof x.id==='string').map(x=>[x.id,x]));
const GRACE=20000; // items younger than this are never deleted by a possibly-stale client
function mergeKey(key,v,u,req){
 const admin=u?.role==='admin';
 switch(key){
  case 'seed':return null;
  case 'listings':{
   if(!Array.isArray(v)||v.length>5000)return bad('Invalid listings');
   const inc=byId(v),known=new Set(db.listings.map(l=>l.id)),out=[];
   for(const e of db.listings){
    const i=inc.get(e.id),mine=u&&(e.owner===u.id||admin);
    if(mine){if(i&&cap(i,60000))out.push({...i,id:e.id,owner:e.owner});else if(i||now()-(e.created||0)<GRACE)out.push(e)}
    else if(i&&Number.isInteger(i.views)&&i.views===(e.views||0)+1)out.push({...e,views:i.views}); // a page view
    else out.push(e);
   }
   const fresh=[];
   for(const i of inc.values()){if(known.has(i.id)||!u||!cap(i,60000)||typeof i.title!=='string')continue;if(i.owner!==u.id&&!admin)continue;fresh.push(i)}
   db.listings=[...fresh,...out];return null;
  }
  case 'apps':{
   if(!Array.isArray(v)||v.length>20000)return bad('Invalid applications');
   const vis=a=>admin||a.userId===u.id||listingOwner(a.listingId)===u.id;
   const inc=byId(v),known=new Set(db.apps.map(a=>a.id)),out=[];
   for(const e of db.apps){
    if(!vis(e)){out.push(e);continue}
    const i=inc.get(e.id);
    if(i&&cap(i,20000))out.push({...i,id:e.id,userId:e.userId,listingId:e.listingId});else if(i||now()-(e.t||0)<GRACE)out.push(e);
   }
   const fresh=[];
   for(const i of inc.values()){
    if(known.has(i.id)||i.userId!==u.id||!cap(i,20000)||!listingOwner(i.listingId)&&!db.listings.some(l=>l.id===i.listingId))continue;
    if(out.some(a=>a.listingId===i.listingId&&a.userId===u.id&&a.status!=='withdrawn'))continue;
    fresh.push(i);
   }
   db.apps=[...out,...fresh];return null;
  }
  case 'threads':{
   if(!Array.isArray(v)||v.length>5000)return bad('Invalid threads');
   const inc=new Map(v.filter(t=>isObj(t)&&typeof t.key==='string').map(t=>[t.key,t]));
   const mineMsgs=t=>(Array.isArray(t.msgs)?t.msgs:[]).filter(m=>isObj(m)&&m.from===u.id&&typeof m.text==='string').map(m=>({from:u.id,text:str(m.text,4000),t:Number(m.t)||now()}));
   const dupe=(arr,m)=>arr.some(x=>x.from===m.from&&x.t===m.t&&x.text===m.text);
   for(const e of db.threads){
    if(!e.users.includes(u.id))continue;const i=inc.get(e.key);if(!i)continue;
    for(const m of mineMsgs(i))if(!dupe(e.msgs,m))e.msgs.push(m);
    e.msgs.sort((a,b)=>a.t-b.t);
    if(isObj(i.read)&&Number.isFinite(i.read[u.id]))e.read[u.id]=i.read[u.id];
    inc.delete(e.key);
   }
   for(const [k,i] of inc){
    if(db.threads.some(t=>t.key===k))continue;
    const users=Array.isArray(i.users)?i.users.map(String):[];
    if(users.length!==2||!users.includes(u.id)||users[0]===users[1]||k!==[...users].sort().join('|'))continue;
    const other=users.find(x=>x!==u.id);if(!db.users.some(x=>x.id===other))continue;
    db.threads.push({key:k,users,msgs:mineMsgs(i).sort((a,b)=>a.t-b.t),read:{[u.id]:Number(i.read?.[u.id])||now()}});
   }
   return null;
  }
  case 'tickets':{
   if(!Array.isArray(v)||v.length>20000)return bad('Invalid tickets');
   const inc=byId(v),known=new Set(db.tickets.map(t=>t.id));
   const vis=t=>admin||(u&&(t.userId===u.id||t.email===u.email));
   const out=db.tickets.map(e=>{
    const i=inc.get(e.id);if(!i||!vis(e)||!cap(i,100000))return e;
    if(admin)return {...i,id:e.id};
    const extra=(Array.isArray(i.replies)?i.replies.slice(e.replies.length):[]).filter(isObj).map(r=>({by:'user',name:str(r.name,120),text:str(r.text,4000),t:Number(r.t)||now()}));
    return {...e,status:['open','closed'].includes(i.status)?i.status:e.status,updated:now(),replies:[...e.replies,...extra].slice(0,200)};
   });
   const fresh=[];
   for(const i of inc.values()){
    if(known.has(i.id)||!/^EX-\d+$/.test(String(i.id))||!cap(i,20000))continue;
    const email=str(i.email,200).trim().toLowerCase();if(!EMAIL_RE.test(email)||!str(i.subject,200).trim())continue;
    if(u&&i.userId&&i.userId!==u.id&&!admin)continue;
    if(!u&&i.userId)continue;
    if(!u&&limited('tix|'+clientIp(req),5,36e5))return bad('Too many tickets. Please try again later.',429);
    const n=Number(String(i.id).slice(3));let tid=i.id;
    if(db.tickets.some(t=>t.id===tid)||fresh.some(t=>t.id===tid))tid='EX-'+(db.tcount+1);
    db.tcount=Math.max(db.tcount,Number(tid.slice(3))||n||db.tcount);
    const name=str(i.name,120),first=Array.isArray(i.replies)&&isObj(i.replies[0])?i.replies[0]:{};
    fresh.push({id:tid,userId:u&&i.userId===u.id?u.id:null,name,email,category:str(i.category,60),subject:str(i.subject,200),status:'open',created:now(),updated:now(),replies:[{by:'user',name,text:str(first.text,4000),t:now()}]});
   }
   db.tickets=[...out,...fresh];return null;
  }
  case 'saves':{
   if(!isObj(v))return bad('Invalid saves');
   if(Array.isArray(v[u.id]))db.saves[u.id]=v[u.id].filter(x=>typeof x==='string').slice(0,500);
   return null;
  }
  case 'news':{
   if(!Array.isArray(v)||v.length>20000)return bad('Invalid list');
   if(admin){db.news=v.filter(x=>isObj(x)&&EMAIL_RE.test(String(x.email||''))).map(x=>({email:str(x.email,200).toLowerCase(),t:Number(x.t)||now()}));return null}
   if(!u&&limited('news|'+clientIp(req),10,36e5))return bad('Too many requests.',429);
   let added=0;
   for(const x of v){
    if(added>=5||!isObj(x))break;const email=str(x.email,200).trim().toLowerCase();
    if(EMAIL_RE.test(email)&&!db.news.some(n=>n.email===email)&&db.news.length<20000){db.news.push({email,t:now()});added++}
   }
   return null;
  }
  case 'tcount':{
   const n=Number(v);if(Number.isFinite(n))db.tcount=Math.min(Math.max(db.tcount,Math.floor(n)),db.tcount+50);
   return null;
  }
  case 'users':{
   if(!Array.isArray(v)||v.length>20000)return bad('Invalid users');
   const PROTECTED=new Set(['id','email','pass','role','status','plan','created','demo']);
   for(const i of v){
    if(!isObj(i)||typeof i.id!=='string')continue;
    const t=db.users.find(x=>x.id===i.id);if(!t||(t.id!==u.id&&!admin)||!cap(i,200000))continue;
    for(const [k,val] of Object.entries(i)){
     if(k==='pass'||k==='id'||k==='__proto__'||k==='constructor'||k==='prototype')continue;
     if(PROTECTED.has(k)&&!admin){if(k==='plan'&&t.id===u.id&&val==='basic')t.plan='basic';continue}
     t[k]=val;
    }
   }
   return null;
  }
  default:return bad('Unsupported state key');
 }
}
async function route(req,res){const p=url.parse(req.url,true),pathname=p.pathname,method=req.method;
 if(method==='GET'&&pathname==='/api/health'){return send(res,200,{ok:true,version:'2.1',database:!!pool})}
 if(pathname==='/api/register'&&method==='POST')return readBody(req).then(async d=>{
  if(limited('reg|'+clientIp(req),20,36e5))return send(res,429,{error:'Too many attempts. Please try again later.'});
  const inc=d.user||d,name=str(inc.name,120).trim(),email=str(inc.email,200).trim().toLowerCase();
  if(!name||!EMAIL_RE.test(email))return send(res,400,{error:'Name and a valid email are required.'});
  const given=String(inc.pass||inc.hash||'');
  if(!HEX64.test(given)&&String(inc.password||'').length<8)return send(res,400,{error:'Password must be at least 8 characters.'});
  const h=credential(inc);if(!h)return send(res,400,{error:'Password is required.'});
  if(db.users.some(u=>u.email===email))return send(res,409,{error:'Email already registered.'});
  const u={id:id('u'),name,email,pass:hashStored(h),role:inc.role==='employer'?'employer':'engineer',status:'active',plan:'basic',company:str(inc.company,160),discipline:str(inc.discipline,80),city:str(inc.city||'Riyadh',80),bio:str(inc.bio,2000),headline:str(inc.headline,200),skills:Array.isArray(inc.skills)?inc.skills.slice(0,40).map(x=>str(x,60)):[],created:now()};
  db.users.push(u);log(u,'REGISTER','user',u.id);
  const token=crypto.randomBytes(32).toString('hex');db.sessions=db.sessions.filter(s=>s.expires>now());db.sessions.push({token,userId:u.id,expires:now()+7*864e5});await save();
  return send(res,201,{token,user:pubUser(u,u),id:u.id});
 }).catch(()=>send(res,400,{error:'Invalid request'}));
 if(pathname==='/api/login'&&method==='POST')return readBody(req).then(async d=>{
  const email=str(d.email,200).trim().toLowerCase();
  if(limited('login|'+clientIp(req)+'|'+email,10,6e5))return send(res,429,{error:'Too many attempts. Please wait a few minutes.'});
  const h=credential(d),u=db.users.find(x=>x.email===email);
  if(!u||!h||!verifyHash(u.pass,h))return send(res,401,{error:'Invalid email or password.'});
  if(u.status!==undefined&&u.status!=='active')return send(res,403,{error:'Account is not active.'});
  if(!String(u.pass).startsWith('scrypt$'))u.pass=hashStored(h);
  const token=crypto.randomBytes(32).toString('hex');db.sessions=db.sessions.filter(s=>s.expires>now());db.sessions.push({token,userId:u.id,expires:now()+7*864e5});await save();
  return send(res,200,{token,user:pubUser(u,u),id:u.id});
 }).catch(()=>send(res,400,{error:'Invalid request'}));
 if(pathname==='/api/password'&&method==='POST'){const u=requireUser(req,res);if(!u)return;return readBody(req).then(async d=>{if(limited('pw|'+u.id,10,6e5))return send(res,429,{error:'Too many attempts. Please wait a few minutes.'});const cur=String(d.current||''),next=String(d.next||'');if(!HEX64.test(cur)||!HEX64.test(next))return send(res,400,{error:'Invalid request'});if(!verifyHash(u.pass,cur))return send(res,403,{error:'Current password is incorrect.'});u.pass=hashStored(next);db.sessions=db.sessions.filter(x=>x.userId!==u.id||x.token===(req.headers.authorization||'').replace(/^Bearer\s+/,''));log(u,'PASSWORD','user',u.id);await save();return send(res,200,{ok:true})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/logout'&&method==='POST'){const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');db.sessions=db.sessions.filter(s=>s.token!==t);save().catch(console.error);return send(res,200,{ok:true})}
 if(pathname==='/api/me'&&method==='GET'){const u=requireUser(req,res);if(!u)return;return send(res,200,{user:safeUser(u)})}
 if(pathname==='/api/jobs'&&method==='GET'){let a=db.jobs.filter(j=>j.status==='published'&&(!p.query.q||[j.title,j.description,j.discipline,j.location,j.skills.join(' ')].join(' ').toLowerCase().includes(p.query.q.toLowerCase())));if(p.query.discipline)a=a.filter(j=>j.discipline===p.query.discipline);if(p.query.city)a=a.filter(j=>j.location.toLowerCase().includes(p.query.city.toLowerCase()));if(p.query.type)a=a.filter(j=>j.type===p.query.type);if(p.query.level)a=a.filter(j=>j.level===p.query.level);if(p.query.remote==='true')a=a.filter(j=>j.remote);a.sort((x,y)=>y.created-x.created);return send(res,200,{jobs:a.map(listing),total:a.length})}
 if(pathname==='/api/jobs'&&method==='POST'){const u=requireUser(req,res,['employer','admin']);if(!u)return;return readBody(req).then(async d=>{const err=validateJob(d);if(err)return send(res,400,{error:err});const j={id:id('job'),ownerId:u.id,title:d.title.trim(),description:d.description.trim(),discipline:d.discipline,location:d.location,type:d.type||'Full-time',level:d.level||'Mid',salaryMin:Number(d.salaryMin)||0,salaryMax:Number(d.salaryMax)||0,remote:!!d.remote,skills:Array.isArray(d.skills)?d.skills:[],status:u.role==='admin'?'published':'pending',created:now(),updated:now(),views:0,deadline:d.deadline||''};db.jobs.unshift(j);log(u,'CREATE','job',j.id);await save();return send(res,201,{job:listing(j),message:j.status==='pending'?'Submitted for admin approval.':'Published.'})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname.startsWith('/api/jobs/')&&method==='GET'){const j=db.jobs.find(x=>x.id===pathname.split('/')[3]);if(!j)return send(res,404,{error:'Job not found'});j.views++;await save();return send(res,200,{job:listing(j)})}
 if(pathname.startsWith('/api/jobs/')&&method==='DELETE'){const u=requireUser(req,res,['employer','admin']);if(!u)return;const jid=pathname.split('/')[3],j=db.jobs.find(x=>x.id===jid);if(!j)return send(res,404,{error:'Job not found'});if(u.role!=='admin'&&j.ownerId!==u.id)return send(res,403,{error:'Not your job'});j.status='closed';j.updated=now();log(u,'CLOSE','job',jid);await save();return send(res,200,{ok:true})}
 if(pathname==='/api/applications'&&method==='POST'){const u=requireUser(req,res,['engineer']);if(!u)return;return readBody(req).then(async d=>{const j=db.jobs.find(x=>x.id===d.jobId&&x.status==='published');if(!j)return send(res,404,{error:'Job unavailable'});if(db.applications.some(a=>a.jobId===j.id&&a.userId===u.id&&a.status!=='withdrawn'))return send(res,409,{error:'You already applied.'});const a={id:id('app'),jobId:j.id,userId:u.id,cover:d.cover||'',expectedSalary:Number(d.expectedSalary)||0,status:'submitted',created:now()};db.applications.push(a);log(u,'APPLY','application',a.id);await save();return send(res,201,{application:a})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/applications'&&method==='GET'){const u=requireUser(req,res);if(!u)return;let a=u.role==='admin'?db.applications:u.role==='employer'?db.applications.filter(x=>db.jobs.find(j=>j.id===x.jobId)?.ownerId===u.id):db.applications.filter(x=>x.userId===u.id);return send(res,200,{applications:a.map(x=>({...x,job:listing(db.jobs.find(j=>j.id===x.jobId)),candidate:safeUser(db.users.find(z=>z.id===x.userId))}))})}
 if(pathname.startsWith('/api/applications/')&&method==='PATCH'){const u=requireUser(req,res,['employer','admin']);if(!u)return;const a=db.applications.find(x=>x.id===pathname.split('/')[3]);if(!a)return send(res,404,{error:'Application not found'});const j=db.jobs.find(x=>x.id===a.jobId);if(u.role!=='admin'&&j.ownerId!==u.id)return send(res,403,{error:'Forbidden'});return readBody(req).then(async d=>{if(!['shortlisted','rejected','hired','submitted'].includes(d.status))return send(res,400,{error:'Invalid status'});a.status=d.status;await save();return send(res,200,{application:a})})}
 if(pathname==='/api/messages'&&method==='GET'){const u=requireUser(req,res);if(!u)return;return send(res,200,{messages:db.messages.filter(m=>m.from===u.id||m.to===u.id).sort((a,b)=>a.t-b.t)})}
 if(pathname==='/api/messages'&&method==='POST'){const u=requireUser(req,res);if(!u)return;return readBody(req).then(async d=>{if(!d.to||!d.text)return send(res,400,{error:'Recipient and message required'});const m={id:id('msg'),from:u.id,to:d.to,text:d.text.trim(),t:now(),read:false};db.messages.push(m);await save();return send(res,201,{message:m})})}
 if(pathname==='/api/profile'&&method==='PATCH'){const u=requireUser(req,res);if(!u)return;return readBody(req).then(async d=>{Object.assign(u,{name:d.name?.trim()||u.name,company:d.company??u.company,discipline:d.discipline??u.discipline,city:d.city??u.city,bio:d.bio??u.bio,skills:Array.isArray(d.skills)?d.skills:u.skills||[]});await save();return send(res,200,{user:safeUser(u)})})}
 if(pathname==='/api/admin/stats'&&method==='GET'){const u=requireUser(req,res,['admin']);if(!u)return;return send(res,200,{users:db.users.length,engineers:db.users.filter(x=>x.role==='engineer').length,employers:db.users.filter(x=>x.role==='employer').length,jobs:db.jobs.length,pendingJobs:db.jobs.filter(x=>x.status==='pending').length,applications:db.applications.length,openJobs:db.jobs.filter(x=>x.status==='published').length})}
 if(pathname==='/api/admin/jobs'&&method==='GET'){const u=requireUser(req,res,['admin']);if(!u)return;return send(res,200,{jobs:db.jobs.map(listing).sort((a,b)=>b.created-a.created)})}
 if(pathname.startsWith('/api/admin/jobs/')&&method==='PATCH'){const u=requireUser(req,res,['admin']);if(!u)return;const j=db.jobs.find(x=>x.id===pathname.split('/')[4]);if(!j)return send(res,404,{error:'Job not found'});return readBody(req).then(async d=>{if(d.status)j.status=d.status;j.updated=now();log(u,'MODERATE','job',j.id);await save();return send(res,200,{job:listing(j)})})}
 if(pathname==='/api/admin/users'&&method==='GET'){const u=requireUser(req,res,['admin']);if(!u)return;return send(res,200,{users:db.users.map(safeUser)})}
 if(pathname.startsWith('/api/admin/users/')&&method==='PATCH'){const u=requireUser(req,res,['admin']);if(!u)return;const x=db.users.find(z=>z.id===pathname.split('/')[4]);if(!x)return send(res,404,{error:'User not found'});return readBody(req).then(async d=>{if(d.status)x.status=d.status;if(d.role&&['engineer','employer','admin'].includes(d.role))x.role=d.role;await save();return send(res,200,{user:safeUser(x)})})}
 if(pathname==='/api/admin/audit'&&method==='GET'){const u=requireUser(req,res,['admin']);if(!u)return;return send(res,200,{audit:db.audit})}
 if(pathname==='/api/state'&&method==='GET'){const u=user(req);return send(res,200,{state:stateFor(u),me:u?pubUser(u,u):null,bank:{name:process.env.BANK_NAME||'ENGINEX Business Account',account:process.env.BANK_ACCOUNT||'Set BANK_ACCOUNT in Render',iban:process.env.BANK_IBAN||'Set BANK_IBAN in Render'},gateway:!!process.env.MOYASAR_SECRET,prices:{pro:99},feature:{}})}
 if(pathname.startsWith('/api/kv/')&&method==='PUT'){const u=user(req);const key=decodeURIComponent(pathname.slice('/api/kv/'.length));const PUBLIC_KEYS=new Set(['listings','tickets','news','tcount']);if(!u&&!PUBLIC_KEYS.has(key))return send(res,401,{error:'Authentication required'});if(!u&&limited('kv|'+clientIp(req),120,6e4))return send(res,429,{error:'Too many requests.'});return readBody(req).then(async d=>{if(!Object.prototype.hasOwnProperty.call(d,'v'))return send(res,400,{error:'Value required'});const err=mergeKey(key,d.v,u,req);if(err)return send(res,err.code,{error:err.error});await save();return send(res,200,{ok:true})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/pay/orders'&&method==='GET'){const u=requireUser(req,res);if(!u)return;const orders=db.orders||[];const out=(u.role==='admin'?orders:orders.filter(o=>o.userId===u.id)).map(o=>({...o,userName:db.users.find(x=>x.id===o.userId)?.name||'',email:db.users.find(x=>x.id===o.userId)?.email||''}));return send(res,200,out)}
 if(pathname==='/api/pay/checkout'&&method==='POST'){const u=requireUser(req,res);if(!u)return;return readBody(req).then(async d=>{const plans={pro:{label:'Professional plan – 1 month',amount:99},basic:{label:'Basic plan – 1 month',amount:0},ent:{label:'Enterprise plan',amount:0}};const p=plans[d.item]||plans.pro;if(d.item==='ent')return send(res,400,{error:'Contact sales for Enterprise'});const o={id:id('ord'),userId:u.id,kind:d.kind||'plan',item:d.item||'pro',label:p.label,amount:p.amount,method:d.method||'bank',status:p.amount>0?'pending':'paid',created:now(),ref:''};db.orders=db.orders||[];db.orders.unshift(o);if(o.status==='paid'){u.plan=o.item;await save();}else await save();if(d.method==='card'&&process.env.MOYASAR_SECRET)return send(res,501,{error:'Card gateway requires webhook configuration'});return send(res,200,{order:o,bank:{name:process.env.BANK_NAME||'ENGINEX Business Account',account:process.env.BANK_ACCOUNT||'Set BANK_ACCOUNT in Render',iban:process.env.BANK_IBAN||'Set BANK_IBAN in Render'}})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/pay/receipt'&&method==='POST'){const u=requireUser(req,res);if(!u)return;return readBody(req).then(async d=>{const o=(db.orders||[]).find(x=>x.id===d.id&&x.userId===u.id);if(!o)return send(res,404,{error:'Order not found'});o.ref=String(d.ref||'').trim();o.status='pending';await save();return send(res,200,{ok:true,order:o})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/pay/decide'&&method==='POST'){const u=requireUser(req,res,['admin']);if(!u)return;return readBody(req).then(async d=>{const o=(db.orders||[]).find(x=>x.id===d.id);if(!o)return send(res,404,{error:'Order not found'});o.status=d.approve?'paid':'rejected';if(d.approve){const x=db.users.find(z=>z.id===o.userId);if(x)x.plan=o.item;}await save();return send(res,200,{ok:true,order:o})}).catch(()=>send(res,400,{error:'Invalid request'}))}
 if(pathname==='/api/bootstrap'&&method==='GET')return send(res,200,{disciplines:['Electrical','Civil','Mechanical','Architecture','Structural','HSE','Environmental','Planning','Quantity Surveying','Project Management','Instrumentation & Control','Telecom & ELV'],cities:['Riyadh','Jeddah','Dammam','Khobar','Makkah','Madinah','NEOM','Tabuk','Jazan','Abha'],types:['Full-time','Part-time','Contract','Temporary','Internship'],levels:['Entry','Junior','Mid','Senior','Manager','Director']});
 return serveStatic(req,res,pathname);
}
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.gif':'image/gif','.svg':'image/svg+xml','.ico':'image/x-icon','.webp':'image/webp','.woff2':'font/woff2'};
const PRIVATE_FILE=/^(server\.js|package(-lock)?\.json|render\.yaml|data\.json|\.env.*|.*\.(db|log|bat|yml|yaml|txt|md))$/i;
function serveStatic(req,res,pathname){
 let decoded;try{decoded=decodeURIComponent(pathname)}catch(e){return send(res,400,{error:'Invalid URL'})}
 let f=decoded==='/'?'/index.html':decoded;f=path.normalize(f);if(path.isAbsolute(f))f=f.replace(/^[/\\]+/,'');
 const root=path.resolve(PUBLIC),file=path.resolve(root,f);
 if(file!==root&&!file.startsWith(root+path.sep))return send(res,403,{error:'Forbidden'});
 const rel=path.relative(root,file).split(path.sep),ext=path.extname(file).toLowerCase();
 if(rel.some(p=>p.startsWith('.')||p==='node_modules')||PRIVATE_FILE.test(path.basename(file))||!MIME[ext])return send(res,404,{error:'Not found'});
 if(!fs.existsSync(file)||fs.statSync(file).isDirectory())return send(res,404,{error:'Not found'});
 res.writeHead(200,{'Content-Type':MIME[ext],'Cache-Control':ext==='.html'?'no-cache':'public,max-age=86400','X-Content-Type-Options':'nosniff'});
 fs.createReadStream(file).pipe(res);
}
async function main(){db=await load();await seedAdmin();const server=http.createServer(async(req,res)=>{try{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','SAMEORIGIN');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('Permissions-Policy','camera=(),microphone=(),geolocation=()');await route(req,res)}catch(e){console.error(e);if(!res.headersSent)send(res,500,{error:'Server error'})}});server.listen(PORT,'0.0.0.0',()=>console.log(`ENGINEX Marketplace running on port ${PORT}`));const shutdown=async()=>{server.close(()=>{});if(pool)await pool.end();process.exit(0)};process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown)}
main().catch(e=>{console.error('Startup failed',e);process.exit(1)});
