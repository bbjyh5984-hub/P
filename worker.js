// Cloudflare Worker API skeleton. Bind a D1 database named DB.
// Set ADMIN_USERNAME, ADMIN_PASSWORD_HASH, TOKEN_SECRET, and SCRIPT_SOURCE as Worker secrets/vars.
// Generate ADMIN_PASSWORD_HASH using a secure password-hashing tool before deployment.
// This intentionally requires a backend secret; do not move credentials into index.html.
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json","Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Allow-Methods":"GET, POST, OPTIONS"}});
const b64=s=>btoa(String.fromCharCode(...new Uint8Array(s)));
async function sha(s){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("")}
async function tokenFor(secret,username){const payload=btoa(JSON.stringify({u:username,exp:Date.now()+8*3600*1000}));const sig=await crypto.subtle.sign("HMAC",await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]),new TextEncoder().encode(payload));return payload+"."+b64(sig)}
async function validToken(req,env){const h=req.headers.get("Authorization")||"";if(!h.startsWith("Bearer "))return false;try{const [p,s]=h.slice(7).split(".");const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.TOKEN_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);const raw=Uint8Array.from(atob(s),c=>c.charCodeAt(0));if(!await crypto.subtle.verify("HMAC",key,raw,new TextEncoder().encode(p)))return false;const x=JSON.parse(atob(p));return x.exp>Date.now()&&x.u===env.ADMIN_USERNAME}catch{return false}}
async function body(req){try{return await req.json()}catch{return {}}}
function now(){return Math.floor(Date.now()/1000)}
export default {
 async fetch(req,env){
  if(req.method==="OPTIONS")return new Response(null,{headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Allow-Methods":"GET, POST, OPTIONS"}});
  const u=new URL(req.url), p=u.pathname;
  if(p==="/health")return json({ok:true});
  if(p==="/api/admin/login"&&req.method==="POST"){
   const d=await body(req);
   // Password hash format: SHA-256 of password. Use a long unique password; for stronger production security replace with PBKDF2/Argon2 via a trusted auth provider.
   const supplied=await sha(String(d.password||""));
   if(d.username!==env.ADMIN_USERNAME||supplied!==env.ADMIN_PASSWORD_SHA256)return json({error:"بيانات الدخول غير صحيحة"},401);
   return json({token:await tokenFor(env.TOKEN_SECRET,env.ADMIN_USERNAME)});
  }
  if(p.startsWith("/api/admin/")){
   if(!await validToken(req,env))return json({error:"تسجيل الدخول مطلوب"},401);
   if(p==="/api/admin/keys"&&req.method==="POST"){
    const d=await body(req),kind=d.kind==="permanent"?"permanent":"temporary",label=String(d.label||"").slice(0,80);
    const raw="SK-"+crypto.randomUUID().replaceAll("-","")+crypto.randomUUID().replaceAll("-","");
    const expiry=kind==="permanent"?null:now()+Math.max(1,Math.min(Number(d.hours)||24,720))*3600;
    const id=crypto.randomUUID();await env.DB.prepare("INSERT INTO keys(id,key_hash,key_prefix,label,kind,created_at,expires_at,revoked) VALUES(?,?,?,?,?,?,?,0)").bind(id,await sha(raw),raw.slice(0,8),label,kind,now(),expiry).run();
    return json({key:raw});
   }
   if(p==="/api/admin/dashboard"&&req.method==="POST"){
    const keys=(await env.DB.prepare("SELECT id,key_prefix,label,kind,created_at,expires_at,revoked FROM keys ORDER BY created_at DESC").all()).results;
    const acts=(await env.DB.prepare("SELECT activated_at,key_prefix,client_id,result FROM activations ORDER BY activated_at DESC LIMIT 100").all()).results;
    const stats={total:keys.length,active:keys.filter(k=>!k.revoked&&(!k.expires_at||k.expires_at>now())).length,activations:(await env.DB.prepare("SELECT COUNT(*) n FROM activations").first()).n};
    return json({stats,keys:keys.map(k=>({...k,prefix:k.key_prefix,created:new Date(k.created_at*1000).toISOString(),expires:k.expires_at?new Date(k.expires_at*1000).toISOString():"Never",status:k.revoked?"Revoked":k.expires_at&&k.expires_at<=now()?"Expired":"Active"})),activations:acts.map(a=>({time:new Date(a.activated_at*1000).toISOString(),prefix:a.key_prefix,client_id:a.client_id,result:a.result}))});
   }
   const match=p.match(/^\/api\/admin\/keys\/([^/]+)\/revoke$/);
   if(match&&req.method==="POST"){await env.DB.prepare("UPDATE keys SET revoked=1 WHERE id=?").bind(match[1]).run();return json({ok:true})}
   return json({error:"not_found"},404);
  }
  if(p==="/api/activate"||p==="/api/script"){
   if(req.method!=="POST")return json({error:"method_not_allowed"},405);
   const d=await body(req),raw=String(d.key||"");if(!raw||raw.length>200)return json({error:"invalid_key"},403);
   const k=await env.DB.prepare("SELECT * FROM keys WHERE key_hash=?").bind(await sha(raw)).first();
   if(!k||k.revoked||(k.expires_at&&k.expires_at<=now())){if(k)await env.DB.prepare("INSERT INTO activations(activated_at,key_prefix,client_id,result) VALUES(?,?,?,?)").bind(now(),k.key_prefix,String(d.client_id||"").slice(0,100),"rejected").run();return json({error:"invalid_or_expired_key"},403)}
   await env.DB.prepare("INSERT INTO activations(activated_at,key_prefix,client_id,result) VALUES(?,?,?,?)").bind(now(),k.key_prefix,String(d.client_id||"").slice(0,100),"accepted").run();
   if(p==="/api/activate")return json({ok:true,kind:k.kind,expires_at:k.expires_at});
   if(!env.SCRIPT_SOURCE)return json({error:"SCRIPT_SOURCE not configured"},503);
   return new Response(env.SCRIPT_SOURCE,{headers:{"Content-Type":"text/plain; charset=utf-8","Access-Control-Allow-Origin":"*"}});
  }
  return json({error:"not_found"},404);
 }
};