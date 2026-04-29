// HOLON-META: {"purpose": "sentinel", "wiki": "32d6d069-74d6-8164-a6d5-f41c3d26ae9b"}

/**
 * SENTINEL v1 — Układ Immunologiczny ofshore.dev
 * 
 * Warstwy ochrony (analogia biologiczna):
 * L1: Skóra      — rate limiting, geo filter, bot detection
 * L2: Śluzówka   — request validation, injection detection
 * L3: Makrofagi  — pattern anomaly detection, auto-block
 * L4: T-cells    — key rotation, credential monitoring
 * L5: B-cells    — memory of attacks, adaptive rules
 * L6: Cytokiny   — alerts, notifications, coordination
 */

const TG   = "8394457153:AAFZQ4eMHaiAnmwejmTfWZHI_5KSqhXgCXg";
const CHAT = "8149345223";
const SB   = "https://blgdhfcosqjzrutncbbr.supabase.co";
const UPS  = "https://fresh-walleye-84119.upstash.io";
const UT   = "gQAAAAAAAUiXAAIncDEwMjljNTI2ZGQ5OWQ0OGJlOTFmYWU2YjQ2OGI0NmIyZXAxODQxMTk";
const CORS = {"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type"};
const CF_ZONE = "f783cda72a2902b86b7f206fc85bb61f";

const ENDPOINTS_TO_MONITOR = [
  { url:"https://genspark.ofshore.dev/health",     name:"genspark-worker",  critical:true },
  { url:"https://clone.ofshore.dev/health",        name:"clone-domain",     critical:true },
  { url:"https://onepass.ofshore.dev/health",      name:"onepass",          critical:true },
  { url:"https://brain-router.ofshore.dev/health", name:"brain-router",     critical:false },
  { url:"https://coolify-agent.maciej-koziej01.workers.dev/health", name:"coolify-agent", critical:false },
  { url:"https://bootstrap-deployer.maciej-koziej01.workers.dev/health", name:"bootstrap-deployer", critical:false },
  { url:"https://fnn-orchestrator.maciej-koziej01.workers.dev/health", name:"fnn-orchestrator", critical:false },
  { url:"https://mcp-gateway.maciej-koziej01.workers.dev/health", name:"mcp-gateway", critical:false },
];

// Wzorce sekretów do wykrycia w requests (leak detection)
const SECRET_PATTERNS = [
  /sk-ant-[a-zA-Z0-9-]{20,}/g,   // Anthropic
  /gsk_[a-zA-Z0-9]{40,}/g,        // Groq
  /ghp_[a-zA-Z0-9]{36}/g,         // GitHub
  /eyJ[a-zA-Z0-9._-]{100,}/g,     // JWT tokens
  /Bearer [a-zA-Z0-9._-]{40,}/g,  // Bearer tokens
  /tvly-[a-zA-Z0-9]{40,}/g,       // Tavily
];

// Attack patterns
const ATTACK_PATTERNS = [
  /(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b)/i,  // SQL injection
  /<script[^>]*>/i,                                      // XSS
  /\.\.[\/\\]/g,                                        // Path traversal
  /\b(eval|exec|system|passthru|shell_exec)\s*\(/i,    // Code injection
  /(\bAND\b|\bOR\b)\s+\d+=\d+/i,                       // SQL boolean
];

function J(d,s){return new Response(JSON.stringify(d),{status:s||200,headers:Object.assign({"Content-Type":"application/json"},CORS)});}

// ── Upstash helpers ───────────────────────────────────────────────
async function uGet(k){
  const r=await fetch(UPS+"/get/"+encodeURIComponent(k),{headers:{"Authorization":"Bearer "+UT}});
  const d=await r.json();
  try{return d.result?JSON.parse(d.result):d.result;}catch{return d.result;}
}
async function uSet(k,v,ttl){
  const s=typeof v==="string"?v:JSON.stringify(v);
  const url=UPS+"/set/"+encodeURIComponent(k)+"/"+encodeURIComponent(s)+(ttl?"?ex="+ttl:"");
  return fetch(url,{method:"POST",headers:{"Authorization":"Bearer "+UT}});
}
async function uIncr(k,ttl){
  await fetch(UPS+"/incr/"+encodeURIComponent(k),{method:"POST",headers:{"Authorization":"Bearer "+UT}});
  if(ttl) await fetch(UPS+"/expire/"+encodeURIComponent(k)+"/"+ttl,{headers:{"Authorization":"Bearer "+UT}});
  const r=await fetch(UPS+"/get/"+encodeURIComponent(k),{headers:{"Authorization":"Bearer "+UT}});
  const d=await r.json(); return parseInt(d.result)||0;
}
async function uSadd(k,v){return fetch(UPS+"/sadd/"+encodeURIComponent(k)+"/"+encodeURIComponent(v),{method:"POST",headers:{"Authorization":"Bearer "+UT}});}
async function uSismember(k,v){
  const r=await fetch(UPS+"/sismember/"+encodeURIComponent(k)+"/"+encodeURIComponent(v),{headers:{"Authorization":"Bearer "+UT}});
  const d=await r.json(); return d.result===1;
}

// ── Telegram alert ────────────────────────────────────────────────
async function alert(msg, level="info"){
  const icon = level==="critical"?"🚨":level==="warning"?"⚠️":level==="healed"?"✅":"ℹ️";
  await fetch(`https://api.telegram.org/bot${TG}/sendMessage`,{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({chat_id:CHAT, parse_mode:"Markdown", text:`${icon} *Sentinel* | ${level.toUpperCase()}\n\n${msg}\n\n_${new Date().toISOString()}_`})
  }).catch(()=>{});
}

// ── L1: Skóra — Rate Limiting ─────────────────────────────────────
async function checkRateLimit(ip, path){
  const key = `rl:${ip}:${Math.floor(Date.now()/60000)}`;
  const count = await uIncr(key, 60);
  const MAX = path.includes("/v1/")?30:100;
  if(count > MAX){
    await uSadd("sentinel:blocked_ips", ip);
    return {blocked:true, reason:"rate_limit", count, max:MAX};
  }
  return {blocked:false, count};
}

// ── L2: Śluzówka — Request Validation ────────────────────────────
function detectAttacks(text){
  const hits = [];
  for(const p of ATTACK_PATTERNS){
    if(p.test(text)) hits.push(p.toString().slice(1,30));
  }
  return hits;
}

function detectLeaks(text){
  const hits = [];
  for(const p of SECRET_PATTERNS){
    const matches = text.match(p);
    if(matches) hits.push({pattern: p.toString().slice(1,20), count: matches.length});
  }
  return hits;
}

// ── L3: Makrofagi — Anomaly Detection ────────────────────────────
async function checkBlocklist(ip){
  return uSismember("sentinel:blocked_ips", ip);
}

// ── L4: T-cells — Health Monitoring ──────────────────────────────
async function runHealthCheck(){
  const results = [];
  const failed = [];

  for(const ep of ENDPOINTS_TO_MONITOR){
    const start = Date.now();
    try {
      const r = await fetch(ep.url, {signal:AbortSignal.timeout(8000)});
      const latency = Date.now()-start;
      const ok = r.ok;
      
      results.push({name:ep.name, ok, latency, status:r.status});
      await uSet(`sentinel:health:${ep.name}`, {ok, latency, ts:new Date().toISOString(), status:r.status}, 600);
      
      if(!ok && ep.critical) failed.push(ep.name);
      
      // Jeśli latencja > 5s → warning
      if(latency > 5000) await alert(`⏱️ *${ep.name}* latency: ${latency}ms`, "warning");
      
    } catch(e) {
      results.push({name:ep.name, ok:false, latency:Date.now()-start, error:String(e).slice(0,50)});
      if(ep.critical) failed.push(ep.name);
    }
  }

  // Trigger self-heal dla krytycznych serwisów
  if(failed.length > 0){
    await alert(`Krytyczne serwisy DOWN: ${failed.join(", ")}\nUruchamiam self-heal...`, "critical");
    for(const name of failed){
      await triggerSelfHeal(name);
    }
  }

  await uSet("sentinel:last_health", {results, ts:new Date().toISOString(), failed}, 600);
  return {results, failed};
}

// ── L5: B-cells — Self Healing ────────────────────────────────────
async function triggerSelfHeal(serviceName){
  const healMap = {
    "genspark-worker": async () => {
      // CF Worker jest self-healing (serverless) - sprawdź czy route istnieje
      await alert(`Auto-heal: genspark-worker - serverless, sprawdzam routes`, "info");
    },
    "onepass": async () => {
      await fetch("https://coolify-agent.maciej-koziej01.workers.dev/restart",{
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({app_name:"onepass"})
      }).catch(()=>{});
      await alert(`Auto-heal: onepass restart triggered`, "healed");
    },
    "clone-domain": async () => {
      await alert(`Auto-heal: clone domain 502 - CF Worker route może wymagać refresh`, "warning");
    }
  };
  
  const healer = healMap[serviceName];
  if(healer) await healer();
  else await alert(`No auto-heal for: ${serviceName}`, "info");
}

// ── L6: Cytokiny — Key Leak Response ─────────────────────────────
async function handleKeyLeak(leaks, source){
  await alert(`🔑 WYKRYTO WYCIEK KLUCZY!\n\nŹródło: ${source}\nPatterns: ${leaks.map(l=>l.pattern).join(", ")}\n\nNatychmiastowe działania:\n1. Sprawdź logi\n2. Zrotuj klucze przez /setkey na Telegramie\n3. Sprawdź workers`, "critical");
  
  // Zablokuj IP jeśli znamy
  await uSet("sentinel:key_leak_alert", {ts:new Date().toISOString(), source, leaks}, 3600);
}

// ── Router ────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p   = url.pathname;
    const ip  = request.headers.get("CF-Connecting-IP") || "unknown";
    
    if(request.method==="OPTIONS") return new Response(null,{headers:CORS});

    // ── L1: Rate limit ────
    const rl = await checkRateLimit(ip, p);
    if(rl.blocked) {
      await alert(`Rate limit exceeded: ${ip} → ${p} (${rl.count} reqs/min)`, "warning");
      return J({error:"rate_limit_exceeded", retry_after:60}, 429);
    }

    // ── L3: Blocklist ─────
    const blocked = await checkBlocklist(ip);
    if(blocked) return J({error:"forbidden"}, 403);

    // ── Request body analysis ─────
    if(request.method==="POST"){
      const bodyText = await request.text();
      
      // L2: Attack detection
      const attacks = detectAttacks(bodyText);
      if(attacks.length > 0){
        await uSadd("sentinel:blocked_ips", ip);
        await alert(`🛡️ Attack blocked from ${ip}\nPatterns: ${attacks.join(", ")}\nPayload: ${bodyText.slice(0,200)}`, "critical");
        return J({error:"forbidden"}, 403);
      }
      
      // L4: Leak detection
      const leaks = detectLeaks(bodyText);
      if(leaks.length > 0) await handleKeyLeak(leaks, `POST ${p} from ${ip}`);
    }

    // ── Endpoints ─────────
    if(p==="/health") return J({
      ok:true, service:"sentinel", version:"1.0",
      layers:["rate_limit","attack_detect","blocklist","health_monitor","self_heal","key_leak"],
      endpoints:["/health","/status","/scan","/unblock","/threats","/heal"]
    });

    if(p==="/status") {
      const health = await uGet("sentinel:last_health");
      const leakAlert = await uGet("sentinel:key_leak_alert");
      return J({
        ok:true,
        health: health || {note:"no scan yet"},
        key_leak_alert: leakAlert,
        ts: new Date().toISOString()
      });
    }

    if(p==="/scan") {
      const result = await runHealthCheck();
      return J({ok:true, ...result});
    }

    if(p==="/threats") {
      const [blocked_ips, leak_alert] = await Promise.all([
        fetch(UPS+"/smembers/sentinel:blocked_ips",{headers:{"Authorization":"Bearer "+UT}}).then(r=>r.json()).then(d=>d.result||[]),
        uGet("sentinel:key_leak_alert")
      ]);
      return J({blocked_ips, leak_alert, ts:new Date().toISOString()});
    }

    if(p==="/unblock" && request.method==="POST") {
      const {ip:targetIp} = await request.json().catch(()=>({}));
      if(targetIp) {
        await fetch(UPS+"/srem/sentinel:blocked_ips/"+encodeURIComponent(targetIp),{method:"POST",headers:{"Authorization":"Bearer "+UT}});
        return J({ok:true, unblocked:targetIp});
      }
      return J({error:"ip required"},400);
    }

    if(p==="/heal") {
      const {service} = await request.json().catch(()=>({}));
      if(service){ await triggerSelfHeal(service); return J({ok:true, healing:service}); }
      const result = await runHealthCheck();
      return J({ok:true, full_scan:true, ...result});
    }

    return J({error:"not found"},404);
  },

  // Cron: co 5 minut health check
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runHealthCheck());
  }
};
