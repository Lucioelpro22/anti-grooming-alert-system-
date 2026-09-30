const DB_NAME="safe-space-v1",DB_VERSION=1,META_STORE="meta",ITEMS_STORE="items",VERIFY_TEXT="safe-space-ready-v1",PBKDF2_ITERATIONS=250000,AUTO_LOCK_MS=10*60*1000;
const encoder=new TextEncoder(),decoder=new TextDecoder();let db=null,key=null,lastActivity=Date.now();
const qs=s=>document.querySelector(s),qsa=s=>[...document.querySelectorAll(s)];
function b64(bytes){let s="";for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s)}
function unb64(v){const s=atob(v),b=new Uint8Array(s.length);for(let i=0;i<s.length;i++)b[i]=s.charCodeAt(i);return b}
function random(n){const b=new Uint8Array(n);crypto.getRandomValues(b);return b}
function openDb(){return new Promise((resolve,reject)=>{const r=indexedDB.open(DB_NAME,DB_VERSION);r.onupgradeneeded=()=>{const d=r.result;if(!d.objectStoreNames.contains(META_STORE))d.createObjectStore(META_STORE,{keyPath:"id"});if(!d.objectStoreNames.contains(ITEMS_STORE))d.createObjectStore(ITEMS_STORE,{keyPath:"id"})};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)})}
function tx(store,mode,fn){return new Promise((resolve,reject)=>{const t=db.transaction(store,mode),r=fn(t.objectStore(store));r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)})}
const get=(s,id)=>tx(s,"readonly",x=>x.get(id)),all=s=>tx(s,"readonly",x=>x.getAll()),put=(s,v)=>tx(s,"readwrite",x=>x.put(v)),del=(s,id)=>tx(s,"readwrite",x=>x.delete(id)),clear=s=>tx(s,"readwrite",x=>x.clear());
async function derive(password,salt){const base=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function seal(value){const iv=random(12),plain=encoder.encode(JSON.stringify(value)),cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plain);return{iv:b64(iv),cipher:b64(new Uint8Array(cipher))}}
async function openSealed(sealed,k=key){const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(sealed.iv)},k,unb64(sealed.cipher));return JSON.parse(decoder.decode(plain))}
async function createVault(password){const salt=random(16),k=await derive(password,salt);key=k;await put(META_STORE,{id:"vault",salt:b64(salt),verifier:await seal({text:VERIFY_TEXT})})}
async function unlock(password){const v=await get(META_STORE,"vault");if(!v)return false;try{const k=await derive(password,unb64(v.salt)),obj=await openSealed(v.verifier,k);if(obj.text!==VERIFY_TEXT)return false;key=k;return true}catch{return false}}
async function hasVault(){return Boolean(await get(META_STORE,"vault"))}
async function saveItem(value,id=crypto.randomUUID()){await put(ITEMS_STORE,{id,sealed:await seal(value)});return id}
async function readItems(){const records=await all(ITEMS_STORE),out=[];for(const r of records){try{out.push({id:r.id,...await openSealed(r.sealed)})}catch{}}return out}
function lock(){key=null;qs("#safeApp").classList.add("hidden");qs("#lockBtn").classList.add("hidden");qs("#gate").classList.remove("hidden");qs("#setupPanel").classList.add("hidden");qs("#unlockPanel").classList.remove("hidden");qs("#unlockPassword").value=""}
async function showApp(){qs("#gate").classList.add("hidden");qs("#safeApp").classList.remove("hidden");qs("#lockBtn").classList.remove("hidden");lastActivity=Date.now();await renderAll()}
async function initGate(){const exists=await hasVault();qs("#setupPanel").classList.toggle("hidden",exists);qs("#unlockPanel").classList.toggle("hidden",!exists)}

qs("#calmButton").onclick=()=>qs("#calmDialog").showModal();
qs("#setupForm").onsubmit=async e=>{e.preventDefault();const a=qs("#setupPassword").value,b=qs("#setupAgain").value;if(a.length<8){alert("Usá al menos 8 caracteres.");return}if(a!==b){alert("Las contraseñas no coinciden.");return}await createVault(a);e.target.reset();await showApp()};
qs("#unlockForm").onsubmit=async e=>{e.preventDefault();qs("#unlockStatus").textContent="Abriendo...";if(await unlock(qs("#unlockPassword").value)){qs("#unlockStatus").textContent="";e.target.reset();await showApp()}else qs("#unlockStatus").textContent="La contraseña no coincide."};
qs("#lockBtn").onclick=lock;
qsa(".tab").forEach(b=>b.onclick=()=>{qsa(".tab,.view").forEach(x=>x.classList.remove("active"));b.classList.add("active");qs("#"+b.dataset.view).classList.add("active")});

qs("#incidentForm").onsubmit=async e=>{e.preventDefault();await saveItem({type:"incident",kind:qs("#incidentType").value,note:qs("#incidentNote").value.trim(),hasEvidence:qs("#incidentEvidence").checked,at:new Date().toISOString()});e.target.reset();qs("#incidentStatus").textContent="Registro guardado y cifrado en este dispositivo.";await renderAll()};
qs("#trustedForm").onsubmit=async e=>{e.preventDefault();await saveItem({type:"trusted",name:qs("#trustedName").value.trim(),phone:qs("#trustedPhone").value.trim(),relation:qs("#trustedRelation").value.trim()},"trusted");await renderAll()};

async function renderAll(){const items=await readItems();renderTrusted(items.find(x=>x.type==="trusted"));renderIncidents(items.filter(x=>x.type==="incident"))}
function renderTrusted(t){qs("#trustedName").value=t?.name||"";qs("#trustedPhone").value=t?.phone||"";qs("#trustedRelation").value=t?.relation||"";qs("#trustedPreview").textContent=t?.name?("Persona guardada: "+t.name+(t.relation?" · "+t.relation:"")):"Todavía no guardaste una persona de confianza."}
function renderIncidents(items){items.sort((a,b)=>b.at.localeCompare(a.at));const wrap=qs("#incidentList");wrap.innerHTML="";if(!items.length){wrap.textContent="Todavía no hay registros.";return}items.forEach(i=>{const c=document.createElement("article");c.className="incident";const h=document.createElement("h3");h.textContent=i.kind;const m=document.createElement("div");m.className="meta";m.textContent=new Date(i.at).toLocaleString("es-AR");const p=document.createElement("p");p.textContent=i.note||"Sin nota adicional.";const ev=document.createElement("p");ev.className="small";ev.textContent=i.hasEvidence?"Marcaste que existe información para revisar con una persona adulta.":"";const a=document.createElement("div");a.className="item-actions";const btn=document.createElement("button");btn.textContent="Eliminar";btn.onclick=async()=>{if(confirm("¿Eliminar este registro cifrado?")){await del(ITEMS_STORE,i.id);await renderAll()}};a.append(btn);c.append(h,m,p,ev,a);wrap.append(c)})}

qs("#shareHelp").onclick=async()=>{const items=await readItems(),t=items.find(x=>x.type==="trusted"),message="Necesito hablar con vos. Usé Mi Espacio Seguro porque algo me hizo sentir incómodo/a o preocupado/a. ¿Podés acompañarme?";if(navigator.share){try{await navigator.share({title:"Necesito hablar",text:message});return}catch{}}if(t?.phone){const phone=t.phone.replace(/[^+0-9]/g,"");location.href="sms:"+phone+"?body="+encodeURIComponent(message)}else{await navigator.clipboard?.writeText(message);alert("Mensaje copiado. Elegí vos cómo compartirlo.")}};

qs("#exportBackup").onclick=async()=>{const vault=await get(META_STORE,"vault"),items=await all(ITEMS_STORE),blob=new Blob([JSON.stringify({format:"safe-space-backup-v1",exportedAt:new Date().toISOString(),vault,items})],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="mi-espacio-seguro-respaldo-cifrado.json";a.click();URL.revokeObjectURL(url)};
qs("#resetAll").onclick=async()=>{if(!confirm("¿Borrar todos los registros y la configuración de este dispositivo?"))return;if(!confirm("Esta acción no se puede deshacer sin un respaldo. ¿Continuar?"))return;await clear(ITEMS_STORE);await clear(META_STORE);key=null;qs("#safeApp").classList.add("hidden");qs("#lockBtn").classList.add("hidden");qs("#gate").classList.remove("hidden");await initGate()};

for(const name of ["pointerdown","keydown","touchstart"])document.addEventListener(name,()=>lastActivity=Date.now(),{passive:true});setInterval(()=>{if(key&&Date.now()-lastActivity>AUTO_LOCK_MS)lock()},30000);
let installPrompt=null;window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;qs("#installBtn").classList.remove("hidden")});qs("#installBtn").onclick=async()=>{if(!installPrompt)return;installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden")};
if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));
(async()=>{db=await openDb();await initGate()})();
