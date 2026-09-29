const DATABASE_NAME="memory-book-v1";
const DATABASE_VERSION=1;
const META_STORE="meta";
const ITEMS_STORE="items";
const VERIFIER_TEXT="memory-book-ready-v1";
const PBKDF2_ITERATIONS=250000;
const AUTO_LOCK_MS=10*60*1000;

const encoder=new TextEncoder();
const decoder=new TextDecoder();
let database=null;
let sessionCryptoKey=null;
let lastActivity=Date.now();

const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];

function bytesToBase64(bytes){
  let binary="";
  const chunk=0x8000;
  for(let i=0;i<bytes.length;i+=chunk){
    binary+=String.fromCharCode(...bytes.subarray(i,i+chunk));
  }
  return btoa(binary);
}
function base64ToBytes(value){
  const binary=atob(value);
  const bytes=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  return bytes;
}
function randomBytes(length){
  const bytes=new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function openDatabase(){
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open(DATABASE_NAME,DATABASE_VERSION);
    request.onupgradeneeded=()=>{
      const db=request.result;
      if(!db.objectStoreNames.contains(META_STORE))db.createObjectStore(META_STORE,{keyPath:"id"});
      if(!db.objectStoreNames.contains(ITEMS_STORE))db.createObjectStore(ITEMS_STORE,{keyPath:"id"});
    };
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
}
function transactionPromise(storeName,mode,operation){
  return new Promise((resolve,reject)=>{
    const tx=database.transaction(storeName,mode);
    const store=tx.objectStore(storeName);
    const request=operation(store);
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
}
const dbGet=(store,id)=>transactionPromise(store,"readonly",s=>s.get(id));
const dbGetAll=store=>transactionPromise(store,"readonly",s=>s.getAll());
const dbPut=(store,value)=>transactionPromise(store,"readwrite",s=>s.put(value));
const dbDelete=(store,id)=>transactionPromise(store,"readwrite",s=>s.delete(id));
const dbClear=store=>transactionPromise(store,"readwrite",s=>s.clear());

async function deriveCryptoKey(password,saltBytes){
  const baseKey=await crypto.subtle.importKey(
    "raw",encoder.encode(password),"PBKDF2",false,["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",salt:saltBytes,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM",length:256},
    false,
    ["encrypt","decrypt"]
  );
}
async function encryptObject(key,value){
  const iv=randomBytes(12);
  const plaintext=encoder.encode(JSON.stringify(value));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plaintext);
  return {
    iv:bytesToBase64(iv),
    cipher:bytesToBase64(new Uint8Array(cipher))
  };
}
async function decryptObject(key,sealed){
  const iv=base64ToBytes(sealed.iv);
  const cipher=base64ToBytes(sealed.cipher);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,cipher);
  return JSON.parse(decoder.decode(plain));
}

async function hasVault(){
  return Boolean(await dbGet(META_STORE,"vault"));
}
async function createVault(password){
  const salt=randomBytes(16);
  const key=await deriveCryptoKey(password,salt);
  const verifier=await encryptObject(key,{text:VERIFIER_TEXT});
  await dbPut(META_STORE,{
    id:"vault",
    version:1,
    salt:bytesToBase64(salt),
    iterations:PBKDF2_ITERATIONS,
    verifier
  });
  sessionCryptoKey=key;
}
async function unlockVault(password){
  const vault=await dbGet(META_STORE,"vault");
  if(!vault)return false;
  try{
    const key=await deriveCryptoKey(password,base64ToBytes(vault.salt));
    const verification=await decryptObject(key,vault.verifier);
    if(verification.text!==VERIFIER_TEXT)return false;
    sessionCryptoKey=key;
    return true;
  }catch{
    return false;
  }
}
function lockBook(){
  sessionCryptoKey=null;
  qs("#bookApp").classList.add("hidden");
  qs("#lockBtn").classList.add("hidden");
  qs("#gate").classList.remove("hidden");
  qs("#setupPanel").classList.add("hidden");
  qs("#unlockPanel").classList.remove("hidden");
  qs("#unlockPassword").value="";
  qs("#unlockStatus").textContent="";
  lastActivity=Date.now();
}
async function showBook(){
  qs("#gate").classList.add("hidden");
  qs("#bookApp").classList.remove("hidden");
  qs("#lockBtn").classList.remove("hidden");
  lastActivity=Date.now();
  await renderAll();
}
async function initializeGate(){
  const exists=await hasVault();
  qs("#setupPanel").classList.toggle("hidden",exists);
  qs("#unlockPanel").classList.toggle("hidden",!exists);
}

async function saveEncryptedPayload(payload,id=crypto.randomUUID()){
  if(!sessionCryptoKey)throw new Error("Libro bloqueado");
  const sealed=await encryptObject(sessionCryptoKey,payload);
  await dbPut(ITEMS_STORE,{id,sealed});
  return id;
}
async function readAllPayloads(){
  if(!sessionCryptoKey)return[];
  const records=await dbGetAll(ITEMS_STORE);
  const result=[];
  for(const record of records){
    try{
      const payload=await decryptObject(sessionCryptoKey,record.sealed);
      result.push({id:record.id,...payload});
    }catch{
      // A corrupted entry is skipped instead of exposing raw data.
    }
  }
  return result;
}

function formatDate(value){
  if(!value)return"Sin fecha";
  const date=new Date(value+"T12:00:00");
  return new Intl.DateTimeFormat("es-AR",{dateStyle:"long"}).format(date);
}
function escapeText(value){
  return String(value??"");
}
function createTextElement(tag,text,className){
  const el=document.createElement(tag);
  el.textContent=escapeText(text);
  if(className)el.className=className;
  return el;
}
function deleteButton(id,label="Eliminar"){
  const button=document.createElement("button");
  button.type="button";
  button.textContent=label;
  button.onclick=()=>requestDelete(id);
  return button;
}

async function resizeImage(file){
  if(!file)return null;
  if(!file.type.startsWith("image/"))throw new Error("El archivo elegido no es una imagen.");
  if(file.size>12*1024*1024)throw new Error("La imagen es demasiado grande. Elige una de menos de 12 MB.");
  const objectUrl=URL.createObjectURL(file);
  try{
    const img=new Image();
    await new Promise((resolve,reject)=>{
      img.onload=resolve;
      img.onerror=()=>reject(new Error("No pudimos leer la imagen."));
      img.src=objectUrl;
    });
    const maxSide=1400;
    const scale=Math.min(1,maxSide/Math.max(img.naturalWidth,img.naturalHeight));
    const width=Math.max(1,Math.round(img.naturalWidth*scale));
    const height=Math.max(1,Math.round(img.naturalHeight*scale));
    const canvas=document.createElement("canvas");
    canvas.width=width;
    canvas.height=height;
    canvas.getContext("2d",{alpha:false}).drawImage(img,0,0,width,height);
    const blob=await new Promise(resolve=>canvas.toBlob(resolve,"image/jpeg",0.8));
    if(!blob)throw new Error("No pudimos preparar la imagen.");
    return await blobToDataUrl(blob);
  }finally{
    URL.revokeObjectURL(objectUrl);
  }
}
function blobToDataUrl(blob){
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onload=()=>resolve(reader.result);
    reader.onerror=()=>reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

qs("#setupForm").addEventListener("submit",async event=>{
  event.preventDefault();
  const first=qs("#setupPassword").value;
  const second=qs("#setupPasswordAgain").value;
  if(first.length<8){
    alert("La contraseña debe tener al menos 8 caracteres.");
    return;
  }
  if(first!==second){
    alert("Las contraseñas no coinciden.");
    return;
  }
  await createVault(first);
  event.target.reset();
  await showBook();
});
qs("#unlockForm").addEventListener("submit",async event=>{
  event.preventDefault();
  qs("#unlockStatus").textContent="Abriendo...";
  const ok=await unlockVault(qs("#unlockPassword").value);
  if(!ok){
    qs("#unlockStatus").textContent="La contraseña no coincide.";
    return;
  }
  event.target.reset();
  qs("#unlockStatus").textContent="";
  await showBook();
});
qs("#lockBtn").onclick=lockBook;

qsa(".tab").forEach(button=>button.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  button.classList.add("active");
  qs("#"+button.dataset.view).classList.add("active");
}));

qs("#memoryForm").addEventListener("submit",async event=>{
  event.preventDefault();
  const status=qs("#memoryStatus");
  status.textContent="Protegiendo y guardando...";
  try{
    const file=qs("#memoryPhoto").files[0]||null;
    const photo=await resizeImage(file);
    await saveEncryptedPayload({
      type:"memory",
      title:qs("#memoryTitle").value.trim(),
      date:qs("#memoryDate").value,
      story:qs("#memoryStory").value.trim(),
      photo,
      savedAt:new Date().toISOString()
    });
    event.target.reset();
    status.textContent="Recuerdo guardado y cifrado en este dispositivo.";
    await renderAll();
  }catch(error){
    status.textContent=error.message||"No pudimos guardar el recuerdo.";
  }
});

qs("#dreamForm").addEventListener("submit",async event=>{
  event.preventDefault();
  await saveEncryptedPayload({
    type:"dream",
    dreamType:qs("#dreamType").value,
    text:qs("#dreamText").value.trim(),
    why:qs("#dreamWhy").value.trim(),
    year:qs("#dreamYear").value,
    savedAt:new Date().toISOString()
  });
  event.target.reset();
  await renderAll();
});

qs("#letterForm").addEventListener("submit",async event=>{
  event.preventDefault();
  await saveEncryptedPayload({
    type:"letter",
    title:qs("#letterTitle").value.trim(),
    openDate:qs("#letterDate").value,
    text:qs("#letterText").value.trim(),
    savedAt:new Date().toISOString()
  });
  event.target.reset();
  await renderAll();
});

qs("#profileForm").addEventListener("submit",async event=>{
  event.preventDefault();
  await saveEncryptedPayload({
    type:"profile",
    name:qs("#profileName").value.trim(),
    phrase:qs("#profilePhrase").value.trim(),
    color:qs("#profileColor").value,
    savedAt:new Date().toISOString()
  },"profile");
  await renderAll();
});

async function renderAll(){
  const items=await readAllPayloads();
  renderMemories(items.filter(x=>x.type==="memory"));
  renderDreams(items.filter(x=>x.type==="dream"));
  renderLetters(items.filter(x=>x.type==="letter"));
  renderProfile(items.find(x=>x.type==="profile"));
  renderStats(items);
}
function renderMemories(items){
  items.sort((a,b)=>(b.date||b.savedAt).localeCompare(a.date||a.savedAt));
  const list=qs("#memoryList");list.innerHTML="";
  if(!items.length){
    list.append(createTextElement("p","Todavía no guardaste recuerdos. Puedes empezar con uno pequeño."));
    return;
  }
  for(const item of items){
    const card=document.createElement("article");card.className="memory-card";
    const head=document.createElement("div");head.className="item-head";
    const titleWrap=document.createElement("div");
    titleWrap.append(createTextElement("h3",item.title),createTextElement("div",formatDate(item.date),"meta"));
    const actions=document.createElement("div");actions.className="item-actions";actions.append(deleteButton(item.id));
    head.append(titleWrap,actions);card.append(head);
    if(item.photo){
      const img=document.createElement("img");
      img.src=item.photo;
      img.alt="Foto guardada en este recuerdo";
      card.append(img);
    }
    const story=createTextElement("p",item.story);story.style.whiteSpace="pre-wrap";card.append(story);
    list.append(card);
  }
}
function renderDreams(items){
  items.sort((a,b)=>(b.savedAt||"").localeCompare(a.savedAt||""));
  const list=qs("#dreamList");list.innerHTML="";
  if(!items.length){
    list.append(createTextElement("p","Todavía no guardaste sueños. Puedes escribir uno aunque cambie más adelante."));
    return;
  }
  for(const item of items){
    const card=document.createElement("article");card.className="dream-card";
    card.append(createTextElement("div",item.dreamType,"dream-type"),createTextElement("h3",item.text));
    if(item.why)card.append(createTextElement("p",item.why));
    if(item.year)card.append(createTextElement("div","Año que imagino: "+item.year,"meta"));
    const actions=document.createElement("div");actions.className="item-actions";actions.append(deleteButton(item.id));
    card.append(actions);list.append(card);
  }
}
function renderLetters(items){
  items.sort((a,b)=>(a.openDate||"").localeCompare(b.openDate||""));
  const list=qs("#letterList");list.innerHTML="";
  const today=new Date().toISOString().slice(0,10);
  if(!items.length){
    list.append(createTextElement("p","Todavía no escribiste una carta al futuro."));
    return;
  }
  for(const item of items){
    const open=!item.openDate||item.openDate<=today;
    const card=document.createElement("article");
    card.className="letter-card "+(open?"open-letter":"locked-letter");
    const head=document.createElement("div");head.className="item-head";
    const wrap=document.createElement("div");
    wrap.append(createTextElement("h3",item.title),createTextElement("div","Abrir desde: "+formatDate(item.openDate),"meta"));
    const actions=document.createElement("div");actions.className="item-actions";actions.append(deleteButton(item.id));
    head.append(wrap,actions);card.append(head);
    if(open){
      card.append(createTextElement("p",item.text,"letter-text"));
    }else{
      card.append(createTextElement("p","🔒 Esta carta espera hasta la fecha que elegiste."));
    }
    list.append(card);
  }
}
function renderProfile(profile){
  const name=profile?.name||"Mi Libro de Recuerdos y Sueños";
  const phrase=profile?.phrase||"Mis recuerdos, mis sueños, mi historia.";
  const color=profile?.color||"#db2777";
  qs("#profileName").value=profile?.name||"";
  qs("#profilePhrase").value=profile?.phrase||"";
  qs("#profileColor").value=color;
  const cover=qs("#coverPreview");
  cover.style.setProperty("--cover",color);
  cover.innerHTML="";
  cover.append(createTextElement("h3",name),createTextElement("p",phrase));
}
function renderStats(items){
  const memories=items.filter(x=>x.type==="memory").length;
  const dreams=items.filter(x=>x.type==="dream").length;
  const letters=items.filter(x=>x.type==="letter").length;
  const stats=qs("#bookStats");stats.innerHTML="";
  for(const [number,label] of [[memories,"recuerdos"],[dreams,"sueños"],[letters,"cartas"]]){
    const box=document.createElement("div");box.className="stat";
    box.append(createTextElement("strong",number),createTextElement("span",label));stats.append(box);
  }
}

let pendingDeleteId=null;
function requestDelete(id){
  pendingDeleteId=id;
  qs("#confirmTitle").textContent="Eliminar contenido";
  qs("#confirmText").textContent="Se borrará este elemento cifrado de este dispositivo.";
  qs("#confirmDialog").showModal();
}
qs("#confirmAction").addEventListener("click",async()=>{
  if(pendingDeleteId){
    await dbDelete(ITEMS_STORE,pendingDeleteId);
    pendingDeleteId=null;
    await renderAll();
  }
});

qs("#exportBackupBtn").onclick=async()=>{
  const vault=await dbGet(META_STORE,"vault");
  const items=await dbGetAll(ITEMS_STORE);
  const backup={
    format:"memory-book-backup-v1",
    exportedAt:new Date().toISOString(),
    vault,
    items
  };
  const blob=new Blob([JSON.stringify(backup)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;
  a.download="libro-recuerdos-respaldo-cifrado.json";
  a.click();
  URL.revokeObjectURL(url);
};

qs("#importBackupBtn").onclick=()=>qs("#backupFile").click();
qs("#backupFile").addEventListener("change",async event=>{
  const file=event.target.files[0];
  if(!file)return;
  try{
    const parsed=JSON.parse(await file.text());
    if(parsed.format!=="memory-book-backup-v1"||!parsed.vault||!Array.isArray(parsed.items)){
      throw new Error("El archivo no parece ser un respaldo válido.");
    }
    if(!confirm("Importar reemplazará el libro local actual. ¿Continuar?"))return;
    await dbClear(META_STORE);
    await dbClear(ITEMS_STORE);
    await dbPut(META_STORE,parsed.vault);
    for(const item of parsed.items)await dbPut(ITEMS_STORE,item);
    sessionCryptoKey=null;
    await initializeGate();
    qs("#unlockStatus").textContent="Respaldo importado. Ábrelo con la contraseña usada al crearlo.";
  }catch(error){
    qs("#unlockStatus").textContent=error.message||"No pudimos importar el respaldo.";
  }finally{
    event.target.value="";
  }
});

qs("#resetBookBtn").onclick=async()=>{
  if(!confirm("Esto borrará definitivamente el libro local de este dispositivo. ¿Continuar?"))return;
  if(!confirm("Última confirmación: ¿borrar recuerdos, sueños, cartas y contraseña local?"))return;
  await dbClear(ITEMS_STORE);
  await dbClear(META_STORE);
  sessionCryptoKey=null;
  qs("#bookApp").classList.add("hidden");
  qs("#lockBtn").classList.add("hidden");
  qs("#gate").classList.remove("hidden");
  await initializeGate();
};

for(const eventName of ["pointerdown","keydown","touchstart"]){
  document.addEventListener(eventName,()=>{lastActivity=Date.now()},{passive:true});
}
setInterval(()=>{
  if(sessionCryptoKey&&Date.now()-lastActivity>AUTO_LOCK_MS)lockBook();
},30000);

let installPrompt=null;
window.addEventListener("beforeinstallprompt",event=>{
  event.preventDefault();
  installPrompt=event;
  qs("#installBtn").classList.remove("hidden");
});
qs("#installBtn").onclick=async()=>{
  if(!installPrompt)return;
  installPrompt.prompt();
  await installPrompt.userChoice;
  installPrompt=null;
  qs("#installBtn").classList.add("hidden");
};

if("serviceWorker"in navigator){
  window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));
}

(async()=>{
  database=await openDatabase();
  await initializeGate();
})();
