const LOCAL_STATE_NAME="emotion-organizer-v1";
const state=JSON.parse(localStorage.getItem(LOCAL_STATE_NAME)||"{}");
state.entries=state.entries||[];
state.resources=state.resources||[];
let selectedEmotion=null;
let monthCursor=new Date();monthCursor.setDate(1);

const emotions=[
  {id:"happy",label:"😊 Alegre",color:"#fde68a"},
  {id:"calm",label:"😌 En calma",color:"#bbf7d0"},
  {id:"sad",label:"😢 Triste",color:"#bfdbfe"},
  {id:"angry",label:"😤 Enojado/a",color:"#fecaca"},
  {id:"worried",label:"😟 Preocupado/a",color:"#ddd6fe"},
  {id:"confused",label:"😕 Confundido/a",color:"#fed7aa"},
  {id:"tired",label:"🥱 Cansado/a",color:"#e5e7eb"},
  {id:"excited",label:"🤩 Entusiasmado/a",color:"#fbcfe8"}
];
const phrases=[
  "Está bien sentir lo que siento. Puedo darme tiempo.",
  "No necesito entender todo de inmediato.",
  "Puedo pedir compañía si la necesito.",
  "Una emoción puede ser fuerte y aun así cambiar.",
  "Descansar también es cuidarme.",
  "Poner en palabras algo puede ayudarme a ordenarlo."
];
const qs=s=>document.querySelector(s),qsa=s=>[...document.querySelectorAll(s)];
const save=()=>localStorage.setItem(LOCAL_STATE_NAME,JSON.stringify(state));
const emotionById=id=>emotions.find(x=>x.id===id);

qsa(".tab").forEach(b=>b.onclick=()=>{qsa(".tab,.view").forEach(x=>x.classList.remove("active"));b.classList.add("active");qs("#"+b.dataset.view).classList.add("active");renderShare()});

function renderEmotionChoices(){
  const wrap=qs("#emotionChoices");wrap.innerHTML="";
  emotions.forEach(e=>{
    const b=document.createElement("button");b.type="button";b.className="emotion-btn"+(selectedEmotion===e.id?" selected":"");b.textContent=e.label;b.style.background=e.color;
    b.onclick=()=>{selectedEmotion=e.id;renderEmotionChoices()};wrap.append(b);
  });
}
qs("#intensity").oninput=e=>qs("#intensityText").textContent=e.target.value+" de 5";
qs("#saveEntry").onclick=()=>{
  if(!selectedEmotion){qs("#saveStatus").textContent="Elige una emoción primero.";return}
  state.entries.unshift({id:crypto.randomUUID(),emotion:selectedEmotion,note:qs("#note").value.trim(),intensity:Number(qs("#intensity").value),at:new Date().toISOString()});
  state.entries=state.entries.slice(0,500);save();qs("#note").value="";qs("#intensity").value="3";qs("#intensityText").textContent="3 de 5";selectedEmotion=null;qs("#saveStatus").textContent="Guardado en este dispositivo.";renderAll();
};
qs("#newPhrase").onclick=()=>qs("#supportPhrase").textContent=phrases[Math.floor(Math.random()*phrases.length)];

function renderRecent(){
  const wrap=qs("#recentEntries");wrap.innerHTML="";
  state.entries.slice(0,8).forEach(item=>{
    const e=emotionById(item.emotion);const card=document.createElement("article");card.className="entry";card.style.setProperty("--entry-color",e?.color||"#94a3b8");
    const h=document.createElement("h3");h.textContent=e?.label||"Emoción";
    const m=document.createElement("div");m.className="meta";m.textContent=new Date(item.at).toLocaleString("es-AR")+" · intensidad "+item.intensity+"/5";
    card.append(h,m);if(item.note){const p=document.createElement("p");p.textContent=item.note;card.append(p)}
    wrap.append(card);
  });
}
function renderMonth(){
  const y=monthCursor.getFullYear(),m=monthCursor.getMonth();qs("#monthTitle").textContent=monthCursor.toLocaleDateString("es-AR",{month:"long",year:"numeric"});
  const grid=qs("#monthGrid");grid.innerHTML="";const first=new Date(y,m,1).getDay();const offset=(first+6)%7;for(let i=0;i<offset;i++){grid.append(document.createElement("div"))}
  const days=new Date(y,m+1,0).getDate();let count=0;
  for(let d=1;d<=days;d++){const cell=document.createElement("div");cell.className="day";cell.textContent=d;const items=state.entries.filter(x=>{const dt=new Date(x.at);return dt.getFullYear()===y&&dt.getMonth()===m&&dt.getDate()===d});if(items.length){count+=items.length;const e=emotionById(items[0].emotion);cell.classList.add("has-entry");cell.style.background=e?.color||"#e2e8f0";cell.title=items.length+" registro(s)"}grid.append(cell)}
  qs("#monthSummary").textContent=count?("Hay "+count+" registro(s) este mes. No es una calificación: solo una forma de observar patrones."):"Todavía no hay registros para este mes.";
}
qs("#prevMonth").onclick=()=>{monthCursor.setMonth(monthCursor.getMonth()-1);renderMonth()};
qs("#nextMonth").onclick=()=>{monthCursor.setMonth(monthCursor.getMonth()+1);renderMonth()};

qs("#addResource").onclick=()=>{const v=qs("#resourceText").value.trim();if(!v)return;state.resources.push({id:crypto.randomUUID(),text:v});save();qs("#resourceText").value="";renderResources()};
function renderResources(){const wrap=qs("#resourceList");wrap.innerHTML="";state.resources.forEach(r=>{const b=document.createElement("button");b.type="button";b.className="chip";b.textContent=r.text+" ×";b.onclick=()=>{state.resources=state.resources.filter(x=>x.id!==r.id);save();renderResources()};wrap.append(b)})}

function last7Summary(){
  const since=Date.now()-7*24*60*60*1000;const items=state.entries.filter(x=>new Date(x.at).getTime()>=since);if(!items.length)return"No hay registros de los últimos 7 días.";
  const counts={};items.forEach(x=>counts[x.emotion]=(counts[x.emotion]||0)+1);const parts=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([id,n])=>(emotionById(id)?.label||id)+": "+n);
  return "Últimos 7 días: "+parts.join(", ")+".";
}
function renderShare(){qs("#sharePreview").textContent=last7Summary()}
qs("#shareSummary").onclick=async()=>{const text=last7Summary();if(navigator.share){try{await navigator.share({title:"Mi resumen de emociones",text})}catch{}}else{await navigator.clipboard?.writeText(text);alert("Resumen copiado para compartir cuando quieras.")}};
qs("#helpButton").onclick=()=>qs("#helpDialog").showModal();
qs("#resetAll").onclick=()=>{if(confirm("¿Borrar todos los registros y recursos locales?")){localStorage.removeItem(LOCAL_STATE_NAME);location.reload()}};

let installPrompt=null;window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;qs("#installBtn").classList.remove("hidden")});qs("#installBtn").onclick=async()=>{if(!installPrompt)return;installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden")};
if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));
function renderAll(){renderEmotionChoices();renderRecent();renderMonth();renderResources();renderShare()}renderAll();
