const STORAGE_KEY="semaforoConversaciones.v1";
const state=JSON.parse(localStorage.getItem(STORAGE_KEY)||"{}");
state.boundaries=state.boundaries||{};
state.trusted=state.trusted||[];
state.scenario=state.scenario||{index:0,completed:false};
state.helpLog=state.helpLog||[];

const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];
const save=()=>localStorage.setItem(STORAGE_KEY,JSON.stringify(state));

qsa(".tab").forEach(btn=>btn.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  btn.classList.add("active");
  qs("#"+btn.dataset.view).classList.add("active");
}));

const scenarios=[
  {text:"Una persona de tu edad en un juego respeta que no quieras hablar por privado.",color:"green",why:"Respeta tu límite y no te presiona."},
  {text:"Alguien pregunta varias veces a qué escuela vas y a qué hora sales.",color:"yellow",why:"Pedir datos de rutina puede ser una señal para pausar y consultar a alguien de confianza."},
  {text:"Una persona te pide una foto íntima y dice que será un secreto entre ustedes.",color:"red",why:"Pedir contenido íntimo y secreto es una señal roja. Salir y pedir ayuda es lo más seguro."},
  {text:"Un amigo acepta cuando dices que no quieres videollamada.",color:"green",why:"Aceptar un no sin insistir muestra respeto."},
  {text:"Alguien te ofrece dinero o regalos si pasas a un chat que nadie conoce.",color:"yellow",why:"Regalos y secreto pueden usarse para generar presión o dependencia."},
  {text:"Una persona amenaza con publicar una foto si no haces lo que pide.",color:"red",why:"Eso es chantaje. No tienes que resolverlo solo/a."},
  {text:"Te invitan a un grupo y te explican quiénes participan antes de entrar.",color:"green",why:"La transparencia y el respeto ayudan a una interacción segura."},
  {text:"Alguien dice que tu familia no te entiende y que solo debes confiar en esa persona.",color:"yellow",why:"Intentar aislarte de tus apoyos es una señal de alerta."},
  {text:"Una persona adulta te pide que ocultes la conversación a tus responsables.",color:"red",why:"El pedido de secreto en ese contexto requiere cortar y pedir ayuda."},
  {text:"Una amistad online pregunta si puede compartir una captura donde apareces y acepta tu decisión.",color:"green",why:"Pedir permiso y respetarlo cuida tu privacidad."},
  {text:"Alguien se enoja cada vez que tardas en responder y te hace sentir culpable.",color:"yellow",why:"La presión emocional es una razón válida para pausar y hablar con alguien."},
  {text:"Te dicen que si bloqueas te van a buscar o hacer daño.",color:"red",why:"Una amenaza requiere apoyo adulto y, si corresponde, ayuda oficial."}
];

const colorLabels={green:"🟢 Verde",yellow:"🟡 Amarillo",red:"🔴 Rojo"};

function renderScenario(){
  const card=qs("#scenarioCard");
  if(state.scenario.completed){
    card.innerHTML="<h3>Completaste las 12 situaciones</h3><p>Practicaste cómo reconocer cambios de color y cuándo pedir ayuda.</p><button id='restart'>Practicar de nuevo</button>";
    qs("#restart").onclick=()=>{state.scenario={index:0,completed:false};save();renderScenario();renderBadges();renderProgress()};
    renderBadges();return;
  }
  const i=state.scenario.index;
  const s=scenarios[i];
  card.innerHTML="";
  const title=document.createElement("h3");title.textContent="Situación "+(i+1)+" de "+scenarios.length;
  const p=document.createElement("p");p.textContent=s.text;
  const actions=document.createElement("div");actions.className="scenario-actions";
  ["green","yellow","red"].forEach(color=>{
    const b=document.createElement("button");
    b.type="button";b.className=color+"-choice";b.textContent=colorLabels[color];
    b.onclick=()=>answerScenario(color===s.color,s);
    actions.append(b);
  });
  card.append(title,p,actions);
}

function answerScenario(correct,s){
  let box=qs(".feedback");if(box)box.remove();
  box=document.createElement("div");box.className="feedback";
  box.textContent=(correct?"¡Bien pensado! ":"Gracias por intentarlo. Miremos una pista: ")+s.why+" Esta situación es "+colorLabels[s.color]+".";
  qs("#scenarioCard").append(box);
  if(correct){
    setTimeout(()=>{
      state.scenario.index++;
      if(state.scenario.index>=scenarios.length)state.scenario.completed=true;
      save();renderScenario();renderBadges();renderProgress();
    },700);
  }
}

function renderBadges(){
  const wrap=qs("#scenarioBadges");wrap.innerHTML="";
  if(state.scenario.index>=4||state.scenario.completed)wrap.innerHTML+="<span class='badge'>👀 Observo señales</span>";
  if(state.scenario.index>=8||state.scenario.completed)wrap.innerHTML+="<span class='badge'>🧭 Pongo límites</span>";
  if(state.scenario.completed)wrap.innerHTML+="<span class='badge'>🛟 Sé pedir ayuda</span>";
}

qsa("[data-boundary]").forEach(input=>{
  input.checked=!!state.boundaries[input.dataset.boundary];
  input.addEventListener("change",()=>{state.boundaries[input.dataset.boundary]=input.checked;save();renderProgress()});
});

qsa(".phrase").forEach(btn=>btn.addEventListener("click",async()=>{
  const text=btn.textContent.trim();
  try{await navigator.clipboard.writeText(text);qs("#phraseCopy").textContent="Frase copiada."}
  catch{qs("#phraseCopy").textContent="Puedes recordar esta frase: “"+text+"”";}
}));

function renderTrusted(){
  const list=qs("#trustedList");list.innerHTML="";
  state.trusted.forEach((p,i)=>{
    const li=document.createElement("li");
    const text=document.createElement("span");
    text.textContent=[p.name,p.relation,p.phone].filter(Boolean).join(" · ");
    const del=document.createElement("button");del.type="button";del.textContent="Quitar";
    del.onclick=()=>{state.trusted.splice(i,1);save();renderTrusted();renderProgress()};
    li.append(text,del);list.append(li);
  });
}
qs("#trustedForm").addEventListener("submit",e=>{
  e.preventDefault();
  state.trusted.push({
    name:qs("#trustedName").value.trim(),
    relation:qs("#trustedRelation").value.trim(),
    phone:qs("#trustedPhone").value.trim()
  });
  e.target.reset();save();renderTrusted();renderProgress();
});

function renderProgress(){
  const boundaryCount=Object.values(state.boundaries).filter(Boolean).length;
  const boundaryPart=boundaryCount/5;
  const scenarioPart=state.scenario.completed?1:Math.min(state.scenario.index/scenarios.length,1);
  const trustPart=state.trusted.length?1:0;
  const pct=Math.round(((boundaryPart+scenarioPart+trustPart)/3)*100);
  qs("#progressBar").style.width=pct+"%";
  qs("#progressText").textContent=pct+"% completado";
  qs(".progress-shell").setAttribute("aria-valuenow",String(pct));
}

qs("#exitHelp").onclick=()=>{
  state.helpLog.push({at:new Date().toISOString()});save();
  qs("#helpStatus").textContent="Guardamos en este dispositivo la fecha y hora en que pediste ayuda.";
  qs("#helpDialog").showModal();
};
qs("#shareHelp").onclick=async()=>{
  const msg="Necesito hablar contigo. Una conversación en internet me incomodó y quiero pedir ayuda.";
  try{
    if(navigator.share){await navigator.share({title:"Necesito ayuda",text:msg});return}
  }catch{}
  location.href="sms:?&body="+encodeURIComponent(msg);
};

let installPrompt=null;
window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;qs("#installBtn").classList.remove("hidden")});
qs("#installBtn").onclick=async()=>{
  if(!installPrompt)return;
  installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden");
};

if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));

renderScenario();renderBadges();renderTrusted();renderProgress();
