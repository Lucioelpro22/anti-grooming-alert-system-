const LOCAL_STATE_NAME="digital-footprint-lab-v1";
const state=JSON.parse(localStorage.getItem(LOCAL_STATE_NAME)||"{}");
state.postQuiz=state.postQuiz||{index:0,completed:false};
state.consentQuiz=state.consentQuiz||{index:0,completed:false};
state.signals=state.signals||{};
state.questions=state.questions||{};
state.clean=state.clean||{};

const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];
const save=()=>localStorage.setItem(LOCAL_STATE_NAME,JSON.stringify(state));

qsa(".tab").forEach(btn=>btn.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  btn.classList.add("active");
  qs("#"+btn.dataset.view).classList.add("active");
}));

const posts=[
  {text:"Una selfie donde al fondo se ve claramente el número de tu casa.",choice:"review",why:"La foto revela una ubicación precisa aunque no la hayas escrito."},
  {text:"Un dibujo tuyo sin nombre completo, ubicación ni datos de otras personas.",choice:"post",why:"No aparecen datos personales claros; aun así puedes elegir la audiencia."},
  {text:"Una historia diciendo: “Estoy solo/a en casa hasta las 22”.",choice:"dont",why:"Publica una rutina y una situación de vulnerabilidad en tiempo real."},
  {text:"Una foto grupal donde varias personas todavía no saben que quieres publicarla.",choice:"review",why:"Conviene pedir permiso antes de subir una imagen donde otras personas son identificables."},
  {text:"Una foto de una comida sin ubicación, personas ni documentos visibles.",choice:"post",why:"Es un contenido general con poca información personal."},
  {text:"Una foto del boleto de viaje donde se ve nombre, fecha y código.",choice:"dont",why:"Los boletos y entradas pueden contener datos personales o códigos útiles para otras personas."},
  {text:"Una foto con uniforme donde se lee el nombre de tu escuela.",choice:"review",why:"Puede revelar una institución y ayudar a identificar tu rutina."},
  {text:"Un comentario que escribiste enojado/a y que podría lastimar a otra persona.",choice:"review",why:"Esperar y releer antes de publicar puede evitar una decisión impulsiva."},
  {text:"Una foto de tu mascota sin ubicación ni datos de contacto.",choice:"post",why:"Normalmente expone poca información personal si el fondo tampoco revela datos."},
  {text:"Una captura de pantalla donde se ve el teléfono de un amigo.",choice:"dont",why:"Incluye un dato personal de otra persona que no deberías publicar sin permiso."},
  {text:"Un anuncio público diciendo exactamente dónde y a qué hora te reunirás después de la escuela.",choice:"dont",why:"Revela una rutina futura y una ubicación específica."},
  {text:"Una publicación que revisaste, limitaste a una audiencia conocida y no contiene datos sensibles.",choice:"post",why:"Revisar contenido y audiencia antes de publicar reduce exposición innecesaria."}
];
const postLabels={post:"✅ Podría publicar",review:"🤔 Reviso primero",dont:"🛑 Mejor no publicar"};

function renderPostQuiz(){
  const card=qs("#postCard");
  if(state.postQuiz.completed){
    card.innerHTML="<h3>Completaste las 12 publicaciones ficticias</h3><p>Practicaste cómo detectar datos directos, indirectos y de otras personas.</p><button id='restartPosts'>Practicar de nuevo</button>";
    qs("#restartPosts").onclick=()=>{state.postQuiz={index:0,completed:false};save();renderPostQuiz();renderPostBadges();renderProgress()};
    renderPostBadges();return;
  }
  const i=state.postQuiz.index;const item=posts[i];
  card.innerHTML="";
  const h=document.createElement("h3");h.textContent="Publicación "+(i+1)+" de "+posts.length;
  const p=document.createElement("p");p.textContent=item.text;
  const actions=document.createElement("div");actions.className="post-actions";
  ["post","review","dont"].forEach(choice=>{
    const b=document.createElement("button");b.type="button";b.textContent=postLabels[choice];
    b.onclick=()=>answerPost(choice===item.choice,item);
    actions.append(b);
  });
  card.append(h,p,actions);
}
function answerPost(correct,item){
  let f=qs("#postCard .feedback");if(f)f.remove();
  f=document.createElement("div");f.className="feedback";
  f.textContent=(correct?"¡Bien pensado! ":"Buena práctica. Mira esta pista: ")+item.why+" → "+postLabels[item.choice]+".";
  qs("#postCard").append(f);
  if(correct)setTimeout(()=>{
    state.postQuiz.index++;
    if(state.postQuiz.index>=posts.length)state.postQuiz.completed=true;
    save();renderPostQuiz();renderPostBadges();renderProgress();
  },650);
}
function renderPostBadges(){
  const b=qs("#postBadges");b.innerHTML="";
  if(state.postQuiz.index>=6||state.postQuiz.completed)b.innerHTML+="<span class='badge'>👀 Veo datos escondidos</span>";
  if(state.postQuiz.completed)b.innerHTML+="<span class='badge'>⏸️ Pienso antes de publicar</span>";
}

const consentItems=[
  {text:"Tu amiga dice claramente que sí quiere salir en la foto y sabe dónde se publicará.",allowed:true,why:"Hay un permiso claro para esa publicación."},
  {text:"Una persona aparece al fondo y es identificable, pero no sabe que quieres subir la foto.",allowed:false,why:"Conviene preguntarle antes de publicar una imagen donde es identificable."},
  {text:"Alguien te pidió que no subieras una foto y luego cambiaste de idea por tu cuenta.",allowed:false,why:"Su decisión debe respetarse."},
  {text:"Un amigo aprobó una foto para un grupo privado, pero ahora quieres hacerla pública.",allowed:false,why:"Cambiar la audiencia cambia el contexto; hay que volver a preguntar."},
  {text:"Una persona te dice que puedes publicar una foto específica en tu cuenta privada.",allowed:true,why:"El permiso es concreto y la audiencia está acordada."},
  {text:"Una foto es graciosa, pero sabes que podría avergonzar a quien aparece.",allowed:false,why:"Que sea graciosa para ti no reemplaza el consentimiento de la otra persona."},
  {text:"Preguntas antes de etiquetar a alguien y acepta.",allowed:true,why:"Pedir permiso antes de asociar su identidad es una buena práctica."},
  {text:"Alguien aceptó una foto ayer pero hoy te pide que la borres.",allowed:false,why:"Puedes respetar su nueva decisión y ayudar a retirar la publicación."}
];

function renderConsentQuiz(){
  const card=qs("#consentCard");
  if(state.consentQuiz.completed){
    card.innerHTML="<h3>Completaste las 8 situaciones de consentimiento</h3><p>Practicaste que el permiso depende de la foto, el contexto y la audiencia.</p><button id='restartConsent'>Practicar de nuevo</button>";
    qs("#restartConsent").onclick=()=>{state.consentQuiz={index:0,completed:false};save();renderConsentQuiz();renderConsentBadges();renderProgress()};
    renderConsentBadges();return;
  }
  const i=state.consentQuiz.index;const item=consentItems[i];
  card.innerHTML="";
  const h=document.createElement("h3");h.textContent="Situación "+(i+1)+" de "+consentItems.length;
  const p=document.createElement("p");p.textContent=item.text;
  const actions=document.createElement("div");actions.className="consent-actions";
  const yes=document.createElement("button");yes.type="button";yes.textContent="✅ Hay permiso suficiente";yes.onclick=()=>answerConsent(item.allowed,item);
  const no=document.createElement("button");no.type="button";no.textContent="🤝 Pregunto o no publico";no.onclick=()=>answerConsent(!item.allowed,item);
  actions.append(yes,no);card.append(h,p,actions);
}
function answerConsent(correct,item){
  let f=qs("#consentCard .feedback");if(f)f.remove();
  f=document.createElement("div");f.className="feedback";
  f.textContent=(correct?"¡Muy bien! ":"Revisemos juntos: ")+item.why;
  qs("#consentCard").append(f);
  if(correct)setTimeout(()=>{
    state.consentQuiz.index++;
    if(state.consentQuiz.index>=consentItems.length)state.consentQuiz.completed=true;
    save();renderConsentQuiz();renderConsentBadges();renderProgress();
  },650);
}
function renderConsentBadges(){
  const b=qs("#consentBadges");b.innerHTML="";
  if(state.consentQuiz.index>=4||state.consentQuiz.completed)b.innerHTML+="<span class='badge'>🤝 Pregunto primero</span>";
  if(state.consentQuiz.completed)b.innerHTML+="<span class='badge'>📷 Respeto otras huellas</span>";
}

qsa("[data-signal]").forEach(input=>{
  input.checked=!!state.signals[input.dataset.signal];
  input.addEventListener("change",()=>{
    if(input.dataset.signal==="none"&&input.checked){
      qsa("[data-signal]").filter(x=>x!==input).forEach(x=>{x.checked=false;state.signals[x.dataset.signal]=false});
    }else if(input.dataset.signal!=="none"&&input.checked){
      const none=qs('[data-signal="none"]');none.checked=false;state.signals.none=false;
    }
    state.signals[input.dataset.signal]=input.checked;save();renderSimulator();renderProgress();
  });
});

const signalMessages={
  location:"ubicación o calle reconocible",
  school:"escuela o uniforme",
  routine:"rutina y horario futuro",
  friend:"otra persona identificable",
  contact:"dato de contacto",
  document:"documento, entrada o código"
};
function renderSimulator(){
  const selected=Object.entries(state.signals).filter(([name,value])=>value&&name!=="none").map(([name])=>signalMessages[name]);
  const box=qs("#simulatorResult");box.classList.remove("attention","good");
  if(state.signals.none&&!selected.length){
    box.classList.add("good");
    box.textContent="No marcaste datos sensibles de la lista. Igual conviene revisar audiencia y contexto antes de publicar.";
  }else if(selected.length){
    box.classList.add("attention");
    box.textContent="Antes de publicar, revisaría: "+selected.join(", ")+".";
  }else{
    box.textContent="Marca elementos para revisar la publicación ficticia.";
  }
}

qsa("[data-question]").forEach(input=>{
  input.checked=!!state.questions[input.dataset.question];
  input.addEventListener("change",()=>{state.questions[input.dataset.question]=input.checked;save();renderProgress()});
});
qsa("[data-clean]").forEach(input=>{
  input.checked=!!state.clean[input.dataset.clean];
  input.addEventListener("change",()=>{state.clean[input.dataset.clean]=input.checked;save();renderProgress()});
});

function renderProgress(){
  const postsPart=state.postQuiz.completed?1:Math.min(state.postQuiz.index/posts.length,1);
  const consentPart=state.consentQuiz.completed?1:Math.min(state.consentQuiz.index/consentItems.length,1);
  const simulatorPart=Object.values(state.signals).some(Boolean)?1:0;
  const questionsPart=Object.values(state.questions).filter(Boolean).length/5;
  const cleanPart=Object.values(state.clean).filter(Boolean).length/6;
  const pct=Math.round(((postsPart+consentPart+simulatorPart+questionsPart+cleanPart)/5)*100);
  qs("#progressBar").style.width=pct+"%";
  qs("#progressText").textContent=pct+"% completado";
  qs(".progress-shell").setAttribute("aria-valuenow",String(pct));
}

qs("#removeHelp").onclick=()=>qs("#helpDialog").showModal();
qs("#resetAll").onclick=()=>{
  if(confirm("¿Seguro que quieres borrar el progreso local de este laboratorio?")){
    localStorage.removeItem(LOCAL_STATE_NAME);location.reload();
  }
};

let installPrompt=null;
window.addEventListener("beforeinstallprompt",event=>{
  event.preventDefault();installPrompt=event;qs("#installBtn").classList.remove("hidden");
});
qs("#installBtn").onclick=async()=>{
  if(!installPrompt)return;
  installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden");
};

if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));

renderPostQuiz();renderPostBadges();renderConsentQuiz();renderConsentBadges();renderSimulator();renderProgress();
