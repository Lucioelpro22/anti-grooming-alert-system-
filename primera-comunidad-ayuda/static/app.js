const LOCAL_STATE_NAME="first-help-community-v1";
const state=JSON.parse(localStorage.getItem(LOCAL_STATE_NAME)||"{}");
state.actions=state.actions||[];
state.gratitudes=state.gratitudes||[];
state.challenges=state.challenges||{};
state.customChallenges=state.customChallenges||[];
state.boundaries=state.boundaries||{};
state.boundaryQuiz=state.boundaryQuiz||{index:0,completed:false};
state.motto=state.motto||"";

const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];
const save=()=>localStorage.setItem(LOCAL_STATE_NAME,JSON.stringify(state));
const uid=()=>crypto.randomUUID();

qsa(".tab").forEach(button=>button.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  button.classList.add("active");
  qs("#"+button.dataset.view).classList.add("active");
}));

function textElement(tag,text,className){
  const el=document.createElement(tag);
  el.textContent=String(text??"");
  if(className)el.className=className;
  return el;
}

qs("#actionForm").addEventListener("submit",event=>{
  event.preventDefault();
  state.actions.unshift({
    id:uid(),
    text:qs("#actionText").value.trim(),
    forWhom:qs("#actionFor").value,
    feeling:qs("#actionFeeling").value,
    at:new Date().toISOString()
  });
  save();event.target.reset();renderActions();renderSummary();
});
function renderActions(){
  const list=qs("#actionList");list.innerHTML="";
  if(!state.actions.length){
    list.append(textElement("p","Todavía no registraste acciones. Puede ser algo muy pequeño."));
    return;
  }
  for(const item of state.actions){
    const card=document.createElement("article");card.className="action-card";
    const head=document.createElement("div");head.className="item-head";
    const left=document.createElement("div");
    left.append(textElement("h3",item.text),textElement("div",item.forWhom+" · "+item.feeling,"meta"));
    const actions=document.createElement("div");actions.className="item-actions";
    const remove=document.createElement("button");remove.type="button";remove.className="remove";remove.textContent="Eliminar";
    remove.onclick=()=>{state.actions=state.actions.filter(x=>x.id!==item.id);save();renderActions();renderSummary()};
    actions.append(remove);head.append(left,actions);card.append(head);list.append(card);
  }
}

const builtInChallenges=[
  {id:"listen",title:"Escuchar de verdad",text:"Preguntar a alguien cómo está y escuchar sin interrumpir."},
  {id:"thanks",title:"Dar las gracias",text:"Agradecer algo concreto que otra persona hizo por mí."},
  {id:"tidy",title:"Cuidar un espacio común",text:"Ordenar o limpiar algo que usamos entre varias personas."},
  {id:"include",title:"Incluir",text:"Invitar a participar a alguien que quedó afuera, sin obligarlo."},
  {id:"nature",title:"Cuidar el ambiente",text:"Reducir un residuo o dejar un lugar más limpio de lo que estaba."},
  {id:"animal",title:"Cuidar a un animal",text:"Ayudar responsablemente a un animal con acompañamiento adulto si hace falta."},
  {id:"teach",title:"Compartir lo que sé",text:"Explicar algo con paciencia a alguien que lo necesita."},
  {id:"kind",title:"Una palabra amable",text:"Decir algo sincero y positivo sin esperar nada a cambio."}
];

function challengeCard(item,custom=false){
  const key=(custom?"custom:":"builtin:")+item.id;
  const card=document.createElement("article");
  card.className="challenge-card"+(state.challenges[key]?" done":"");
  card.append(textElement("div",item.title||"Mi desafío","challenge-title"),textElement("p",item.text));
  const actions=document.createElement("div");actions.className="item-actions";
  const toggle=document.createElement("button");toggle.type="button";
  toggle.textContent=state.challenges[key]?"✓ Lo hice":"Marcar como realizado";
  toggle.onclick=()=>{
    state.challenges[key]=!state.challenges[key];
    save();renderChallenges();renderSummary();
  };
  actions.append(toggle);
  if(custom){
    const remove=document.createElement("button");remove.type="button";remove.className="remove";remove.textContent="Eliminar";
    remove.onclick=()=>{
      state.customChallenges=state.customChallenges.filter(x=>x.id!==item.id);
      delete state.challenges[key];
      save();renderChallenges();renderSummary();
    };
    actions.append(remove);
  }
  card.append(actions);return card;
}
function renderChallenges(){
  const list=qs("#challengeList");list.innerHTML="";
  builtInChallenges.forEach(item=>list.append(challengeCard(item)));
  state.customChallenges.forEach(item=>list.append(challengeCard(item,true)));
}
qs("#customChallengeForm").addEventListener("submit",event=>{
  event.preventDefault();
  state.customChallenges.push({id:uid(),text:qs("#customChallengeText").value.trim()});
  save();event.target.reset();renderChallenges();renderSummary();
});

qs("#gratitudeForm").addEventListener("submit",event=>{
  event.preventDefault();
  state.gratitudes.unshift({id:uid(),text:qs("#gratitudeText").value.trim(),at:new Date().toISOString()});
  save();event.target.reset();renderGratitudes();renderSummary();
});
function renderGratitudes(){
  const list=qs("#gratitudeJar");list.innerHTML="";
  if(!state.gratitudes.length){
    list.append(textElement("p","Tu frasco está listo para la primera gratitud."));
    return;
  }
  for(const item of state.gratitudes){
    const card=document.createElement("article");card.className="gratitude-card";
    card.append(textElement("p","🌟 "+item.text));
    const actions=document.createElement("div");actions.className="item-actions";
    const remove=document.createElement("button");remove.type="button";remove.className="remove";remove.textContent="Eliminar";
    remove.onclick=()=>{state.gratitudes=state.gratitudes.filter(x=>x.id!==item.id);save();renderGratitudes();renderSummary()};
    actions.append(remove);card.append(actions);list.append(card);
  }
}

qsa("[data-boundary]").forEach(input=>{
  input.checked=!!state.boundaries[input.dataset.boundary];
  input.addEventListener("change",()=>{
    state.boundaries[input.dataset.boundary]=input.checked;save();renderSummary();
  });
});

const boundaryScenarios=[
  {text:"Un amigo te cuenta que un adulto lo amenaza y te pide que jures no decírselo a nadie.",safe:false,why:"No hace falta cargar solo/a con un secreto peligroso. Lo responsable es buscar a una persona adulta de confianza."},
  {text:"Una compañera está triste y le preguntas si quiere hablar. Si dice que no, respetas su decisión.",safe:true,why:"Escuchar y respetar un no también es ayudar."},
  {text:"Alguien por internet dice necesitar ayuda urgente y te pide tu contraseña para entrar a una cuenta.",safe:false,why:"Ayudar nunca requiere entregar contraseñas ni códigos."},
  {text:"Ves basura en un espacio común y la recoges usando una forma segura.",safe:true,why:"Es una acción solidaria que no te expone a un riesgo innecesario."},
  {text:"Una persona te pide dinero en secreto y te dice que si no das eres egoísta.",safe:false,why:"La culpa y el secreto son señales para parar y pedir orientación."},
  {text:"Un amigo se lastimó y buscas rápidamente a una persona adulta responsable.",safe:true,why:"Pedir ayuda adecuada es una forma importante de cuidar."},
  {text:"Para defender a alguien, piensas en enfrentarte físicamente con otra persona.",safe:false,why:"Ayudar no significa ponerte en peligro. Busca apoyo adulto o institucional."},
  {text:"Compartes materiales escolares con alguien porque quieres y sin quedarte tú sin lo necesario.",safe:true,why:"Ayudar con límites también cuida tus propias necesidades."},
  {text:"Una persona te pide una foto íntima para demostrar que confías en ella.",safe:false,why:"La confianza nunca se demuestra enviando contenido íntimo."},
  {text:"Alguien está solo en el recreo y le preguntas si quiere sumarse, aceptando su respuesta.",safe:true,why:"Ofrecer compañía sin imponerla respeta a la otra persona."}
];

function renderBoundaryScenario(){
  const card=qs("#boundaryScenario");
  if(state.boundaryQuiz.completed){
    card.innerHTML="<h3>Completaste las 10 situaciones</h3><p>Practicaste que ayudar también implica cuidarte y pedir apoyo cuando hace falta.</p><button id='restartBoundary'>Practicar de nuevo</button>";
    qs("#restartBoundary").onclick=()=>{state.boundaryQuiz={index:0,completed:false};save();renderBoundaryScenario();renderBoundaryBadges();renderSummary()};
    renderBoundaryBadges();return;
  }
  const i=state.boundaryQuiz.index;const item=boundaryScenarios[i];
  card.innerHTML="";
  card.append(textElement("h3","Situación "+(i+1)+" de "+boundaryScenarios.length),textElement("p",item.text));
  const actions=document.createElement("div");actions.className="scenario-actions";
  const safe=document.createElement("button");safe.type="button";safe.textContent="✅ Es una ayuda segura";safe.onclick=()=>answerBoundary(item.safe,item);
  const pause=document.createElement("button");pause.type="button";pause.textContent="🛑 Paro y busco apoyo";pause.onclick=()=>answerBoundary(!item.safe,item);
  actions.append(safe,pause);card.append(actions);
}
function answerBoundary(correct,item){
  let f=qs("#boundaryScenario .feedback");if(f)f.remove();
  f=document.createElement("div");f.className="feedback";
  f.textContent=(correct?"¡Bien pensado! ":"Gracias por intentarlo. ")+item.why;
  qs("#boundaryScenario").append(f);
  if(correct)setTimeout(()=>{
    state.boundaryQuiz.index++;
    if(state.boundaryQuiz.index>=boundaryScenarios.length)state.boundaryQuiz.completed=true;
    save();renderBoundaryScenario();renderBoundaryBadges();renderSummary();
  },650);
}
function renderBoundaryBadges(){
  const wrap=qs("#boundaryBadges");wrap.innerHTML="";
  if(state.boundaryQuiz.index>=5||state.boundaryQuiz.completed)wrap.innerHTML+="<span class='badge'>🧭 Ayudo con límites</span>";
  if(state.boundaryQuiz.completed)wrap.innerHTML+="<span class='badge'>🫶 Sé cuándo pedir apoyo</span>";
}

qs("#mottoForm").addEventListener("submit",event=>{
  event.preventDefault();
  state.motto=qs("#mottoText").value.trim();
  save();renderMotto();renderSummary();
});
function renderMotto(){
  qs("#mottoText").value=state.motto||"";
  qs("#mottoPreview").textContent="“"+(state.motto||"Cada gesto cuenta.")+"”";
}

function renderSummary(){
  const doneChallenges=Object.values(state.challenges).filter(Boolean).length;
  const stats=qs("#stats");stats.innerHTML="";
  for(const [value,label] of [
    [state.actions.length,"acciones"],
    [doneChallenges,"desafíos"],
    [state.gratitudes.length,"gratitudes"]
  ]){
    const box=document.createElement("div");box.className="stat";
    box.append(textElement("strong",value),textElement("span",label));stats.append(box);
  }
  const boundaryPart=Object.values(state.boundaries).filter(Boolean).length/6;
  const quizPart=state.boundaryQuiz.completed?1:Math.min(state.boundaryQuiz.index/boundaryScenarios.length,1);
  const actionsPart=Math.min(state.actions.length/3,1);
  const challengePart=Math.min(doneChallenges/3,1);
  const gratitudePart=Math.min(state.gratitudes.length/3,1);
  const mottoPart=state.motto?1:0;
  const pct=Math.round(((boundaryPart+quizPart+actionsPart+challengePart+gratitudePart+mottoPart)/6)*100);
  qs("#progressBar").style.width=pct+"%";
  qs("#progressText").textContent=pct+"% completado";
  qs(".progress-shell").setAttribute("aria-valuenow",String(pct));
}

qs("#helpButton").onclick=()=>qs("#helpDialog").showModal();
qs("#resetAll").onclick=()=>{
  if(confirm("¿Seguro que quieres borrar el recorrido local de este proyecto?")){
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

renderActions();renderChallenges();renderGratitudes();renderBoundaryScenario();renderBoundaryBadges();renderMotto();renderSummary();
