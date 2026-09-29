const LOCAL_STATE_NAME="privacy-shield-v1";
const state=JSON.parse(localStorage.getItem(LOCAL_STATE_NAME)||"{}");
state.dataQuiz=state.dataQuiz||{index:0,completed:false};
state.keyRules=state.keyRules||{};
state.permissions=state.permissions||{};
state.trapQuiz=state.trapQuiz||{index:0,completed:false};
state.shield=state.shield||{};
state.recovery=state.recovery||{};

const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];
const save=()=>localStorage.setItem(LOCAL_STATE_NAME,JSON.stringify(state));

qsa(".tab").forEach(btn=>btn.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  btn.classList.add("active");
  qs("#"+btn.dataset.view).classList.add("active");
}));

const dataItems=[
  {text:"Mi contraseña de una cuenta",level:"private",why:"Las contraseñas son privadas y no se comparten."},
  {text:"Mi dirección exacta",level:"private",why:"La dirección exacta permite ubicar dónde vivo."},
  {text:"El nombre de mi videojuego favorito",level:"shareable",why:"Un gusto general suele ser menos sensible que un dato que me identifica o ubica."},
  {text:"Mi escuela y el horario en que salgo",level:"private",why:"Combina lugar y rutina; conviene protegerlo."},
  {text:"Una foto donde aparece el uniforme de mi escuela",level:"ask",why:"Puede revelar información indirecta. Es mejor revisar antes de publicar."},
  {text:"Un dibujo que hice sin mi nombre completo",level:"shareable",why:"Puede compartirse si no contiene otros datos personales."},
  {text:"Un código que llegó por SMS para iniciar sesión",level:"private",why:"Los códigos de verificación funcionan como una llave temporal."},
  {text:"Mi ubicación en tiempo real",level:"private",why:"Muestra dónde estoy en ese momento."},
  {text:"Una foto de un amigo",level:"ask",why:"Antes de publicar a otra persona, debo pedir permiso."},
  {text:"Mi color favorito",level:"shareable",why:"Es un dato general que normalmente no permite identificarme por sí solo."},
  {text:"Una captura donde se ve mi correo y número de teléfono",level:"private",why:"La captura contiene datos de contacto personales."},
  {text:"El nombre de una plaza donde quiero reunirme",level:"ask",why:"Antes de publicar planes o lugares conviene revisarlo con una persona de confianza."}
];
const dataLabels={private:"🔒 Lo protejo",ask:"🤔 Pregunto primero",shareable:"🙂 Puede ser compartible"};

function renderDataQuiz(){
  const card=qs("#dataCard");
  if(state.dataQuiz.completed){
    card.innerHTML="<h3>Completaste la práctica de datos</h3><p>Aprendiste que no todo dato tiene el mismo nivel de privacidad.</p><button id='restartData'>Practicar de nuevo</button>";
    qs("#restartData").onclick=()=>{state.dataQuiz={index:0,completed:false};save();renderDataQuiz();renderDataBadges();renderProgress()};
    renderDataBadges();return;
  }
  const i=state.dataQuiz.index;
  const item=dataItems[i];
  card.innerHTML="";
  const h=document.createElement("h3");h.textContent="Dato "+(i+1)+" de "+dataItems.length;
  const p=document.createElement("p");p.textContent=item.text;
  const actions=document.createElement("div");actions.className="data-actions";
  ["private","ask","shareable"].forEach(level=>{
    const b=document.createElement("button");b.type="button";b.textContent=dataLabels[level];
    b.onclick=()=>answerData(level===item.level,item);
    actions.append(b);
  });
  card.append(h,p,actions);
}

function answerData(correct,item){
  let f=qs("#dataCard .feedback");if(f)f.remove();
  f=document.createElement("div");f.className="feedback";
  f.textContent=(correct?"¡Bien pensado! ":"Buena práctica. Revisemos: ")+item.why+" → "+dataLabels[item.level]+".";
  qs("#dataCard").append(f);
  if(correct)setTimeout(()=>{
    state.dataQuiz.index++;
    if(state.dataQuiz.index>=dataItems.length)state.dataQuiz.completed=true;
    save();renderDataQuiz();renderDataBadges();renderProgress();
  },650);
}
function renderDataBadges(){
  const b=qs("#dataBadges");b.innerHTML="";
  if(state.dataQuiz.index>=6||state.dataQuiz.completed)b.innerHTML+="<span class='badge'>🔎 Miro antes de compartir</span>";
  if(state.dataQuiz.completed)b.innerHTML+="<span class='badge'>🔐 Cuido mis datos</span>";
}

const words=["mate","nube","rio","sol","bosque","puente","estrella","zorro","luna","tren","hoja","cielo","barco","farol","montaña","puma"];
qs("#makePhrase").onclick=()=>{
  const bytes=new Uint32Array(4);
  crypto.getRandomValues(bytes);
  const chosen=[...bytes].map(n=>words[n%words.length]);
  const number=(bytes[0]%90)+10;
  qs("#practicePhrase").textContent=chosen.join("-")+"-"+number;
};

qsa("[data-keyrule]").forEach(input=>{
  input.checked=!!state.keyRules[input.dataset.keyrule];
  input.addEventListener("change",()=>{state.keyRules[input.dataset.keyrule]=input.checked;save();renderProgress()});
});

const permissionHints={
  ask:"Buena idea: primero entiendo por qué la app lo pide.",
  needed:"Buena idea: doy el menor acceso necesario para la función.",
  always:"Conviene revisar si realmente necesita acceso permanente."
};
qsa("[data-permission]").forEach(select=>{
  select.value=state.permissions[select.dataset.permission]||"";
  const show=()=>{select.parentElement.querySelector(".hint").textContent=permissionHints[select.value]||""};
  show();
  select.addEventListener("change",()=>{state.permissions[select.dataset.permission]=select.value;save();show();renderProgress()});
});

const traps=[
  {text:"“Tu cuenta se cierra en 5 minutos. Entra YA a este enlace y escribe tu contraseña.”",safe:false,why:"La urgencia y el pedido de contraseña son señales para detenerse y entrar por el canal oficial."},
  {text:"La app oficial te muestra dentro de Configuración que hay una actualización disponible.",safe:true,why:"Revisar desde la propia app o tienda oficial evita depender de un enlace inesperado."},
  {text:"Un supuesto soporte te pide por chat el código de seis dígitos que acaba de llegarte.",safe:false,why:"Un código de verificación no debe compartirse con otra persona."},
  {text:"Escribes tú mismo la dirección del sitio oficial que conoces para revisar una alerta.",safe:true,why:"Entrar por tu cuenta al sitio oficial es una forma de verificar."},
  {text:"Un mensaje promete un premio si inicias sesión en una página con un nombre extraño.",safe:false,why:"Premio + enlace desconocido es una razón para no iniciar sesión y verificar por otro canal."},
  {text:"Un adulto de confianza te acompaña a recuperar una cuenta desde la opción oficial “Olvidé mi contraseña”.",safe:true,why:"Usar el proceso oficial de recuperación es una práctica adecuada."},
  {text:"Una persona dice ser moderador y te pide una captura donde aparece tu código de recuperación.",safe:false,why:"Los códigos de recuperación son llaves privadas."},
  {text:"Antes de aceptar un permiso, lees para qué se usa y eliges solo lo necesario.",safe:true,why:"Revisar propósito y minimizar permisos protege tu privacidad."},
  {text:"Un correo imita un logo conocido pero la dirección del remitente es rara y pide datos personales.",safe:false,why:"La apariencia no alcanza: remitente y solicitud deben verificarse."},
  {text:"Recibes una alerta y, en vez de tocar el enlace, abres la app oficial desde tu pantalla de inicio.",safe:true,why:"Es una buena manera de comprobar si la alerta es real."}
];

function renderTrapQuiz(){
  const card=qs("#trapCard");
  if(state.trapQuiz.completed){
    card.innerHTML="<h3>Completaste las 10 verificaciones</h3><p>Practicaste cómo frenar la urgencia y verificar por canales oficiales.</p><button id='restartTrap'>Practicar de nuevo</button>";
    qs("#restartTrap").onclick=()=>{state.trapQuiz={index:0,completed:false};save();renderTrapQuiz();renderTrapBadges();renderProgress()};
    renderTrapBadges();return;
  }
  const i=state.trapQuiz.index;const item=traps[i];
  card.innerHTML="";
  const h=document.createElement("h3");h.textContent="Situación "+(i+1)+" de "+traps.length;
  const p=document.createElement("p");p.textContent=item.text;
  const actions=document.createElement("div");actions.className="trap-actions";
  const verify=document.createElement("button");verify.type="button";verify.textContent="🛑 Paro y verifico";verify.onclick=()=>answerTrap(!item.safe,item);
  const continueBtn=document.createElement("button");continueBtn.type="button";continueBtn.textContent="✅ Parece una acción segura";continueBtn.onclick=()=>answerTrap(item.safe,item);
  actions.append(verify,continueBtn);card.append(h,p,actions);
}

function answerTrap(correct,item){
  let f=qs("#trapCard .feedback");if(f)f.remove();
  f=document.createElement("div");f.className="feedback";
  f.textContent=(correct?"¡Muy bien! ":"Gracias por pensarlo. ")+item.why;
  qs("#trapCard").append(f);
  if(correct)setTimeout(()=>{
    state.trapQuiz.index++;
    if(state.trapQuiz.index>=traps.length)state.trapQuiz.completed=true;
    save();renderTrapQuiz();renderTrapBadges();renderProgress();
  },650);
}
function renderTrapBadges(){
  const b=qs("#trapBadges");b.innerHTML="";
  if(state.trapQuiz.index>=5||state.trapQuiz.completed)b.innerHTML+="<span class='badge'>⏸️ No me apuro</span>";
  if(state.trapQuiz.completed)b.innerHTML+="<span class='badge'>🕵️ Verifico primero</span>";
}

qsa("[data-shield]").forEach(input=>{
  input.checked=!!state.shield[input.dataset.shield];
  input.addEventListener("change",()=>{state.shield[input.dataset.shield]=input.checked;save();renderProgress()});
});

function renderRecovery(){
  qs("#recoverySaved").textContent=state.recovery.name
    ?"Persona guardada: "+state.recovery.name+(state.recovery.relation?" · "+state.recovery.relation:"")
    :"";
}
qs("#recoveryForm").addEventListener("submit",e=>{
  e.preventDefault();
  state.recovery={name:qs("#recoveryName").value.trim(),relation:qs("#recoveryRelation").value.trim()};
  save();e.target.reset();renderRecovery();renderProgress();
});

function renderProgress(){
  const dataPart=state.dataQuiz.completed?1:Math.min(state.dataQuiz.index/dataItems.length,1);
  const keys=Object.values(state.keyRules).filter(Boolean).length/4;
  const permissions=Object.values(state.permissions).filter(Boolean).length/5;
  const trapPart=state.trapQuiz.completed?1:Math.min(state.trapQuiz.index/traps.length,1);
  const shield=Object.values(state.shield).filter(Boolean).length/5;
  const recovery=state.recovery.name?1:0;
  const pct=Math.round(((dataPart+keys+permissions+trapPart+shield+recovery)/6)*100);
  qs("#progressBar").style.width=pct+"%";
  qs("#progressText").textContent=pct+"% completado";
  qs(".progress-shell").setAttribute("aria-valuenow",String(pct));
}

qs("#credentialHelp").onclick=()=>qs("#helpDialog").showModal();
qs("#resetAll").onclick=()=>{
  if(confirm("¿Seguro que quieres borrar el progreso local de este proyecto?")){
    localStorage.removeItem(LOCAL_STATE_NAME);location.reload();
  }
};

let installPrompt=null;
window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;qs("#installBtn").classList.remove("hidden")});
qs("#installBtn").onclick=async()=>{
  if(!installPrompt)return;
  installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden");
};

if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));

renderDataQuiz();renderDataBadges();renderTrapQuiz();renderTrapBadges();renderRecovery();renderProgress();
