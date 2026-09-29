const STORAGE_KEY="cuadernoSeguridadDigital.v1";
const state=JSON.parse(localStorage.getItem(STORAGE_KEY)||"{}");
state.notes=state.notes||{}; state.progress=state.progress||{}; state.trusted=state.trusted||[]; state.profile=state.profile||{}; state.helpLog=state.helpLog||[]; state.quiz=state.quiz||{index:0,completed:false};

const save=()=>localStorage.setItem(STORAGE_KEY,JSON.stringify(state));
const qs=s=>document.querySelector(s);
const qsa=s=>[...document.querySelectorAll(s)];

qsa(".tab").forEach(btn=>btn.addEventListener("click",()=>{
  qsa(".tab,.view").forEach(el=>el.classList.remove("active"));
  btn.classList.add("active"); qs("#"+btn.dataset.view).classList.add("active");
}));

qsa("[data-note]").forEach(el=>{el.value=state.notes[el.dataset.note]||"";el.addEventListener("input",()=>{state.notes[el.dataset.note]=el.value;save()})});
qsa("[data-progress]").forEach(el=>{el.checked=!!state.progress[el.dataset.progress];el.addEventListener("change",()=>{state.progress[el.dataset.progress]=el.checked;save();renderProgress()})});

function renderTrusted(){
  const list=qs("#trustedList");list.innerHTML="";
  state.trusted.forEach((p,i)=>{
    const li=document.createElement("li");
    const text=document.createElement("span");
    text.textContent=[p.name,p.relation,p.phone].filter(Boolean).join(" · ");
    const del=document.createElement("button");del.type="button";del.textContent="Quitar";
    del.addEventListener("click",()=>{state.trusted.splice(i,1);save();renderTrusted()});
    li.append(text,del);list.append(li);
  });
}
qs("#trustedForm").addEventListener("submit",e=>{
  e.preventDefault();
  state.trusted.push({name:qs("#trustedName").value.trim(),phone:qs("#trustedPhone").value.trim(),relation:qs("#trustedRelation").value.trim()});
  e.target.reset();save();renderTrusted();
});

const questions=[
["Una persona que conociste en un juego te pide tu dirección para mandarte un regalo.",["Le doy mi dirección.","No la comparto y se lo cuento a alguien de confianza."],1,"Tus datos personales ayudan a cuidar tu privacidad."],
["Un amigo quiere subir una foto tuya que no te gusta.",["Le digo que no doy permiso.","Me callo aunque me incomode."],0,"Tienes derecho a decir que no a una publicación sobre ti."],
["Alguien te pide tu contraseña para demostrar amistad.",["La comparto.","No la comparto con nadie."],1,"Una amistad nunca necesita tu contraseña."],
["Recibes un mensaje que te hace sentir raro/a o incómodo/a.",["Lo cuento a un adulto de confianza.","Sigo conversando para no quedar mal."],0,"Tus sensaciones importan y pedir ayuda es una buena decisión."],
["Te amenazan con publicar una foto si no haces algo.",["Guardo evidencia y pido ayuda.","Borro todo y no se lo cuento a nadie."],0,"Guardar evidencia y buscar apoyo puede ayudar a resolver la situación."],
["Una app pide tu ubicación exacta sin una razón clara.",["La desactivo y pregunto a un adulto.","La dejo siempre encendida."],0,"Compartir menos ubicación protege tu privacidad."],
["Una persona dice tener tu edad pero no la conoces fuera de internet.",["Evito compartir datos privados y hablo con alguien de confianza.","Le mando fotos privadas."],0,"En internet no siempre sabemos quién está del otro lado."],
["Ves una publicación humillante sobre un compañero.",["No la comparto y busco ayuda.","La reenvío para que otros la vean."],0,"No amplificar el daño también es una forma de cuidar."],
["Te equivocaste y compartiste algo personal.",["Pido ayuda cuanto antes.","Pienso que ya no tiene solución."],0,"Siempre puedes pedir ayuda; equivocarse no te quita ese derecho."],
["Una conversación te genera miedo.",["Puedo salir, bloquear y pedir ayuda.","Tengo que seguir respondiendo."],0,"Tú decides cuándo terminar una conversación."],
];

function renderQuiz(){
 const box=qs("#quizCard"); const i=state.quiz.index||0;
 if(state.quiz.completed){box.innerHTML="<h3>Completaste las 10 situaciones</h3><p>Practicaste formas de cuidarte y pedir ayuda.</p><button id='restartQuiz'>Volver a practicar</button>";qs("#restartQuiz").onclick=()=>{state.quiz={index:0,completed:false};save();renderQuiz();renderBadges()};renderBadges();return;}
 const [q,opts,correct,explain]=questions[i]; box.innerHTML="";
 const h=document.createElement("h3");h.textContent="Situación "+(i+1)+" de "+questions.length;
 const p=document.createElement("p");p.textContent=q; const actions=document.createElement("div");actions.className="quiz-actions";
 opts.forEach((opt,idx)=>{const b=document.createElement("button");b.type="button";b.textContent=opt;b.onclick=()=>answerQuiz(idx===correct,explain);actions.append(b)});
 box.append(h,p,actions);
}
function answerQuiz(ok,explain){
 let f=qs(".quiz-feedback"); if(f)f.remove(); f=document.createElement("div");f.className="quiz-feedback";
 f.textContent=(ok?"¡Muy bien! Pensaste con cuidado. ":"Gracias por pensarlo. Probemos una opción más segura. ")+explain;
 qs("#quizCard").append(f);
 if(ok){setTimeout(()=>{state.quiz.index++; if(state.quiz.index>=questions.length)state.quiz.completed=true;save();renderQuiz();renderBadges();renderProgress()},650)}
}
function renderBadges(){const b=qs("#badges");b.innerHTML="";if(state.quiz.index>=5||state.quiz.completed)b.innerHTML+="<span class='badge'>🧭 Explorador seguro</span>";if(state.quiz.completed)b.innerHTML+="<span class='badge'>🛡️ Cuidador de mí mismo/a</span>"}

function renderProgress(){
 const lessonTotal=4;const lessons=Object.values(state.progress).filter(Boolean).length;const quizPart=state.quiz.completed?1:0;
 const pct=Math.round(((lessons+quizPart)/(lessonTotal+1))*100);qs("#progressBar").style.width=pct+"%";qs("#progressText").textContent=pct+"% completado";qs(".progress-shell").setAttribute("aria-valuenow",String(pct));
}

qs("#helpButton").onclick=()=>{
 const when=new Date().toISOString();state.helpLog.push({at:when});save();
 qs("#helpSaved").textContent="Guardamos en este dispositivo la fecha y hora de este pedido de ayuda.";
 qs("#helpDialog").showModal();
};
qs("#shareHelp").onclick=async()=>{
 const msg="Necesito hablar contigo. Algo en internet me hizo sentir incómodo/a y quiero pedirte ayuda.";
 try{if(navigator.share){await navigator.share({title:"Necesito ayuda",text:msg});return}}catch{}
 location.href="sms:?&body="+encodeURIComponent(msg);
};

qs("#profileName").value=state.profile.name||"";
qs("#profileColor").value=state.profile.color||"#4f46e5";
qs("#profileAvatar").value=state.profile.avatar||"🙂";
function applyProfile(){document.documentElement.style.setProperty("--accent",qs("#profileColor").value);qs("#avatarPreview").textContent=qs("#profileAvatar").value}
["#profileName","#profileColor","#profileAvatar"].forEach(sel=>qs(sel).addEventListener("input",()=>{state.profile={name:qs("#profileName").value.trim(),color:qs("#profileColor").value,avatar:qs("#profileAvatar").value};save();applyProfile()}));applyProfile();

async function hashPin(pin){const data=new TextEncoder().encode(pin);const hash=await crypto.subtle.digest("SHA-256",data);return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("")}
qs("#savePin").onclick=async()=>{const pin=qs("#pinInput").value;if(!/^\d{4}$/.test(pin)){alert("El PIN debe tener 4 números.");return}state.pinHash=await hashPin(pin);save();qs("#pinInput").value="";alert("PIN guardado en este dispositivo.")};
qs("#lockNow").onclick=()=>{if(!state.pinHash){alert("Primero guarda un PIN.");return}qs("#pinDialog").showModal()};
qs("#unlockForm").addEventListener("submit",async e=>{e.preventDefault();if(await hashPin(qs("#unlockPin").value)===state.pinHash){qs("#pinDialog").close();qs("#unlockPin").value="";qs("#pinError").textContent=""}else qs("#pinError").textContent="Ese PIN no coincide. Inténtalo otra vez."});

qs("#resetAll").onclick=()=>{if(confirm("¿Seguro que quieres borrar todos los datos de este cuaderno en este dispositivo?")){localStorage.removeItem(STORAGE_KEY);location.reload()}};

let installPrompt=null;window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;qs("#installBtn").classList.remove("hidden")});qs("#installBtn").onclick=async()=>{if(installPrompt){installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;qs("#installBtn").classList.add("hidden")}};

if("serviceWorker"in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/static/sw.js"));
renderTrusted();renderQuiz();renderBadges();renderProgress();
