const targetDialog=()=>document.querySelector('[data-target-dialog]');
const targetContent=()=>targetDialog()?.querySelector('[data-target-content]');
const deleteConfirmDialog=()=>document.querySelector('[data-delete-confirm-dialog]');
let pendingDeleteForm=null;
function isDeleteForm(form){
  if(!form?.matches?.('form'))return false;
  const action=formAttribute(form,'action','');
  return form.hasAttribute('data-target-delete-form')||/(?:^|\/)delete(?:[/?#]|$)/.test(action);
}
function requestDeleteConfirmation(form){
  const dlg=deleteConfirmDialog();
  if(!dlg){form.dataset.deleteConfirmed='1';form.requestSubmit();return}
  pendingDeleteForm=form;
  if(!dlg.open)dlg.showModal();
  requestAnimationFrame(()=>dlg.querySelector('[data-delete-confirm-no]')?.focus());
}
function cancelDeleteConfirmation(){
  pendingDeleteForm=null;
  deleteConfirmDialog()?.close();
}
function confirmDelete(){
  const form=pendingDeleteForm;
  pendingDeleteForm=null;
  deleteConfirmDialog()?.close();
  if(!form||!document.contains(form))return;
  form.dataset.deleteConfirmed='1';
  form.requestSubmit();
}

async function loadTargetModal(url){
  const dlg=targetDialog(),box=targetContent();
  if(!dlg||!box)return;
  box.innerHTML='<div class="modal-loading">Lade…</div>';
  if(!dlg.open)dlg.showModal();
  try{
    const r=await fetch(url,{credentials:'same-origin',headers:{'X-Requested-With':'fetch'}});
    const html=await r.text();
    if(!r.ok)throw new Error(html||`HTTP ${r.status}`);
    box.innerHTML=html;
    initTargetEditor(box);
  }catch(err){
    box.innerHTML=`<div class="error modal-load-error">Ziel-Editor konnte nicht geladen werden.<br><span>${escapeHtml(String(err.message||err))}</span></div>`;
  }
}

function formAttribute(form,name,fallback=''){
  // Never read native form properties directly here. Controls named "method", "action",
  // "name" etc. become named properties on HTMLFormElement and can shadow the
  // native form properties. Reading the literal HTML attribute avoids that class
  // of browser-only bugs completely.
  const value=form?.getAttribute?.(name);
  return value==null||value===''?fallback:String(value);
}
function responseErrorMessage(data,status){
  if(typeof data?.detail==='string')return data.detail;
  if(Array.isArray(data?.detail))return data.detail.map(x=>x?.msg||x?.message||String(x)).join('; ');
  if(data?.detail&&typeof data.detail==='object')return data.detail.message||JSON.stringify(data.detail);
  if(typeof data?.error==='string')return data.error;
  return `HTTP ${status}`;
}
function setFormBusy(form,busy){
  if(!form)return;
  form.dataset.submitting=busy?'1':'0';
  form.querySelectorAll('button[type="submit"],button:not([type])').forEach(btn=>{
    if(busy){if(!('oldText' in btn.dataset))btn.dataset.oldText=btn.textContent;btn.disabled=true;btn.textContent='…'}
    else{btn.disabled=false;if('oldText' in btn.dataset){btn.textContent=btn.dataset.oldText;delete btn.dataset.oldText}}
  });
}
async function submitTargetModalForm(form){
  const box=targetContent();
  if(!box||form.dataset.submitting==='1')return;
  const action=formAttribute(form,'action',location.href);
  const method=formAttribute(form,'method','POST').trim().toUpperCase();
  setFormBusy(form,true);
  try{
    const r=await fetch(action,{method,body:new FormData(form),credentials:'same-origin',headers:{'X-Requested-With':'fetch','Accept':'application/json,text/html'}});
    const ct=r.headers.get('content-type')||'';
    if(ct.includes('application/json')){
      let data={};try{data=await r.json()}catch{}
      if(!r.ok||!data.ok)throw new Error(responseErrorMessage(data,r.status));
      targetDialog()?.close();location.reload();return;
    }
    const html=await r.text();
    if(!r.ok)throw new Error(html||`HTTP ${r.status}`);
    box.innerHTML=html;initTargetEditor(box);
  }catch(err){
    const old=box?.querySelector('.modal-ajax-error');if(old)old.remove();
    box?.insertAdjacentHTML('afterbegin',`<div class="error modal-ajax-error">${escapeHtml(String(err.message||err))}</div>`);
  }finally{
    if(document.contains(form))setFormBusy(form,false);
  }
}

function escapeHtml(v){return v.replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}

function flowEditorForm(){return document.querySelector('[data-flow-editor-form]')}
function markFlowDirty(){const form=flowEditorForm();if(form)form.dataset.dirty='1'}
function showFlowSaveError(message){let box=document.querySelector('[data-flow-save-error]');if(!box){box=document.createElement('div');box.dataset.flowSaveError='1';box.className='error flow-save-error';document.querySelector('.flow-topbar')?.insertAdjacentElement('afterend',box)}box.textContent=message||'Flow konnte nicht gespeichert werden.'}
async function saveFlowBeforeTarget(){const form=flowEditorForm();if(!form||form.dataset.dirty!=='1')return true;if(form.dataset.submitting==='1')return false;setFormBusy(form,true);try{const action=formAttribute(form,'action',location.href),method=formAttribute(form,'method','POST').trim().toUpperCase();const r=await fetch(action,{method,body:new FormData(form),credentials:'same-origin',headers:{'X-Requested-With':'fetch','Accept':'application/json'}});let data={};try{data=await r.json()}catch{}if(!r.ok||!data.ok)throw new Error(responseErrorMessage(data,r.status));form.dataset.dirty='0';document.querySelector('[data-flow-save-error]')?.remove();return true}catch(err){showFlowSaveError(String(err.message||err));return false}finally{setFormBusy(form,false)}}
async function loadMoreRows(button){if(!button||button.dataset.loading==='1')return;const url=button.dataset.url,target=document.querySelector(`[data-load-more-target="${CSS.escape(button.dataset.target||'')}"]`);if(!url||!target)return;button.dataset.loading='1';button.disabled=true;const old=button.innerHTML;button.textContent='…';button.parentElement?.querySelector('.load-more-error')?.remove();try{const r=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{'X-Requested-With':'fetch','Accept':'text/html'}});const ct=(r.headers.get('content-type')||'').toLowerCase(),html=await r.text();if(!r.ok||!ct.includes('text/html'))throw new Error(button.dataset.loadError||'Weitere Events konnten nicht geladen werden.');const tpl=document.createElement('template');tpl.innerHTML=`<table><tbody>${html}</tbody></table>`;[...tpl.content.querySelectorAll('tr')].forEach(row=>target.appendChild(row));syncDiffSelection(button.dataset.target||'');const next=r.headers.get('X-Next-URL')||'';if(next){button.dataset.url=next;button.disabled=false;button.innerHTML=old}else button.closest('.load-more-wrap')?.remove()}catch(err){button.disabled=false;button.innerHTML=old;button.insertAdjacentHTML('afterend',`<span class="error-inline load-more-error">${escapeHtml(String(err.message||err))}</span>`)}finally{button.dataset.loading='0'}}
function eventFilterUrl(form,partial=false){
  const url=new URL(formAttribute(form,'action','/events'),location.origin),data=new FormData(form);
  for(const [key,value] of data.entries()){const v=String(value??'').trim();if(v)url.searchParams.append(key,v)}
  if(partial)url.searchParams.set('partial','true');
  return url;
}
function setEventsLoadMore(nextUrl){
  const host=document.querySelector('[data-events-load-more-host]');if(!host)return;
  const label=host.dataset.moreLabel||'Mehr anzeigen',loadError=host.dataset.loadError||'Weitere Events konnten nicht geladen werden.';host.innerHTML=nextUrl?`<div class="load-more-wrap"><button type="button" class="btn" data-load-more data-target="events-list" data-url="${escapeHtml(nextUrl)}" data-load-error="${escapeHtml(loadError)}">${escapeHtml(label)}</button></div>`:'';
}
async function submitEventsFilter(form){
  if(!form||form.dataset.loading==='1')return;
  const target=document.querySelector('[data-load-more-target="events-list"]'),panel=document.querySelector('[data-events-results-panel]');if(!target)return;
  form.dataset.loading='1';form.querySelector('.events-filter-error')?.remove();panel?.classList.add('events-filter-loading');
  const submit=form.querySelector('button[type="submit"]');if(submit)submit.disabled=true;
  try{
    const fetchUrl=eventFilterUrl(form,true),browserUrl=eventFilterUrl(form,false);
    const r=await fetch(fetchUrl.pathname+fetchUrl.search,{credentials:'same-origin',cache:'no-store',headers:{'X-Requested-With':'fetch','Accept':'text/html'}});
    const ct=(r.headers.get('content-type')||'').toLowerCase(),html=await r.text();
    if(!r.ok)throw new Error(html||`HTTP ${r.status}`);
    if(!ct.includes('text/html'))throw new Error(form.dataset.filterError||'Event search failed.');
    target.innerHTML=html;
    target.querySelectorAll('[data-event-diff-select]').forEach(box=>{box.checked=false;box.disabled=false});
    syncDiffSelection('events-list');
    setEventsLoadMore(r.headers.get('X-Next-URL')||'');
    history.replaceState(null,'',browserUrl.pathname+browserUrl.search);
  }catch(err){
    let box=form.querySelector('.events-filter-error');if(!box){box=document.createElement('div');box.className='error events-filter-error field full';form.appendChild(box)}box.textContent=String(err.message||err);
  }finally{
    form.querySelector('.events-filter-error:empty')?.remove();if(submit)submit.disabled=false;panel?.classList.remove('events-filter-loading');form.dataset.loading='0';
  }
}

function openClickableRow(row){const href=row?.dataset?.href;if(href)location.href=href}
function parseJsonScript(root,selector){try{return JSON.parse(root.querySelector(selector)?.textContent||'{}')}catch{return {}}}
function pathTokens(path){return String(path||'').match(/[^.[\]]+|\[(\d+)\]/g)?.map(x=>x.startsWith('[')?Number(x.slice(1,-1)):x)||[]}
function getPath(data,path){if(!String(path||'').trim())return undefined;let cur=data;for(const tok of pathTokens(path)){if(cur==null||!(tok in Object(cur)))return undefined;cur=cur[tok]}return cur}
function setPath(root,path,value){const toks=pathTokens(path);if(!toks.length)return;let cur=root;for(let i=0;i<toks.length;i++){const tok=toks[i],last=i===toks.length-1,next=toks[i+1];if(last){if(Array.isArray(cur)&&typeof tok==='number'){while(cur.length<=tok)cur.push(null);cur[tok]=value}else cur[tok]=value;continue}if(Array.isArray(cur)&&typeof tok==='number'){while(cur.length<=tok)cur.push(null);if(cur[tok]==null)cur[tok]=typeof next==='number'?[]:{};cur=cur[tok]}else{if(cur[tok]==null)cur[tok]=typeof next==='number'?[]:{};cur=cur[tok]}}}
function valueType(v){if(v===null)return'null';if(Array.isArray(v))return'array';if(typeof v==='boolean')return'boolean';if(typeof v==='number')return Number.isInteger(v)?'integer':'float';if(typeof v==='object')return'object';return'string'}
function staticTypeFor(t){return['integer','float'].includes(t)?'number':t}
function displayValue(v){if(v===undefined)return'';if(typeof v==='string')return `"${v}"`;try{return JSON.stringify(v)}catch{return String(v)}}
function leafFields(data,prefix=''){const out=[];if(data&&typeof data==='object'){if(Array.isArray(data)){data.forEach((v,i)=>{const p=`${prefix}[${i}]`;if(v&&typeof v==='object')out.push(...leafFields(v,p));else out.push({path:p,value:v,type:valueType(v)})})}else{Object.entries(data).forEach(([k,v])=>{const p=prefix?`${prefix}.${k}`:k;if(v&&typeof v==='object')out.push(...leafFields(v,p));else out.push({path:p,value:v,type:valueType(v)})})}}return out}

let draggedField=null;
function dragMetaFromElement(el){const root=el.closest('[data-target-editor-fragment]')||document;const ctx=root.matches?.('[data-target-editor-fragment]')?parseJsonScript(root,'[data-sample-context-json]'):parseJsonScript(document,'[data-flow-sample-json]');const path=el.dataset.dragPath||'';return{path,type:el.dataset.dragType||valueType(getPath(ctx,path)),value:getPath(ctx,path)}}

function conditionLabel(key,fallback){const labels=parseJsonScript(document,'[data-condition-labels]');return labels[key]||fallback}
const operators={
  string:[['equals','='],['not_equals','≠'],['contains',()=>conditionLabel('contains','contains')],['not_contains',()=>conditionLabel('not_contains','not contains')],['starts_with',()=>conditionLabel('starts_with','starts with')],['ends_with',()=>conditionLabel('ends_with','ends with')],['empty',()=>conditionLabel('empty','empty')],['not_empty',()=>conditionLabel('not_empty','not empty')],['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')]],
  number:[['equals','='],['not_equals','≠'],['gt','>'],['lt','<'],['gte','≥'],['lte','≤'],['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')]],
  boolean:[['true',()=>conditionLabel('true','true')],['false',()=>conditionLabel('false','false')],['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')]],
  null:[['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')],['equals','= null']],
  object:[['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')],['empty',()=>conditionLabel('empty','empty')],['not_empty',()=>conditionLabel('not_empty','not empty')]],
  array:[['exists',()=>conditionLabel('exists','exists')],['not_exists',()=>conditionLabel('not_exists','not exists')],['empty',()=>conditionLabel('empty','empty')],['not_empty',()=>conditionLabel('not_empty','not empty')]]
};
function opGroup(type){return operators[['integer','float'].includes(type)?'number':type]||operators.string}
function setConditionOperators(row,type,current){const sel=row.querySelector('[data-condition-operator]');if(!sel)return;const opts=opGroup(type);const wanted=current||sel.dataset.current||opts[0][0];sel.innerHTML=opts.map(([v,l])=>`<option value="${v}" ${v===wanted?'selected':''}>${typeof l==='function'?l():l}</option>`).join('');if(!opts.some(x=>x[0]===wanted))sel.value=opts[0][0];toggleConditionValue(row)}
function toggleConditionValue(row){const op=row.querySelector('[data-condition-operator]')?.value||'';const input=row.querySelector('[data-condition-value]');if(!input)return;const noValue=['exists','not_exists','true','false','empty','not_empty'].includes(op);input.disabled=noValue;input.closest('.condition-value')?.classList.toggle('is-disabled',noValue)}
function fillCondition(row,meta,overwriteValue=true){if(!row||!meta)return;const field=row.querySelector('[data-condition-field]'),value=row.querySelector('[data-condition-value]');field.value=meta.path;field.dataset.fieldType=meta.type;setConditionOperators(row,meta.type);if(overwriteValue&&value&&!['boolean'].includes(meta.type))value.value=meta.value==null?'':(typeof meta.value==='object'?JSON.stringify(meta.value):String(meta.value));if(meta.type==='boolean'){row.querySelector('[data-condition-operator]').value=meta.value?'true':'false';toggleConditionValue(row)}evaluateConditionRow(row)}
function createConditionRow(meta=null){const list=document.getElementById('rule-list'),tpl=document.getElementById('condition-template');if(!list||!tpl)return null;const i=Number(list.dataset.next||list.children.length);list.dataset.next=String(i+1);list.insertAdjacentHTML('beforeend',tpl.innerHTML.replaceAll('__i__',String(i)));const row=list.lastElementChild;if(meta)fillCondition(row,meta);return row}
function parseConditionTarget(v){if(v==='true')return true;if(v==='false')return false;if(v==='null')return null;if(v!==''&&!Number.isNaN(Number(v)))return Number(v);try{return JSON.parse(v)}catch{return v}}
function evaluateConditionRow(row){const ctx=parseJsonScript(document,'[data-flow-sample-json]');const path=row.querySelector('[data-condition-field]')?.value||'',op=row.querySelector('[data-condition-operator]')?.value||'',target=parseConditionTarget(row.querySelector('[data-condition-value]')?.value||'');const actual=getPath(ctx,path);let ok=false;if(op==='exists')ok=actual!==undefined;else if(op==='not_exists')ok=actual===undefined;else if(op==='empty')ok=actual===undefined||actual===null||actual===''||(Array.isArray(actual)&&!actual.length)||(actual&&typeof actual==='object'&&!Array.isArray(actual)&&!Object.keys(actual).length);else if(op==='not_empty')ok=!(actual===undefined||actual===null||actual===''||(Array.isArray(actual)&&!actual.length)||(actual&&typeof actual==='object'&&!Array.isArray(actual)&&!Object.keys(actual).length));else if(op==='true')ok=actual===true;else if(op==='false')ok=actual===false;else if(op==='equals')ok=String(actual)===String(target);else if(op==='not_equals')ok=String(actual)!==String(target);else if(op==='contains')ok=String(actual).includes(String(target));else if(op==='not_contains')ok=!String(actual).includes(String(target));else if(op==='starts_with')ok=String(actual).startsWith(String(target));else if(op==='ends_with')ok=String(actual).endsWith(String(target));else if(['gt','lt','gte','lte'].includes(op)){const a=Number(actual),b=Number(target);ok=op==='gt'?a>b:op==='lt'?a<b:op==='gte'?a>=b:a<=b}const res=row.querySelector('[data-condition-result]');if(res)res.textContent=path?(ok?'✓':'×'):'';if(res)res.classList.toggle('ok',ok)}
function initConditions(){document.querySelectorAll('[data-condition-row]').forEach(row=>{const path=row.querySelector('[data-condition-field]')?.value||'';const src=[...document.querySelectorAll(`[data-drag-path]`)].find(x=>x.dataset.dragPath===path);const meta=src?dragMetaFromElement(src):{path,type:'string',value:undefined};setConditionOperators(row,meta.type,row.querySelector('[data-condition-operator]')?.dataset.current);evaluateConditionRow(row)})}

function targetRoot(el=document){return el.closest?.('[data-target-editor-fragment]')||document.querySelector('[data-target-editor-fragment]')}
function targetSample(root){return{body:parseJsonScript(root,'[data-sample-body-json]'),context:parseJsonScript(root,'[data-sample-context-json]')}}
function newMappingRow(root,meta=null,isStatic=false){const list=root.querySelector('#route-map-list'),tpl=root.querySelector('#route-map-template');if(!list||!tpl)return null;const i=Number(list.dataset.next||list.children.length);list.dataset.next=String(i+1);list.insertAdjacentHTML('beforeend',tpl.innerHTML.replaceAll('__i__',String(i)));const row=list.lastElementChild;if(isStatic){row.querySelector('[data-map-source-type]').value='static';row.querySelector('[data-map-source]').placeholder='Wert';row.querySelector('.map-target input')?.focus()}else if(meta)fillMappingRow(root,row,meta,true);updateMappingRow(root,row);renderOutgoingPreview(root);return row}
function fillMappingRow(root,row,meta,autoTarget=false){if(!row||!meta)return;const source=row.querySelector('[data-map-source]'),target=row.querySelector('.map-target input'),stype=row.querySelector('[data-map-source-type]'),typeSel=row.querySelector('[data-map-static-type]');stype.value='field';source.value=meta.path;source.dataset.fieldType=meta.type;if(autoTarget&&!target.value)target.value=meta.path;if(typeSel)typeSel.value=staticTypeFor(meta.type);updateMappingRow(root,row)}
function parseStatic(v,t){if(t==='null')return null;if(t==='boolean')return ['true','1','yes','on'].includes(String(v).toLowerCase());if(t==='number'){const n=Number(v);return Number.isNaN(n)?0:n}if(['object','array'].includes(t)){try{return JSON.parse(v)}catch{return t==='array'?[]:{}}}return String(v)}
function applyPreviewTransform(v,op,arg){if(!op)return v;if(op==='lowercase')return String(v).toLowerCase();if(op==='uppercase')return String(v).toUpperCase();if(op==='trim')return String(v).trim();if(op==='prefix')return String(arg)+String(v);if(op==='suffix')return String(v)+String(arg);if(op==='replace'){const [a,b='']=String(arg).split('=>',2);return String(v).replaceAll(a,b)}if(op==='add')return Number(v)+Number(arg);if(op==='subtract')return Number(v)-Number(arg);if(op==='multiply')return Number(v)*Number(arg);if(op==='divide')return Number(v)/Number(arg);if(op==='round')return Number(Number(v).toFixed(Number(arg||0)));if(op==='invert')return !Boolean(v);return v}
function mappingValue(root,row){const sample=targetSample(root).context,type=row.querySelector('[data-map-source-type]')?.value||'field',src=row.querySelector('[data-map-source]')?.value||'',staticType=row.querySelector('[data-map-static-type]')?.value||'string';let value;if(type==='field')value=getPath(sample,src);else if(type==='static')value=parseStatic(src,staticType);else value=src.replace(/\{\{\s*([^}]+?)\s*\}\}/g,(_,p)=>{const v=getPath(sample,p);return v===undefined||v===null?'':String(v)});const op=row.querySelector('[name^="map_transform_"]')?.value||'',arg=row.querySelector('[name^="map_transform_arg_"]')?.value||'';return applyPreviewTransform(value,op,arg)}
function updateMappingRow(root,row){const stype=row.querySelector('[data-map-source-type]')?.value||'field',src=row.querySelector('[data-map-source]'),typeSel=row.querySelector('[data-map-static-type]'),sample=targetSample(root).context;let v,type;if(stype==='field'){v=getPath(sample,src.value);type=v===undefined?'—':valueType(v);src.placeholder='Incoming Feld';if(v!==undefined&&typeSel)typeSel.value=staticTypeFor(type)}else if(stype==='static'){v=parseStatic(src.value,typeSel?.value||'string');type=typeSel?.value||'string';src.placeholder='Statischer Wert'}else{v=mappingValue(root,row);type=valueType(v);src.placeholder='{{ first_name }} {{ last_name }}'}const badge=row.querySelector('[data-map-type]'),preview=row.querySelector('[data-map-value-preview]');if(badge)badge.textContent=type;if(preview)preview.textContent=v===undefined?'':displayValue(v)}
function renderOutgoingPreview(root){const out={};root.querySelectorAll('[data-map-row]').forEach(row=>{const target=row.querySelector('.map-target input')?.value.trim();if(!target)return;try{setPath(out,target,mappingValue(root,row))}catch{}});const pre=root.querySelector('[data-outgoing-preview]');if(pre)pre.textContent=JSON.stringify(out,null,2)}
function initTargetEditor(root=document){const frag=root.matches?.('[data-target-editor-fragment]')?root:root.querySelector('[data-target-editor-fragment]');if(!frag)return;const mode=frag.querySelector('input[name="request_mode"]:checked')?.value||'passthrough';frag.querySelector('[data-custom-request]')?.toggleAttribute('hidden',mode!=='custom');frag.querySelector('[data-custom-method-panel]')?.toggleAttribute('hidden',mode!=='custom');frag.querySelectorAll('[data-map-row]').forEach(row=>updateMappingRow(frag,row));renderOutgoingPreview(frag)}

function handleFieldDrop(target,meta){if(!meta)return;if(target.matches('[data-condition-dropzone]')){createConditionRow(meta);markFlowDirty();return}if(target.matches('[data-mapping-dropzone]')){const root=targetRoot(target);newMappingRow(root,meta,false);return}const input=target.closest('.drop-path');if(!input)return;const cRow=input.closest('[data-condition-row]'),mRow=input.closest('[data-map-row]');if(mRow&&mRow.querySelector('[data-map-source-type]')?.value==='combine'){const token=`{{${meta.path}}}`,start=Number.isInteger(input.selectionStart)?input.selectionStart:input.value.length,end=Number.isInteger(input.selectionEnd)?input.selectionEnd:start;input.value=input.value.slice(0,start)+token+input.value.slice(end);const pos=start+token.length;try{input.focus();input.setSelectionRange(pos,pos)}catch{}const root=targetRoot(mRow);updateMappingRow(root,mRow);renderOutgoingPreview(root);input.dispatchEvent(new Event('input',{bubbles:true}));return}input.value=meta.path;input.dispatchEvent(new Event('change',{bubbles:true}));if(cRow){fillCondition(cRow,meta,true);markFlowDirty()}if(mRow){const root=targetRoot(mRow);fillMappingRow(root,mRow,meta,!mRow.querySelector('.map-target input')?.value);renderOutgoingPreview(root)}}


function diffScope(targetName){return document.querySelector(`[data-diff-selection-scope="${CSS.escape(targetName||'')}"]`)}
function diffCheckboxes(targetName){const scope=diffScope(targetName);return scope?[...scope.querySelectorAll('[data-event-diff-select]')]:[]}
function syncDiffSelection(targetName){
  const boxes=diffCheckboxes(targetName),checked=boxes.filter(box=>box.checked),locked=checked.length>=2;
  boxes.forEach(box=>{box.disabled=locked&&!box.checked});
  const button=document.querySelector(`[data-json-diff-button][data-target="${CSS.escape(targetName||'')}"]`);
  if(button)button.disabled=checked.length!==2;
}
function openSelectedJsonDiff(button){
  const targetName=button?.dataset.target||'',ids=diffCheckboxes(targetName).filter(box=>box.checked).map(box=>box.dataset.eventId).filter(Boolean);
  if(ids.length!==2)return;
  const url=new URL('/events/compare',location.origin);url.searchParams.set('first',ids[0]);url.searchParams.set('second',ids[1]);location.href=url.pathname+url.search;
}

function startLiveDeliveries(tbody){
  if(!tbody||tbody.dataset.liveStarted==='1')return;
  tbody.dataset.liveStarted='1';
  let stopped=false,attempts=0;
  const poll=async()=>{
    if(stopped||!document.contains(tbody))return;
    attempts+=1;
    try{
      const r=await fetch(tbody.dataset.url,{credentials:'same-origin',cache:'no-store',headers:{'X-Requested-With':'fetch'}});
      const html=await r.text();
      if(!r.ok)throw new Error(html||`HTTP ${r.status}`);
      tbody.innerHTML=html;
      const nextStatus=r.headers.get('X-Event-Status')||'';tbody.dataset.eventStatus=nextStatus;
      const pending=r.headers.get('X-Deliveries-Pending')==='1';
      if(!pending){stopped=true;return}
    }catch(err){
      if(attempts>=60){stopped=true;return}
    }
    if(attempts<120)setTimeout(poll,750);
  };
  // Always do at least one refresh. A replay can reach a terminal event state
  // just before this page is rendered while its final delivery row is still
  // being committed by the worker.
  setTimeout(poll,350);
}
function initLiveDeliveries(){document.querySelectorAll('[data-live-deliveries]').forEach(startLiveDeliveries)}

// Generic UI actions.
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-copy]');if(b){navigator.clipboard.writeText(b.dataset.copy);const old=b.innerHTML;b.textContent='✓';setTimeout(()=>b.innerHTML=old,1000);return}
  const add=e.target.closest('[data-add-row]');if(add){const id=add.dataset.target||add.dataset.addRow,target=document.getElementById(id)||document.querySelector(id||''),tpl=document.getElementById(add.dataset.template)||document.querySelector(add.dataset.template||'');if(target&&tpl){const i=Number(target.dataset.next||target.children.length);target.dataset.next=String(i+1);target.insertAdjacentHTML('beforeend',tpl.innerHTML.replaceAll('__i__',String(i)))}return}
  const addCond=e.target.closest('[data-add-condition]');if(addCond){createConditionRow();markFlowDirty();return}
  const rm=e.target.closest('[data-remove-row]');if(rm){const row=rm.closest('[data-row]'),root=row?targetRoot(row):null;if(row)row.remove();if(root?.matches?.('[data-target-editor-fragment]'))renderOutgoingPreview(root);if(row?.matches?.('[data-condition-row]'))markFlowDirty();return}
  const modalLink=e.target.closest('[data-target-modal]');if(modalLink){e.preventDefault();if(modalLink.hasAttribute('data-flow-save-before-target')){const ok=await saveFlowBeforeTarget();if(!ok)return}loadTargetModal(modalLink.href);return}
  const more=e.target.closest('[data-load-more]');if(more){e.preventDefault();await loadMoreRows(more);return}
  const diffButton=e.target.closest('[data-json-diff-button]');if(diffButton){e.preventDefault();openSelectedJsonDiff(diffButton);return}
  const row=e.target.closest('.clickable-row');if(row&&!e.target.closest('a,button,input,select,textarea,label')){openClickableRow(row);return}
  const deleteNo=e.target.closest('[data-delete-confirm-no]');if(deleteNo){cancelDeleteConfirmation();return}
  const deleteYes=e.target.closest('[data-delete-confirm-yes]');if(deleteYes){confirmDelete();return}
  const closeModal=e.target.closest('[data-close-target-modal]');if(closeModal){targetDialog()?.close();return}
  const exportButton=e.target.closest('[data-export-button]');if(exportButton){const form=exportButton.closest('[data-export-form]'),toggle=form?.querySelector('[data-export-secrets-toggle]');if(toggle?.checked)form.requestSubmit();else location.href=form?.dataset.normalUrl||'/settings/export';return}
  const theme=e.target.closest('[data-theme]');if(theme){document.body.classList.toggle('light');localStorage.setItem('zentwhook-theme',document.body.classList.contains('light')?'light':'dark');return}
  const all=e.target.closest('[data-add-all-mappings]');if(all){const root=targetRoot(all),sample=targetSample(root).body;leafFields(sample).forEach(meta=>{if(![...root.querySelectorAll('[data-map-source]')].some(el=>el.value===meta.path))newMappingRow(root,meta,false)});renderOutgoingPreview(root);return}
  const stat=e.target.closest('[data-add-static-mapping]');if(stat){newMappingRow(targetRoot(stat),null,true);return}
});

document.addEventListener('submit',e=>{const submitted=e.target;if(isDeleteForm(submitted)){if(submitted.dataset.deleteConfirmed!=='1'){e.preventDefault();requestDeleteConfirmation(submitted);return}delete submitted.dataset.deleteConfirmed}const eventFilters=submitted.closest('[data-events-filter-form]');if(eventFilters){e.preventDefault();submitEventsFilter(eventFilters);return}const flow=submitted.closest('[data-flow-editor-form]');if(flow)flow.dataset.dirty='0';const dlg=submitted.closest('[data-target-dialog]');if(!dlg)return;const form=submitted.closest('[data-target-editor-form],[data-target-delete-form]');if(!form)return;e.preventDefault();submitTargetModalForm(form)});

document.addEventListener('change',async e=>{
  const diffSelect=e.target.closest('[data-event-diff-select]');if(diffSelect){const scope=diffSelect.closest('[data-diff-selection-scope]');syncDiffSelection(scope?.dataset.diffSelectionScope||'');return}
  const exportToggle=e.target.closest('[data-export-secrets-toggle]');if(exportToggle){const form=exportToggle.closest('[data-export-form]'),button=form?.querySelector('[data-export-button]'),label=button?.querySelector('[data-export-button-label]');if(label)label.textContent=exportToggle.checked?button.dataset.labelSecret:button.dataset.labelNormal;button?.classList.toggle('danger',exportToggle.checked);return}
  if(e.target.closest('[data-flow-editor-form]')&&!e.target.closest('[data-flow-sample-select]'))markFlowDirty();
  const mode=e.target.closest('input[name="request_mode"]');if(mode){initTargetEditor(targetRoot(mode));return}
  const targetSampleSelect=e.target.closest('[data-target-sample-select]');if(targetSampleSelect){const root=targetRoot(targetSampleSelect),base=root?.dataset.sampleBase;if(!base)return;const form=root.querySelector('[data-target-editor-form]'),url=new URL(base,location.origin);if(form?.querySelector('[name="modal"]')?.value==='1')url.searchParams.set('modal','1');const branch=form?.querySelector('[name="branch"]')?.value;if(branch)url.searchParams.set('branch',branch);if(targetSampleSelect.value)url.searchParams.set('sample_event',targetSampleSelect.value);if(form?.querySelector('[name="modal"]')?.value==='1')loadTargetModal(url.toString());else location.href=url.toString();return}
  const flowSample=e.target.closest('[data-flow-sample-select]');if(flowSample){const url=new URL(location.href);if(flowSample.value)url.searchParams.set('sample_event',flowSample.value);else url.searchParams.delete('sample_event');url.searchParams.delete('new_target');const ok=await saveFlowBeforeTarget();if(ok)location.href=url.toString();return}
  const cOp=e.target.closest('[data-condition-operator]');if(cOp){toggleConditionValue(cOp.closest('[data-condition-row]'));evaluateConditionRow(cOp.closest('[data-condition-row]'));return}
  const cField=e.target.closest('[data-condition-field]');if(cField){const src=[...document.querySelectorAll('[data-drag-path]')].find(x=>x.dataset.dragPath===cField.value);if(src)fillCondition(cField.closest('[data-condition-row]'),dragMetaFromElement(src),false);else evaluateConditionRow(cField.closest('[data-condition-row]'));return}
  const mapControl=e.target.closest('[data-map-source-type],[data-map-static-type],[name^="map_transform_"]');if(mapControl){const row=mapControl.closest('[data-map-row]'),root=targetRoot(row);if(mapControl.matches('[data-map-source-type]')&&mapControl.value==='field'){const src=row.querySelector('[data-map-source]'),sample=targetSample(root).context;if(src?.value&&getPath(sample,src.value)===undefined)src.value=''}updateMappingRow(root,row);renderOutgoingPreview(root);return}
});

document.addEventListener('input',e=>{
  if(e.target.closest('[data-flow-editor-form]'))markFlowDirty();
  const c=e.target.closest('[data-condition-value]');if(c){evaluateConditionRow(c.closest('[data-condition-row]'));return}
  const m=e.target.closest('[data-map-row] input');if(m){const row=m.closest('[data-map-row]'),root=targetRoot(row);updateMappingRow(root,row);renderOutgoingPreview(root)}
});

document.addEventListener('keydown',e=>{const row=e.target.closest('.clickable-row');if(row&&!e.target.closest('a,button,input,select,textarea,label')&&(e.key==='Enter'||e.key===' ')){e.preventDefault();openClickableRow(row)}});

document.addEventListener('dragstart',e=>{const f=e.target.closest('[data-drag-path]');if(!f)return;draggedField=dragMetaFromElement(f);e.dataTransfer?.setData('application/x-zentwhook-field',JSON.stringify(draggedField));e.dataTransfer?.setData('text/plain',draggedField.path);e.dataTransfer.effectAllowed='copy'});
document.addEventListener('dragover',e=>{const target=e.target.closest('.drop-path,[data-mapping-dropzone],[data-condition-dropzone]');if(!target)return;e.preventDefault();target.classList.add('dragover')});
document.addEventListener('dragleave',e=>{const target=e.target.closest('.drop-path,[data-mapping-dropzone],[data-condition-dropzone]');target?.classList.remove('dragover')});
document.addEventListener('drop',e=>{const target=e.target.closest('.drop-path,[data-mapping-dropzone],[data-condition-dropzone]');if(!target)return;e.preventDefault();target.classList.remove('dragover');let meta=draggedField;try{meta=JSON.parse(e.dataTransfer?.getData('application/x-zentwhook-field')||'null')||meta}catch{}if(!meta){const path=e.dataTransfer?.getData('text/plain')||'';meta={path,type:'string',value:''}}handleFieldDrop(target,meta)});

document.addEventListener('DOMContentLoaded',()=>{if(localStorage.getItem('zentwhook-theme')==='light')document.body.classList.add('light');initConditions();initTargetEditor(document);initLiveDeliveries();document.querySelectorAll('[data-diff-selection-scope]').forEach(scope=>syncDiffSelection(scope.dataset.diffSelectionScope||''));const auto=targetDialog()?.dataset.autoTargetUrl;if(auto)loadTargetModal(auto)});

const terminalDeliveryStatuses=new Set(['success','failed','skipped','cancelled']);
function startLiveDelivery(root){
  if(!root||root.dataset.liveStarted==='1')return;
  root.dataset.liveStarted='1';
  let attempts=0,stopped=false;
  const poll=async()=>{
    if(stopped||!document.contains(root))return;
    attempts+=1;
    try{
      const r=await fetch(root.dataset.url,{credentials:'same-origin',cache:'no-store',headers:{'X-Requested-With':'fetch'}});
      const data=await r.json();
      if(!r.ok)throw new Error(data?.detail||`HTTP ${r.status}`);
      root.innerHTML=data.summary_html||root.innerHTML;
      root.dataset.deliveryStatus=data.status||'';
      const response=document.querySelector('[data-live-delivery-response]');
      if(response&&data.response)response.textContent=data.response;
      const attemptRows=document.querySelector('[data-live-delivery-attempts]');
      if(attemptRows&&data.attempts_html)attemptRows.innerHTML=data.attempts_html;
      if(terminalDeliveryStatuses.has(data.status)){stopped=true;return}
    }catch(err){if(attempts>=80){stopped=true;return}}
    if(attempts<160)setTimeout(poll,750);
  };
  if(!terminalDeliveryStatuses.has(root.dataset.deliveryStatus||''))setTimeout(poll,250);
}
function initLiveDelivery(){document.querySelectorAll('[data-live-delivery]').forEach(startLiveDelivery)}
initLiveDelivery();

document.addEventListener('cancel',e=>{if(e.target.matches?.('[data-delete-confirm-dialog]'))pendingDeleteForm=null});
