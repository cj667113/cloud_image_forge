'use strict';
const studioState = {plans:{},helpId:0,requestId:0,helpOpenTimer:null,helpCloseTimer:null,dismissedHelp:new WeakSet()};
const MiB = 1024 ** 2, GiB = 1024 ** 3;
function studioImage() { return state.images.find(image => image.id === state.selected); }
function studioSession() { return studioState.plans[state.selected] ||= {}; }
function studioInspectionKey() { const image=studioImage();return JSON.stringify([image?.inspected_at||image?.updated_at,image?.inspection?.storage,image?.inspection?.platform,image?.inspection?.boot]); }
function helpHint(text,label='More information') {
  const id = `help-${++studioState.helpId}`;
  return `<span class="help-anchor"><button type="button" class="help-toggle" aria-label="${esc(label)}" aria-expanded="false" aria-controls="${id}" aria-describedby="${id}">?</button><span class="help-popover" role="tooltip" id="${id}">${esc(text)}</span></span>`;
}
function closeHelp(except=null) {
  clearTimeout(studioState.helpOpenTimer); clearTimeout(studioState.helpCloseTimer);
  document.querySelectorAll('.help-anchor.open').forEach(anchor => {
    if(anchor!==except) { anchor.classList.remove('open','pinned'); anchor.querySelector('.help-toggle')?.setAttribute('aria-expanded','false'); }
  });
}
function positionHelp(anchor) {
  const button=anchor.querySelector('.help-toggle'),popover=anchor.querySelector('.help-popover'),box=button.getBoundingClientRect();
  popover.style.left=`${Math.max(14,Math.min(innerWidth-popover.offsetWidth-14,box.right-popover.offsetWidth))}px`;
  popover.style.top=`${box.bottom+6+popover.offsetHeight>innerHeight?Math.max(14,box.top-popover.offsetHeight-6):box.bottom+6}px`;
}
function openHelp(anchor) {
  if(!anchor?.isConnected)return;
  closeHelp(anchor); anchor.classList.add('open');
  $('.help-toggle',anchor).setAttribute('aria-expanded','true'); positionHelp(anchor);
}
function scheduleHelpClose(anchor) {
  clearTimeout(studioState.helpOpenTimer); clearTimeout(studioState.helpCloseTimer);
  studioState.helpCloseTimer=setTimeout(()=>{
    if(!anchor.matches(':hover')&&!anchor.classList.contains('pinned')&&!anchor.contains(document.activeElement))closeHelp();
  },160);
}
function alignFieldHints(root) {
  $$('.field > .help-anchor',root).forEach(hint=>{
    const field=hint.parentElement;
    let heading=$(':scope > .field-label',field);
    if(!heading) {
      const control=[...field.children].find(node=>node.matches('input,select,textarea,.capacity-input'));
      if(!control)return;
      heading=document.createElement('span'); heading.className='field-label';
      for(const node of [...field.childNodes]) {
        if(node===control)break;
        if(node!==hint&&!node.matches?.('.code-label'))heading.append(node);
      }
      field.prepend(heading);
    }
    heading.append(hint);
  });
}
function compactStudioHelp(root=document) {
  $$('.field-help,.check-field small',root).forEach(node => {
    if (node.dataset.visibleHelp || node.dataset.compacted || node.closest('.help-anchor') || node.closest('#storage-studio,#platform-studio')) return;
    const owner = node.closest('label'); if (!owner || !node.textContent.trim()) return;
    const text=node.textContent.trim(),label=[...owner.childNodes].find(child=>child.nodeType===3&&child.textContent.trim())?.textContent.trim()||$(':scope > span',owner)?.firstChild?.textContent?.trim()||'this setting';node.dataset.compacted='true';
    const holder=document.createElement('span');holder.innerHTML=helpHint(text,`Help: ${label.slice(0,90)}`);
    owner.classList.add('has-help');owner.append(holder.firstElementChild);node.remove();
  });
  alignFieldHints(root);
  $$('.oci-capability',root).forEach(card => {
    const description=$(':scope > p',card),action=$('.oci-guest-action',card);if(description && !$('.oci-capability-title .help-anchor',card)) { $('.oci-capability-title',card).insertAdjacentHTML('beforeend',helpHint(description.textContent+(action?' '+action.textContent:''),'Capability details'));description.remove();action?.remove(); }
  });
}
function storageFilesystems() {
  const inspection=studioImage()?.inspection || {};
  if (Array.isArray(inspection.storage?.filesystems)) return inspection.storage.filesystems;
  return (inspection.partitions || []).filter(part => part.filesystem && !['LVM2_member','unknown'].includes(part.filesystem)).map(part => ({...part,kind:part.device.split('/').length>3?'lv':/vfat|fat/.test(part.filesystem)?'efi':'partition',editable:false,used:null,free:null}));
}
function getDiskCapacityBytes(unit=null) { const raw=$('#disk-size')?.value;if(!raw)return null;const value=Number(raw),scale=(unit||$('#disk-size-unit')?.value)==='gb'?1e9:GiB;return Math.ceil(value*scale/512)*512; }
function getDiskSizeGiB() { const value=getDiskCapacityBytes();return value===null?null:value/GiB; }
function storageSizeInputs() { return $$('[data-rebuild-device]'); }
function getStorageResizeConfig() {
  const explicit=$('#storage-rebuild-enabled')?.checked;
  if (!explicit) return getDiskSizeGiB()===null?null:{enabled:true,sizes:[]};
  for(const field of $$('[data-fs-size-input]')) {
    const unit=$('[data-fs-size-unit]',field.closest('[data-fs-device]')).value;
    field.min=String(unit==='gib'?32/1024:32);field.step=unit==='gib'?'any':'1';
    if(!field.checkValidity()) { const error=new Error(field.validationMessage||'Enter a valid partition capacity.');error.field=field;throw error; }
  }
  const sizes=storageSizeInputs().map(input=>({device:input.dataset.rebuildDevice,size_mib:Number(input.value)}));
  if(sizes.some(item=>!Number.isInteger(item.size_mib)||item.size_mib<32)) throw new Error('Filesystem capacities must be whole MiB of at least 32.');
  return {enabled:true,sizes};
}
function storagePlanBody(config=undefined,disk=undefined,mountPolicy=undefined) {
  return {storage_resize:config===undefined?(getStorageResizeConfig()||{enabled:false,sizes:[]}):config,disk_size_gib:disk===undefined?getDiskSizeGiB():disk,mount_policy:mountPolicy??getMountPolicy()};
}
function storageRows() {
  return [...storageFilesystems()].sort((a,b)=>(a.mountpoint==='/'?-1:b.mountpoint==='/'?1:0)).map((fs,index)=>{
    const current=Math.ceil(Number(fs.size||0)/MiB),known=Number.isFinite(fs.used),minimum=Number(fs.minimum_size_mib)||32;
    const unit=current>=1024&&current%256===0?'gib':'mib',name=fs.mountpoint||fs.device;
    const description=fs.mountpoint==='/'?'System':fs.kind==='efi'?'EFI boot':fs.mountpoint==='/boot'?'Boot':fs.kind==='lv'?'Logical volume':'Partition';
    return `<article class="filesystem-row" data-fs-device="${esc(fs.device)}">
      <div class="filesystem-heading"><div><span class="filesystem-dot color-${index%5}"></span><strong>${esc(name)}</strong>${helpHint(`${description} · ${fs.filesystem||'Unknown'} · ${fs.device}${fs.editable?'. Sizes round up to whole MiB, or 4 MiB for LVM.':''}`,`About ${name}`)}</div><span class="filesystem-kind">${esc(description)} · ${esc(fs.filesystem||'Unknown')}</span></div>
      <div class="filesystem-size-choice"><span class="filesystem-original"><small>Current</small><strong>${bytes(fs.size)}</strong></span><span class="filesystem-auto-target" hidden><small>Planned</small><strong data-fs-auto-size></strong></span>${fs.editable?`<span class="filesystem-arrow" data-rebuild-controls hidden aria-hidden="true">→</span><label class="filesystem-target" data-rebuild-controls hidden><span>New size</span><span class="size-field"><input type="number" id="fs-size-${encodeURIComponent(fs.device)}" data-fs-size-input="${esc(fs.device)}" value="${unit==='gib'?current/1024:current}" min="${unit==='gib'?32/1024:32}" step="${unit==='gib'?'any':'1'}" required aria-label="New capacity of ${esc(name)}"><select id="fs-unit-${encodeURIComponent(fs.device)}" data-fs-size-unit="${esc(fs.device)}" aria-label="Capacity unit for ${esc(name)}"><option value="gib"${unit==='gib'?' selected':''}>GiB</option><option value="mib"${unit==='mib'?' selected':''}>MiB</option></select></span></label><input type="hidden" value="${current}" data-rebuild-device="${esc(fs.device)}">`:`<span class="filesystem-locked">Fixed${helpHint(fs.kind==='efi'?'The EFI partition keeps its original size and boot files.':'This filesystem is not supported for resizing. Refresh inspection if storage evidence is missing.',`Why ${name} is fixed`)}</span>`}</div>
      <div class="filesystem-visual"><div class="fs-track" role="img"><span class="fs-original-capacity"></span><span class="fs-capacity"><i class="fs-used"></i></span><span class="fs-size-marker"></span></div><div class="filesystem-usage"><span>${known?`${bytes(fs.used)} used`:'Usage unavailable'}</span><span data-fs-difference></span><span class="sr-only" data-fs-planned>${bytes(fs.size)}</span></div></div>
      ${fs.editable?`<div class="filesystem-resize" data-rebuild-controls hidden><label class="slider-field"><span class="sr-only">Resize ${esc(name)} in MiB</span><input type="range" min="${minimum}" max="${Math.max(current*2,minimum+1024)}" step="1" value="${current}" data-rebuild-slider="${esc(fs.device)}"></label><span class="filesystem-minimum">Min. ${bytes(minimum*MiB)} ${helpHint(`Estimated minimum: ${minimum.toLocaleString()} MiB, including data and headroom. The server checks the layout before building; the estimate is not a guarantee.`,'Minimum size estimate')}</span></div>`:''}
      <div class="filesystem-alert" data-fs-alert role="status" hidden></div></article>`;
  }).join('') || '<p class="muted">No filesystem layout is available. Refresh inspection to collect storage evidence.</p>';
}
function renderStorageStudio() {
  const evidence=studioImage()?.inspection?.storage;
  return `<div id="storage-studio">
    <section class="storage-sizing-card" aria-labelledby="storage-sizing-title">
      <div class="storage-card-heading"><h3 id="storage-sizing-title">Disk &amp; filesystems</h3><label class="check-field"><input type="checkbox" id="storage-rebuild-enabled"><span>Resize filesystems</span>${helpHint('Adjust supported XFS, ext and LVM filesystems on a new disk. Containing partitions and LVM grow automatically. Shrinking uses the verified filesystem rebuild workflow. The imported source stays unchanged.','Partition resizing')}</label></div>
      <div class="storage-capacity-editor">
        <div class="storage-summary"><div><span>Current disk</span><strong id="storage-before"></strong></div><span class="storage-summary-arrow" aria-hidden="true">→</span><div><span>Planned disk</span><strong id="storage-after"></strong></div><div class="storage-saving"><strong id="storage-reduction"></strong></div><div class="storage-capacity-rail" role="img"><span id="storage-capacity-original"></span><span id="storage-capacity-target"></span></div></div>
        <div class="storage-capacity-controls"><fieldset class="storage-capacity-modes"><legend>Disk capacity</legend><div><label><input type="radio" name="storage-capacity-mode" id="storage-capacity-keep" value="keep" checked><span>Automatic</span></label><label><input type="radio" name="storage-capacity-mode" id="storage-capacity-custom" value="custom"><span>Custom size</span></label></div></fieldset><div id="storage-capacity-field" hidden></div><div class="storage-fit-action"><button type="button" class="button secondary small" id="storage-fit-button" data-studio-action="storage-fit" hidden>${icon('image')}Fit to filesystems</button><span id="storage-fit-help" hidden>${helpHint('Checks the server’s layout plan and sets the disk to its minimum capacity, rounded up to two decimal places in your selected unit. Refit after changing filesystem sizes.','Fit disk to filesystems')}</span></div></div>
      </div>
      ${!evidence?'<div class="notice warning storage-evidence-notice">Refresh inspection to enable resizing. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh</button></div>':''}
      <div class="storage-filesystems-heading"><h4>Filesystems</h4><span class="storage-usage-key">Used / capacity${helpHint('The dark bar shows used data; the lighter area is filesystem capacity. Hatched space marks a reduction from the source size. The downloaded file size is measured after export.','Reading the size bars')}</span></div>
      <div class="filesystem-list">${storageRows()}</div>
      <div id="filesystem-reduction" class="filesystem-total-change"></div>
      <div id="storage-plan-controls" hidden><div class="plan-action-row"><button type="button" class="button secondary" id="storage-plan-button" data-studio-action="storage-preview">${icon('check')}Check sizes</button>${helpHint('Sizes and available space are also checked when you choose Next. The plan reports layout limits before any image is built.','Sizing validation')}</div><div id="storage-plan-error" class="notice error" role="alert" hidden></div><div id="storage-plan" class="studio-plan"></div></div>
    </section>
    <details class="editor-disclosure storage-layout-details" data-disclosure="storage-layout"><summary>Disk layout <span class="disclosure-meta">Details</span></summary><div class="details-content" id="storage-advanced-content">
      <div class="storage-disk-facts"><span>Source file <strong id="storage-file-size"></strong></span><span>Target capacity <strong id="storage-exact-capacity"></strong></span></div>
      <div class="disk-comparison"><div class="disk-caption"><span>Current</span><span id="storage-current-size"></span></div><div class="disk-track" id="storage-current-map" role="img"></div><div class="disk-caption"><span>Planned</span><span id="storage-planned-size"></span></div><div class="disk-track" id="storage-planned-map" role="img"></div><div id="storage-map-note" class="storage-note"></div></div>
    </div></details>
  </div>`;
}
function prepareStudioEditor() {
  const panel=$('#panel-storage');if(!panel||$('#storage-studio'))return;
  const capacity=$('#disk-size').closest('label');capacity.remove();
  panel.innerHTML=renderStorageStudio();$('#storage-capacity-field').append(capacity);
  const disk=$('#disk-size');disk.setAttribute('aria-label','Target disk capacity');disk.step='any';disk.placeholder='Automatic';const title=[...capacity.childNodes].find(node=>node.nodeType===3&&node.textContent.trim());if(title)title.textContent='Target capacity';const units=document.createElement('div');units.className='capacity-input';disk.replaceWith(units);units.append(disk);units.insertAdjacentHTML('beforeend','<select id="disk-size-unit" aria-label="Capacity unit" data-previous-unit="gib"><option value="gib">GiB</option><option value="gb">GB</option></select>');const oldHelp=$('.field-help',capacity);if(oldHelp)oldHelp.remove();capacity.insertAdjacentHTML('beforeend',helpHint('Keeps current capacity unless filesystem targets require more space. Custom size sets a fixed disk capacity. Fit to filesystems chooses the smallest verified layout. A larger custom disk fills the verified root only when filesystem sizes are not explicitly selected. GiB uses 1024³ bytes; GB uses 1000³.','Target disk capacity'));
  $('#panel-export').insertAdjacentHTML('beforeend',renderPlatformStudio());
  compactStudioHelp($('#recipe-form'));
}
function partitionMap(partitions,capacity,scale) {
  let total=0;const segments=[];
  for(const [index,part] of partitions.entries()) {
    const size=Number(part.size)||0;if(size<=0)continue;total+=size;
    const label=`${part.device}: ${bytes(size)}`;
    segments.push(`<span class="disk-segment color-${index%5}" style="width:${Math.max(.2,size/scale*100)}%" title="${esc(label)}"><span>${size/scale>.07?esc(part.device):''}</span></span>`);
  }
  const free=Math.max(0,capacity-total);if(free)segments.push(`<span class="disk-unallocated" style="width:${free/scale*100}%" title="${esc(bytes(free)+' unallocated or metadata')}"></span>`);
  return segments.join('');
}
function reductionText(before,after) {
  if(!Number.isFinite(after)||after<=0||!before)return '—';const delta=before-after,pct=Math.abs(delta)/before*100;
  return delta===0?'Unchanged':`${bytes(Math.abs(delta))} · ${pct.toLocaleString(undefined,{maximumFractionDigits:1})}% ${delta>0?'less':'more'}`;
}
function updateStorageStudio() {
  if(!$('#storage-studio'))return;
  const inspection=studioImage()?.inspection||{},enabled=$('#storage-rebuild-enabled').checked;
  const requested=enabled||getDiskSizeGiB()!==null;$('#storage-plan-controls').hidden=!requested;
  $('#storage-fit-button').hidden=!enabled;$('#storage-fit-help').hidden=!enabled;
  $('#storage-studio').classList.toggle('resizing',enabled);
  $$('[data-rebuild-controls]').forEach(node=>node.hidden=!enabled);
  let plan;try { const body=storagePlanBody();const cached=studioSession().storage;if(cached?.signature===JSON.stringify(body)&&cached.snapshot===studioInspectionKey())plan=cached.plan;}catch{}
  const before=Number(inspection.virtual_size)||0,raw=$('#disk-size').value,custom=Boolean(raw)||$('#storage-capacity-custom').checked,after=custom?(getDiskCapacityBytes()??NaN):(plan?.layout?.disk_size_after||before);
  $('#storage-capacity-keep').checked=!custom;$('#storage-capacity-custom').checked=custom;$('#storage-capacity-field').hidden=!custom;$('#disk-size').required=custom;
  $('#storage-before').textContent=bytes(before);$('#storage-after').textContent=after>0?bytes(after):'Enter a valid size';$('#storage-reduction').textContent=reductionText(before,after);$('#storage-file-size').textContent=bytes(inspection.actual_size);$('#storage-exact-capacity').textContent=after>0?`${after.toLocaleString('en-US')} bytes`:'Enter a positive disk capacity.';
  const diskScale=Math.max(before,after||0,1);
  $('#storage-capacity-original').style.width=`${before/diskScale*100}%`;
  $('#storage-capacity-target').style.width=`${Math.max(0,(after||0)/diskScale*100)}%`;
  $('.storage-capacity-rail').setAttribute('aria-label',`Disk capacity: ${bytes(before)} current, ${bytes(after)} planned. ${reductionText(before,after)}`);
  $('#storage-studio').classList.toggle('disk-shrinking',after>0&&after<before);
  const sourceParts=(inspection.partitions||[]).filter(part=>/^\/dev\/sda\d+$/.test(part.device));
  let proposed=sourceParts.map(part=>({...part}));
  if(plan?.layout?.partitions)proposed=plan.layout.partitions;
  const scale=Math.max(before,after||0,1);
  $('#storage-current-map').innerHTML=partitionMap(sourceParts,before,scale);$('#storage-current-map').setAttribute('aria-label',`Current disk ${bytes(before)}. ${sourceParts.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').innerHTML=partitionMap(proposed,after,scale);$('#storage-planned-map').setAttribute('aria-label',`Planned disk ${bytes(after)}. ${requested&&!plan?'Partition positions require plan validation.':proposed.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').classList.toggle('unvalidated',requested&&!plan);$('#storage-current-size').textContent=bytes(before);$('#storage-planned-size').textContent=after>0?bytes(after):'Invalid capacity';
  $('#storage-map-note').textContent=`Scale: ${bytes(scale)}. `+(requested&&!plan?'Check sizes to update this layout.':requested&&plan?.ready?'Validated layout.':requested?'Resolve the size blockers.':'Hatched areas are unallocated.');
  let fsBefore=0,fsAfter=0;
  for(const fs of storageFilesystems()) {
    const row=$$('[data-fs-device]').find(node=>node.dataset.fsDevice===fs.device);if(!row)continue;
    const field=storageSizeInputs().find(node=>node.dataset.rebuildDevice===fs.device),selected=plan?.filesystems?.find(item=>item.device===fs.device)?.selected_size_mib,next=Number.isFinite(selected)?selected*MiB:enabled&&field?Number(field.value)*MiB:Number(fs.size),current=Number(fs.size)||0,used=Number.isFinite(fs.used)?fs.used:null;
    fsBefore+=current;fsAfter+=Number.isFinite(next)?next:current;
    $('[data-fs-planned]',row).textContent=next>0?bytes(next):'Invalid';
    const automatic=$('.filesystem-auto-target',row);automatic.hidden=enabled||!Number.isFinite(selected)||next===current;$('[data-fs-auto-size]',row).textContent=next>0?bytes(next):'Invalid';
    const max=Math.max(current,next||0,1);
    const track=$('.fs-track',row),bar=$('.fs-capacity',track);
    bar.style.width=`${Math.max(0,Math.min(100,(next||0)/max*100))}%`;
    $('.fs-original-capacity',row).style.width=`${current/max*100}%`;
    $('.fs-size-marker',row).style.left=`${Math.min(100,current/max*100)}%`;
    $('.fs-used',track).style.width=used===null?'0%':`${Math.min(100,used/Math.max(next||0,1)*100)}%`;
    track.setAttribute('aria-label',`${bytes(current)} current, ${bytes(next)} planned${used===null?', usage unavailable':', '+bytes(used)+' used'}`);
    $('[data-fs-difference]',row).textContent=next>0&&next!==current?`${bytes(Math.abs(current-next))} ${next<current?'less':'more'}`:'';
    row.classList.toggle('size-changed',next>0&&next!==current);
    const slider=$('[data-rebuild-slider]',row);if(slider&&field) { slider.max=Math.max(Number(slider.max),Number(field.value)||0);slider.value=field.value;slider.setAttribute('aria-valuetext',`${field.value} MiB`); }
    const minimum=Number(fs.minimum_size_mib);const tooSmall=enabled&&field&&minimum&&Number(field.value)<minimum;
    const alert=$('[data-fs-alert]',row);alert.hidden=!tooSmall;alert.textContent=tooSmall?`Use at least ${bytes(minimum*MiB)} (${minimum.toLocaleString()} MiB).`:'';row.classList.toggle('size-blocked',Boolean(tooSmall));
  }
  $('#filesystem-reduction').textContent=fsBefore===fsAfter?'':`Filesystems: ${reductionText(fsBefore,fsAfter)}`;
  if(requested&&plan)renderStoragePlan(plan);
  for(const button of [$('#storage-plan-button'),$('#storage-fit-button')])if(button)button.disabled=wizardInspectionPending()||Boolean(studioSession().storageFitPending)||button.getAttribute('aria-busy')==='true';
}
function renderStoragePlan(plan) {
  const container=$('#storage-plan'),signature=JSON.stringify(plan);
  if(container.dataset.renderedPlan===signature&&$('.plan-status',container))return;
  container.dataset.renderedPlan=signature;
  const lines=items=>(items||[]).map(item=>`<li>${esc(item)}</li>`).join('');
  $('#storage-plan').innerHTML=`<div role="status" class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${plan.ready?'Storage plan ready':'Resolve storage blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers" role="alert">${lines(plan.blockers)}</ul>`:''}<div class="plan-facts"><span>Method <strong>${plan.mode==='growth'?'Grow in place on a copy':plan.mode==='unchanged'?'Keep current sizes':'Rebuild filesystems'}</strong></span><span>Minimum disk <strong>${bytes(plan.layout?.minimum_disk_size)}</strong></span><span>Working space <strong>${bytes(plan.estimated_temporary_bytes)}</strong></span></div>${plan.changes?.length?`<details><summary>Planned changes</summary><ul>${lines(plan.changes)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
}
function beginStudioPlan(button) {
  const requestId=String(++studioState.requestId);
  if(button) {
    button.dataset.requestId=requestId;button.disabled=true;button.setAttribute('aria-busy','true');
    button.innerHTML='<span class="spinner" aria-hidden="true"></span>Checking…';
  }
  return requestId;
}
function finishStudioPlan(button,requestId,kind) {
  if(!button?.isConnected||button.dataset.requestId!==requestId)return;
  button.removeAttribute('aria-busy');button.disabled=wizardInspectionPending()||(kind==='storage'&&Boolean(studioSession().storageFitPending));
  button.innerHTML=icon('check')+(kind==='storage'?'Check sizes':'Check compatibility');
}
async function previewStorage(config=undefined,beforeBuild=false,disk=undefined,mountPolicy=undefined) {
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey(),button=$('#storage-plan-button'),requestId=beginStudioPlan(button);notice('#storage-plan-error','');
  try {
    const body=storagePlanBody(config,disk,mountPolicy),signature=JSON.stringify(body);
    const plan=await api(`/images/${encodeURIComponent(imageId)}/storage/plan`,{method:'POST',body:signature});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot){if(beforeBuild)throw new Error('Storage choices changed. Check the current plan again.');return null;}
    studioSession().storage={signature,plan,snapshot};updateStorageStudio();renderStoragePlan(plan);
    if(beforeBuild&&(!plan.ready||plan.blockers?.length)){setTab('storage');throw new Error('Resolve the storage plan blockers before continuing.');}return plan;
  }catch(error){if(state.selected===imageId&&state.editorRevision===revision)notice('#storage-plan-error',errorText(error));if(beforeBuild){if(state.selected===imageId)setTab('storage');throw error;}return null;}
  finally{finishStudioPlan(button,requestId,'storage');}
}
async function fitStorageDisk() {
  const session=studioSession(),button=$('#storage-fit-button');
  if(session.storageFitPending||wizardInspectionPending()||!$('#storage-rebuild-enabled').checked)return;
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey();
  session.storageFitPending=true;button.disabled=true;button.setAttribute('aria-busy','true');
  button.innerHTML='<span class="spinner" aria-hidden="true"></span>Calculating…';updateStorageStudio();wizardUpdate();
  try {
    // A bounded undersized preview selects the safe packing/rebuild planner.
    const plan=await previewStorage(undefined,false,1/1024);
    if(!plan||state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot)return;
    const minimum=plan.layout?.minimum_disk_size;
    if(!Number.isFinite(minimum)||minimum<=0)return;
    const field=$('#disk-size'),scale=$('#disk-size-unit').value==='gb'?1e9:GiB;
    field.value=String(Math.ceil(minimum/scale*100)/100);field.dispatchEvent(new Event('input',{bubbles:true}));
    await previewStorage();
  } finally {
    session.storageFitPending=false;
    if(button.isConnected) {button.removeAttribute('aria-busy');button.innerHTML=icon('image')+'Fit to filesystems';}
    updateStorageStudio();wizardUpdate();
  }
}
function setStorageCapacityMode(mode) {
  const field=$('#disk-size'),unit=$('#disk-size-unit').value,session=studioSession();
  if(mode==='keep') {
    if(field.value)session.customCapacity={value:field.value,unit};
    field.value='';
  } else if(!field.value) {
    const saved=session.customCapacity;
    field.value=saved?(saved.unit===unit?saved.value:String(Number(saved.value)*(saved.unit==='gb'?1e9:GiB)/(unit==='gb'?1e9:GiB))):String(Number(studioImage()?.inspection?.virtual_size||0)/(unit==='gb'?1e9:GiB));
  }
  field.dispatchEvent(new Event('input',{bubbles:true}));
  if(mode==='custom')field.focus({preventScroll:true});
}
function syncFilesystemInput(device,fromDisplay=false) {
  const row=$$('[data-fs-device]').find(node=>node.dataset.fsDevice===device);if(!row)return;
  const field=$('[data-rebuild-device]',row),display=$('[data-fs-size-input]',row),unit=$('[data-fs-size-unit]',row);
  if(!field||!display)return;
  const scale=unit.value==='gib'?1024:1;
  display.min=String(32/scale);
  display.step=unit.value==='gib'?'any':'1';
  if(fromDisplay)field.value=display.value&&Number.isFinite(display.valueAsNumber)?String(Math.ceil(display.valueAsNumber*scale)):'';
  else display.value=field.value?String(Number(field.value)/scale):'';
}
function renderPlatformStudio() {
  return `<section id="platform-studio" class="platform-studio">
    <div class="studio-section-heading"><h3>Hardware compatibility</h3>${helpHint('Preserve & validate also supports VM-to-VM moves. Existing guest drivers may already support the destination; the image’s origin does not choose its target networking mode.','Hardware compatibility')}</div>
    <label class="check-field feature-switch"><input type="checkbox" id="platform-enabled"><span>Check or prepare target hardware</span></label>
    <div id="platform-controls" hidden>
      ${!studioImage()?.inspection?.platform?'<div class="notice warning">Refresh inspection to check hardware support. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh</button></div>':''}
      <label class="field">Behavior<select id="platform-strategy"><option value="reconfigure" selected>Prepare for destination</option><option value="preserve">Preserve &amp; validate</option></select>${helpHint('Preserve validates existing hardware settings without rewriting them. Separately requested edits still apply. Prepare changes boot drivers and networking as shown in the plan. Mount identifiers follow the separate Mounts policy.','Hardware behavior')}</label>
      ${renderDestinationProfile()}
      <div class="notice warning" id="platform-provider-warning"></div>
      <details class="editor-disclosure platform-advanced-options" id="platform-advanced" data-disclosure="platform-advanced"><summary>Hardware overrides <span class="disclosure-meta">Advanced</span></summary><div class="details-content"><div class="platform-direction"><label class="field">Previous platform<select id="platform-source"><option value="unknown" selected>Not specified</option><option value="vm">Virtual machine</option><option value="bare_metal">Bare metal</option></select>${helpHint('Leave unspecified when the previous platform is unknown. Preparation follows the destination; inspection does not establish where the image last ran.','Source type')}</label><span class="direction-arrow" aria-hidden="true">${icon('arrow')}</span><label class="field">Target type<select id="platform-target"><option value="bare_metal">Bare metal</option><option value="vm" selected>Virtual machine</option></select></label></div>
      <div class="form-grid"><label class="field">Boot attachment<select id="platform-boot"><option value="iscsi">Firmware iSCSI</option><option value="paravirtualized" selected>Paravirtualized</option></select>${helpHint('Choose the target attachment. Firmware iSCSI uses target-provided iBFT; optional firmware discovery alone does not mean the guest requires network root.','Boot attachment')}</label><label class="field">Network attachment<select id="platform-network"><option value="vfio">Physical / VFIO</option><option value="paravirtualized" selected>Paravirtualized</option><option value="accelerated">Accelerated PV</option></select>${helpHint(sourceArchitecture()==='aarch64'?'Use a shape matching ARM64. Select the destination’s OCI network mode: Paravirtualized for VM.Standard.A1.Flex; Accelerated PV only for supported Arm Acceleron shapes. Guest driver support does not change OCI attachment values.':'The reviewed PV and Ax guests both use VirtIO drivers. Select the destination’s OCI mode: Paravirtualized for VM.Standard.E5.Flex, Accelerated PV for VM.Standard.E6.Ax.Flex. Physical/VFIO needs its matching NIC driver.','Network attachment')}</label></div>
      <label class="field" id="platform-nic-field">NIC drivers<select id="platform-nic"><option value="">Select target driver</option><option value="auto">Automatic (available drivers)</option>${['ixgbe','ixgbevf','i40e','iavf','mlx4_en','mlx5_core','bnxt_en'].map(driver=>`<option value="${driver}">${driver}</option>`).join('')}</select>${helpHint('Automatic checks the supported installed NIC drivers across every kernel. The compatibility plan lists the verified bundle; the destination’s exact NIC remains unverified. Choose a specific driver when the target hardware is known.','NIC drivers')}</label>
      </div></details>
      <div id="platform-accelerated-note" class="notice warning" hidden>Accelerated PV is shape-dependent. Confirm image and regional schema support, then test the OCI launch.</div>

      <details class="editor-disclosure" id="platform-write-options" data-disclosure="platform-options" hidden><summary>Preparation options <span class="disclosure-meta">Network, console & packages</span></summary><div class="details-content platform-options">
        <label class="check-field"><input type="checkbox" id="platform-configure-network" checked><span>Configure network startup${helpHint('Replaces machine-bound network profiles with portable DHCP and prepares early networking when required.','Network startup')}</span></label>
        <label class="check-field"><input type="checkbox" id="platform-serial-console" checked><span>Enable serial console${helpHint(sourceArchitecture()==='aarch64'?'Enables ttyAMA0 at 115200 baud and a serial login service for ARM64.':sourceArchitecture()==='x86_64'?'Enables ttyS0 at 115200 baud and a serial login service for x86_64.':'Enables the guest-supported serial console after architecture checks.','Serial console')}</span></label>
        <label class="check-field"><input type="checkbox" id="platform-install-packages"><span>Install required packages${helpHint('Required packages are downloaded from the guest repositories during preparation.','Package installation')}</span></label>
      </div></details>
      <div class="notice error" id="platform-preserve-conflict" role="alert" hidden>Preserve &amp; validate requires OCI guest preparation off. <button type="button" class="button ghost small" id="platform-preserve-validate-button" data-studio-action="platform-validate-oci">Use validate-only</button></div>
      <div class="platform-oci-note" id="platform-oci-note" hidden></div>
      <div class="plan-action-row"><button type="button" class="button secondary" id="platform-plan-button" data-studio-action="platform-preview">${icon('check')}Check compatibility</button></div>
      <div id="platform-plan-error" class="notice error" role="alert" hidden></div><div id="platform-plan" class="studio-plan"></div>
    </div></section>`;
}
function getPlatformMigrationConfig() {
  if(!$('#platform-enabled')?.checked)return null;
  const strategy=$('#platform-strategy').value,preserve=strategy==='preserve';
  const config={enabled:true,strategy,source:$('#platform-source').value,target:$('#platform-target').value,boot_attachment:$('#platform-boot').value,network_attachment:$('#platform-network').value,nic_driver:$('#platform-nic').value||null,install_packages:!preserve&&$('#platform-install-packages').checked,configure_network:!preserve&&$('#platform-configure-network').checked,configure_serial_console:!preserve&&$('#platform-serial-console').checked};
  const destinationIssue=destinationConfigurationIssue();if(destinationIssue)throw editorError(destinationIssue,'#destination-profile');
  if(platformPreserveConflict())throw editorError('Turn off OCI guest preparation to preserve the existing hardware configuration.','#platform-preserve-validate-button');
  if((config.target==='bare_metal'||config.network_attachment==='vfio')&&!config.nic_driver)throw editorError('Choose Automatic or the NIC driver for the destination hardware.','#platform-nic');
  return config;
}
function platformPreserveConflict() { return Boolean($('#platform-enabled')?.checked&&$('#platform-strategy')?.value==='preserve'&&$('input[name="target"]:checked')?.value==='oci'&&$('#oci-enabled')?.checked&&$('#oci-prepare')?.checked); }
function updatePlatformPreserveConflict() { for(const id of ['platform-preserve-conflict','oci-platform-preserve-conflict']) { const node=$(`#${id}`);if(node)node.hidden=!platformPreserveConflict(); } }
function preservePlatformConfiguration() {
  if($('#oci-prepare'))$('#oci-prepare').checked=false;
  studioSession().pendingOciPlatformSync=false;
  if($('#oci-enabled')?.checked)markOciChanged();else updateDisclosureSummaries();
}
function syncOciPlatformChoices() {
  if(!$('#platform-enabled')?.checked)return;
  if($('#destination-profile')?.value!=='custom')return;
  if($('#platform-strategy')?.value==='preserve'){studioSession().pendingOciPlatformSync=false;return;}
  if($('input[name="target"]:checked')?.value!=='oci'){studioSession().pendingOciPlatformSync=true;return;}
  studioSession().pendingOciPlatformSync=false;
  const boot=$('#platform-boot').value==='iscsi'?'ISCSI':'PARAVIRTUALIZED',network={vfio:'VFIO',paravirtualized:'PARAVIRTUALIZED',accelerated:'ACCELERATEDPV'}[$('#platform-network').value];
  const settings={'Storage.BootVolumeType':boot,'Network.AttachmentType':network,'Compute.LaunchMode':boot==='ISCSI'&&network==='VFIO'?'NATIVE':boot==='PARAVIRTUALIZED'&&['PARAVIRTUALIZED','ACCELERATEDPV'].includes(network)?network:'CUSTOM'};
  if($('#platform-target').value==='bare_metal')settings['Compute.Firmware']='UEFI_64';
  const unavailable=Object.entries(settings).filter(([key,value])=>{const input=$$('[data-oci-default]').find(node=>node.dataset.ociDefault===key);return !input||![...input.options].some(option=>option.value===JSON.stringify(value));}).map(([key])=>key);
  if(unavailable.length) {
    const customKept=unavailable.length===1&&unavailable[0]==='Compute.LaunchMode'&&$$('[data-oci-default]').find(node=>node.dataset.ociDefault==='Compute.LaunchMode')?.value===JSON.stringify('CUSTOM');
    const note=$('#platform-oci-note');note.className=`notice ${customKept?'warning':'error'}`;
    note.textContent=`Automatic sync could not select ${unavailable.map(key=>`${settings[key]} for ${key}`).join(', ')}. Existing OCI choices were kept.${customKept?' CUSTOM remains selected; review the attachments under OCI compatibility.':' Review the OCI choices or load a regional schema that supports these preferences.'}`;
    if($('#oci-enabled')?.checked)markOciChanged();else updateDisclosureSummaries();return;
  }
  for(const [key,value] of Object.entries(settings)) {
    const input=$$('[data-oci-default]').find(node=>node.dataset.ociDefault===key);
    input.value=JSON.stringify(value);$$('[data-oci-allowed]').filter(node=>node.dataset.ociAllowed===key).forEach(node=>node.checked=node.value===JSON.stringify(value));
    if(key==='Compute.Firmware'){state.ociFirmwareEdited=true;if($('#oci-firmware-confirm'))$('#oci-firmware-confirm').checked=true;}
  }
  if($('#oci-launch-mode'))$('#oci-launch-mode').value=settings['Compute.LaunchMode'];
  $('#platform-oci-note').className='platform-oci-note';$('#platform-oci-note').textContent='Attachments synced with OCI.';
  if($('#oci-enabled')?.checked)markOciChanged();else updateDisclosureSummaries();
}
function updatePlatformStudio() {
  if(!$('#platform-studio'))return;
  const enabled=$('#platform-enabled').checked,preserve=$('#platform-strategy').value==='preserve',bare=$('#platform-target').value==='bare_metal',oci=$('input[name="target"]:checked')?.value==='oci';
  $('#platform-controls').hidden=!enabled;
  $('#platform-write-options').hidden=preserve;
  updatePlatformPreserveConflict();
  $('#platform-provider-warning').hidden=!bare;
  $('#platform-provider-warning').textContent=oci?'Experimental: OCI BYOI does not support bare metal. Test the output on the target hardware.':'Experimental hardware preparation. A destination boot test is required.';
  $('#platform-nic-field').hidden=!bare&&$('#platform-network').value!=='vfio';
  const accelerated=$('#platform-accelerated-note'),issue=oci?ociAcceleratedSchemaError():'';
  accelerated.hidden=$('#platform-network').value!=='accelerated';accelerated.className=`notice ${issue?'error':'warning'}`;accelerated.textContent=issue||'Accelerated PV is shape-dependent. Confirm image and regional schema support, then test the destination launch.';
  const note=$('#platform-oci-note');note.hidden=preserve||!oci||!note.textContent;
  const button=$('#platform-plan-button');button.disabled=wizardInspectionPending()||button.getAttribute('aria-busy')==='true';
}
function platformPlanBody(config=undefined,recipe=null) {
  const selected=config===undefined?getPlatformMigrationConfig():config;
  return {target:recipe?recipe.target:($('input[name="target"]:checked')?.value||'oci'),platform_migration:selected,mount_policy:recipe?recipe.mount_policy:getMountPolicy(),allow_network:recipe?recipe.allow_network:requiredDownloadsEnabled(),...((recipe?recipe.boot_migration:getBootMigrationConfig())?{boot_migration:recipe?recipe.boot_migration:getBootMigrationConfig()}:{}),...((recipe?recipe.oci:($('input[name="target"]:checked')?.value==='oci'&&$('#oci-enabled').checked?getOciConfig():null))?{oci:recipe?recipe.oci:getOciConfig()}:{} )};
}
function renderPlatformPlan(plan) {
  const container=$('#platform-plan'),signature=JSON.stringify(plan);
  if(container.dataset.renderedPlan===signature&&$('.plan-status',container))return;
  container.dataset.renderedPlan=signature;
  const lines=items=>(items||[]).map(item=>`<li>${esc(typeof item==='string'?item:JSON.stringify(item))}</li>`).join('');
  const preserve=(plan.strategy||$('#platform-strategy').value)==='preserve',assessment=plan.portability,ready=plan.ready&&!plan.blockers?.length;
  const rootLabel={local:'Local root',optional_firmware_iscsi:'Local root · optional iSCSI discovery',mandatory_network:'Network root required',unknown:'Not established'}[assessment?.root_transport]||'Not established';
  const assessmentDetails=assessment?`<details class="platform-portability-evidence"><summary>Offline evidence${assessment.checks?.length?` · ${assessment.checks.length} checks`:''}</summary><ul>${(assessment.checks||[]).map(check=>`<li><strong>${esc(check.label||check.id)} · ${esc(check.status)}</strong>${check.evidence?.length?`<ul>${lines(check.evidence)}</ul>`:''}</li>`).join('')}</ul>${assessment.kernels?.length?`<div class="table-wrap"><table><thead><tr><th>Kernel</th><th>Offline status</th><th>Missing drivers</th></tr></thead><tbody>${assessment.kernels.map(kernel=>`<tr><td><code>${esc(kernel.version)}</code></td><td>${esc(kernel.status)}</td><td>${esc([...(kernel.missing_installed||[]),...(kernel.missing_initramfs||[])].filter((value,index,list)=>list.indexOf(value)===index).join(', ')||'None reported')}</td></tr>`).join('')}</tbody></table></div>`:''}${assessment.dual_environment?`<p class="module-list"><strong>VM + bare metal prerequisites</strong> ${esc(assessment.dual_environment.status||'unknown')} ${helpHint('Offline evidence only. A target may need a matching physical NIC driver; an available driver bundle does not identify that hardware or prove either environment boots.','Cross-environment evidence')}</p>`:''}</details>`:'';
  $('#platform-plan').innerHTML=`<div role="status" class="plan-status ${ready?'ready':'blocked'}">${icon(ready?'check':'info')}<strong>${ready?(preserve?'Offline prerequisites met':'Reconfiguration plan ready'):'Resolve hardware blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers" role="alert">${lines(plan.blockers)}</ul>`:''}${assessment?.status==='unknown'?`<button type="button" class="button secondary small" data-action="refresh-inspection">${icon('activity')}Refresh inspection</button>`:''}<div class="plan-facts"><span>Firmware <strong>${esc(Array.isArray(plan.effective_firmware)?plan.effective_firmware.join(', '):plan.effective_firmware||'Not established')}</strong></span>${assessment?`<span>Root boot <strong>${esc(rootLabel)}</strong>${helpHint('Optional firmware iSCSI discovery can coexist with local root. Mandatory network-root arguments are assessed separately.','Root boot')}</span>`:`<span>Initramfs <strong>${esc(plan.initramfs_backend||'Not established')}</strong></span>`}<span>Boot verification <strong>Not tested</strong></span></div>${assessmentDetails}${plan.fstab_changes?.length?`<details class="editor-disclosure"><summary>Mount identifier changes <span class="disclosure-meta">${plan.fstab_changes.length}</span></summary><div class="details-content">${mountChangeList(plan.fstab_changes)}</div></details>`:''}${plan.required_modules?.length||plan.packages?.length?`<details><summary>Drivers & packages</summary>${plan.required_modules?.length?`<p class="module-list"><strong>Drivers</strong> ${plan.required_modules.map(esc).join(', ')}</p>`:''}${plan.packages?.length?`<p class="module-list"><strong>Packages</strong> ${plan.packages.map(esc).join(', ')}</p>`:''}</details>`:''}${plan.actions?.length?`<details><summary>${preserve?'Validation actions':'Planned changes'}</summary><ul>${lines(plan.actions)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
}
async function previewPlatform(config=undefined,beforeBuild=false,recipe=null) {
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey(),button=$('#platform-plan-button'),requestId=beginStudioPlan(button);notice('#platform-plan-error','');
  try {
    const body=platformPlanBody(config,recipe);if(!body.platform_migration)throw new Error('Enable platform preparation to check its prerequisites.');
    const plan=await api(`/images/${encodeURIComponent(imageId)}/platform/plan`,{method:'POST',body:JSON.stringify(body)});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot){if(beforeBuild)throw new Error('Platform choices changed. Check the current plan again.');return null;}
    studioSession().platform={signature:JSON.stringify(body),plan,snapshot};renderPlatformPlan(plan);
    if(beforeBuild&&(!plan.ready||plan.blockers?.length)){setTab('export');throw new Error('Resolve the platform plan blockers before continuing.');}return plan;
  }catch(error){if(state.selected===imageId&&state.editorRevision===revision)notice('#platform-plan-error',errorText(error));if(beforeBuild){if(state.selected===imageId)setTab('export');throw error;}return null;}
  finally{finishStudioPlan(button,requestId,'platform');}
}
function syncStudioEditor() { syncDestinationEditor(); if($('#disk-size-unit'))$('#disk-size-unit').dataset.previousUnit=$('#disk-size-unit').value;updateStorageStudio();updatePlatformStudio();try { const cached=studioSession().platform;if(cached?.signature===JSON.stringify(platformPlanBody())&&cached.snapshot===studioInspectionKey())renderPlatformPlan(cached.plan); }catch{}compactStudioHelp($('#recipe-form')||document); }
function invalidateStudioPlans(kind) {
  const node=$(`#${kind}-plan`);
  if(node)node.innerHTML=studioSession()[kind]?'<p class="storage-note">Settings changed. Recheck the plan.</p>':'';
  if(kind==='storage')updateStorageStudio();
  if(kind==='platform'&&$('#oci-enabled')?.checked)markOciChanged();
}
document.addEventListener('click',event=>{
  const help=event.target.closest('.help-toggle');if(help){event.preventDefault();const anchor=help.closest('.help-anchor'),pinned=anchor.classList.contains('pinned');closeHelp();if(!pinned){studioState.dismissedHelp.delete(anchor);openHelp(anchor);anchor.classList.add('pinned');}return;}
  if(!event.target.closest('.help-anchor'))closeHelp();
  const button=event.target.closest('[data-studio-action]');if(!button)return;
  if(button.dataset.studioAction==='storage-preview')previewStorage();
  if(button.dataset.studioAction==='storage-fit')fitStorageDisk();
  if(button.dataset.studioAction==='platform-preview')previewPlatform();
  if(button.dataset.studioAction==='platform-validate-oci'){preservePlatformConfiguration();state.editorRevision++;invalidateStudioPlans('platform');updatePlatformStudio();}
});
document.addEventListener('mouseover',event=>{
  const anchor=event.target.closest('.help-anchor');if(!anchor)return;
  clearTimeout(studioState.helpCloseTimer);
  if(anchor.contains(event.relatedTarget)||studioState.dismissedHelp.has(anchor))return;
  clearTimeout(studioState.helpOpenTimer);
  studioState.helpOpenTimer=setTimeout(()=>{if(anchor.matches(':hover'))openHelp(anchor);},140);
});
document.addEventListener('mouseout',event=>{
  const anchor=event.target.closest('.help-anchor');
  if(anchor&&!anchor.contains(event.relatedTarget)){studioState.dismissedHelp.delete(anchor);scheduleHelpClose(anchor);}
});
document.addEventListener('focusin',event=>{const anchor=event.target.closest('.help-anchor');if(anchor&&!studioState.dismissedHelp.has(anchor))openHelp(anchor);});
document.addEventListener('focusout',event=>{const anchor=event.target.closest('.help-anchor');if(anchor&&!anchor.contains(event.relatedTarget)){studioState.dismissedHelp.delete(anchor);scheduleHelpClose(anchor);}});
document.addEventListener('keydown',event=>{if(event.key==='Escape'){const anchor=$('.help-anchor.open');if(anchor)studioState.dismissedHelp.add(anchor);closeHelp();}});
document.addEventListener('input',event=>{
  const input=event.target;
  if(input.dataset.rebuildSlider){const field=storageSizeInputs().find(node=>node.dataset.rebuildDevice===input.dataset.rebuildSlider);if(field)field.value=input.value;syncFilesystemInput(input.dataset.rebuildSlider);}
  if(input.dataset.fsSizeInput)syncFilesystemInput(input.dataset.fsSizeInput,true);
  if(input.dataset.rebuildDevice)syncFilesystemInput(input.dataset.rebuildDevice);
  if(input.closest('#panel-storage')&&input.name!=='storage-capacity-mode')invalidateStudioPlans('storage');
  if(input.closest('#platform-controls'))invalidateStudioPlans('platform');
});
document.addEventListener('change',event=>{
  const input=event.target;
  if(input.name==='target'){if(input.value==='oci'&&studioSession().pendingOciPlatformSync)syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
  if(input.name==='storage-capacity-mode')setStorageCapacityMode(input.value);
  if(input.id==='disk-size-unit'){const previous=input.dataset.previousUnit||'gib',value=getDiskCapacityBytes(previous);if(value!==null)$('#disk-size').value=String(value/(input.value==='gb'?1e9:GiB));input.dataset.previousUnit=input.value;invalidateStudioPlans('storage');}
  if(input.dataset.fsSizeUnit){syncFilesystemInput(input.dataset.fsSizeUnit);invalidateStudioPlans('storage');}
  if(input.id==='storage-rebuild-enabled'){updateStorageStudio();invalidateStudioPlans('storage');}
  if(['platform-enabled','platform-strategy','platform-source','platform-target'].includes(input.id)) {
    const preserve=$('#platform-strategy').value==='preserve';
    if(input.id==='platform-strategy')$('#platform-oci-note').textContent='';
    if(preserve&&$('#platform-enabled').checked&&['platform-enabled','platform-strategy'].includes(input.id))preservePlatformConfiguration();
    updatePlatformStudio();invalidateStudioPlans('platform');
  }
  if(['platform-boot','platform-network'].includes(input.id)){syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
  if(['oci-enabled','oci-prepare'].includes(input.id)){updatePlatformPreserveConflict();invalidateStudioPlans('platform');}
  if(input.closest('#panel-storage'))updateStorageStudio();
});

window.addEventListener('scroll',()=>{const anchor=document.querySelector('.help-anchor.open');if(!anchor)return;const rect=anchor.querySelector('.help-toggle').getBoundingClientRect();if(rect.bottom<0||rect.top>innerHeight)closeHelp();else positionHelp(anchor);},{passive:true});
window.addEventListener('resize',()=>closeHelp());
