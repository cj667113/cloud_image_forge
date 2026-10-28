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
  $$('.help-anchor.open').forEach(anchor => {
    if(anchor!==except) { anchor.classList.remove('open','pinned'); $('.help-toggle',anchor).setAttribute('aria-expanded','false'); }
  });
}
function positionHelp(anchor) {
  const button=$('.help-toggle',anchor),popover=$('.help-popover',anchor),box=button.getBoundingClientRect();
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
function getStorageRebuildConfig() {
  if (!$('#storage-rebuild-enabled')?.checked) return null;
  const sizes=storageSizeInputs().map(input=>({device:input.dataset.rebuildDevice,size_mib:Number(input.value)}));
  if(sizes.some(item=>!Number.isInteger(item.size_mib)||item.size_mib<32)) throw new Error('Filesystem capacities must be whole MiB of at least 32.');
  return {enabled:true,sizes};
}
function storagePlanBody(config=undefined,disk=undefined) {
  return {storage_rebuild:config===undefined?(getStorageRebuildConfig()||{enabled:false,sizes:[]}):config,disk_size_gib:disk===undefined?getDiskSizeGiB():disk};
}
function storageRows() {
  return storageFilesystems().map((fs,index)=>{
    const current=Math.ceil(Number(fs.size||0)/MiB),known=Number.isFinite(fs.used),minimum=Number(fs.minimum_size_mib)||32;
    return `<article class="filesystem-row" data-fs-device="${esc(fs.device)}"><div class="filesystem-heading"><div><span class="filesystem-dot color-${index%5}"></span><strong>${esc(fs.mountpoint||fs.device)}</strong><span class="badge">${esc(fs.filesystem||'Unknown')}</span>${fs.kind==='lv'?'<span class="filesystem-kind">Logical volume</span>':''}</div><code>${esc(fs.device)}</code></div><div class="filesystem-sizes"><span>Current <strong>${bytes(fs.size)}</strong></span><span>Planned <strong data-fs-planned>${bytes(fs.size)}</strong></span><span>${known?'Used <strong>'+bytes(fs.used)+'</strong>':'Usage unavailable'}</span></div><div class="filesystem-tracks"><div class="fs-track current" aria-label="Current capacity"><span class="fs-capacity"><i class="fs-used"></i></span></div><div class="fs-track planned" aria-label="Planned capacity"><span class="fs-capacity"><i class="fs-used"></i></span></div></div>${fs.editable?`<div class="filesystem-resize" data-rebuild-controls hidden><label class="slider-field"><span class="sr-only">Resize ${esc(fs.mountpoint||fs.device)} in MiB</span><input type="range" min="${minimum}" max="${Math.max(current*2,minimum+1024)}" step="1" value="${current}" data-rebuild-slider="${esc(fs.device)}"></label><label class="size-field"><input type="number" min="32" step="1" value="${current}" data-rebuild-device="${esc(fs.device)}" aria-label="Capacity of ${esc(fs.device)} in MiB"><span>MiB</span></label></div><div class="filesystem-minimum" data-rebuild-controls hidden>Minimum estimate: ${minimum.toLocaleString()} MiB ${helpHint('This estimate includes data and headroom. Logical volume sizes round up to 4 MiB extents. The server checks the layout and verifies the rebuild; a minimum estimate is not a guarantee.','Minimum size estimate')}</div>`:`<span class="filesystem-locked">${fs.kind==='efi'?'EFI · fixed size':'Read-only'}${helpHint(fs.kind==='efi'?'The EFI partition is copied at its original size to retain boot files.':'Refresh inspection to collect supported filesystem and usage evidence.','Why this capacity is fixed')}</span>`}<div class="filesystem-alert" data-fs-alert role="status" hidden></div></article>`;
  }).join('') || '<p class="muted">No filesystem layout is available. Refresh inspection to collect storage evidence.</p>';
}
function renderStorageStudio() {
  const evidence=studioImage()?.inspection?.storage;
  return `<div id="storage-studio">
    <div class="storage-summary"><div><span>Current disk</span><strong id="storage-before"></strong></div><div><span>Target disk</span><strong id="storage-after"></strong></div><div class="storage-saving"><span>Difference</span><strong id="storage-reduction"></strong></div></div>
    <div id="storage-capacity-field"></div>
    <details class="editor-disclosure storage-layout-details" data-disclosure="storage-layout"><summary>Disk layout <span class="disclosure-meta">Partitions & exact sizes</span></summary><div class="details-content">
      <div class="storage-disk-facts"><span>Source file <strong id="storage-file-size"></strong></span><span>Target capacity <strong id="storage-exact-capacity"></strong></span></div>
      <div class="disk-comparison"><div class="disk-caption"><span>Current</span><span id="storage-current-size"></span></div><div class="disk-track" id="storage-current-map" role="img"></div><div class="disk-caption"><span>Planned</span><span id="storage-planned-size"></span></div><div class="disk-track" id="storage-planned-map" role="img"></div><div id="storage-map-note" class="storage-note"></div></div>
    </div></details>
    <label class="check-field feature-switch"><input type="checkbox" id="storage-rebuild-enabled"><span>Resize filesystems${helpHint('Rebuilds supported XFS, ext and LVM filesystems at new sizes, preserving the imported source. Check the plan before building.','Filesystem resizing')}</span></label>
    ${!evidence?'<div class="notice warning">Refresh inspection to enable resizing. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh</button></div>':''}
    <div class="storage-row-heading"><h4>Filesystems</h4><span id="filesystem-reduction"></span></div>
    <div class="storage-legend"><span><i class="legend-current"></i>Current</span><span><i class="legend-planned"></i>Planned</span><span><i class="legend-used"></i>Used</span></div>
    <div class="filesystem-list">${storageRows()}</div>
    <div id="storage-plan-controls" hidden><div class="plan-action-row"><button type="button" class="button secondary" id="storage-plan-button" data-studio-action="storage-preview">${icon('check')}Check sizes</button></div><div id="storage-plan-error" class="notice error" role="alert" hidden></div><div id="storage-plan" class="studio-plan"></div></div>
  </div>`;
}
function prepareStudioEditor() {
  const panel=$('#panel-storage');if(!panel||$('#storage-studio'))return;
  const capacity=$('#disk-size').closest('label');capacity.remove();
  $('h3',panel)?.remove();$('.panel-intro',panel)?.remove();
  const direct=document.createElement('details');direct.id='storage-direct-options';direct.className='studio-details editor-disclosure';direct.dataset.disclosure='storage-direct';
  direct.innerHTML='<summary>Direct resize <span class="disclosure-meta">Partitions & LVM growth</span></summary><div class="details-content"></div>';
  const content=$('.details-content',direct);while(panel.firstChild)content.append(panel.firstChild);
  panel.innerHTML=renderStorageStudio();$('#storage-capacity-field').append(capacity);panel.append(direct);
  const disk=$('#disk-size');disk.setAttribute('aria-label','Target disk capacity');disk.step='any';const title=[...capacity.childNodes].find(node=>node.nodeType===3&&node.textContent.trim());if(title)title.textContent='Target disk capacity';const units=document.createElement('div');units.className='capacity-input';disk.replaceWith(units);units.append(disk);units.insertAdjacentHTML('beforeend','<select id="disk-size-unit" aria-label="Capacity unit" data-previous-unit="gib"><option value="gib">GiB (1024³)</option><option value="gb">GB (1000³)</option></select>');const oldHelp=$('.field-help',capacity);if(oldHelp)oldHelp.remove();capacity.insertAdjacentHTML('beforeend',helpHint('Leave blank to keep the current disk capacity. GiB uses 1024³ bytes; GB uses 1000³. Compressed file size is measured after export. Boot migration can add capacity.','Target disk capacity'));
  $$('[data-partition]',direct).forEach(field=>{const part=studioImage().inspection.partitions.find(item=>item.device===field.dataset.partition),size=Math.ceil((part?.size||0)/MiB);field.insertAdjacentHTML('afterend',`<input type="range" class="direct-resize-slider" min="32" max="${Math.max(size*2,1024)}" value="${size}" step="1" data-partition-slider="${esc(field.dataset.partition)}" aria-label="Resize ${esc(field.dataset.partition)} in MiB">`);});
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
  $('#storage-direct-options').hidden=enabled;$('#storage-plan-controls').hidden=!enabled;
  $$('[data-rebuild-controls]').forEach(node=>node.hidden=!enabled);
  const before=Number(inspection.virtual_size)||0,raw=$('#disk-size').value,after=raw?getDiskCapacityBytes():before;
  $('#storage-before').textContent=bytes(before);$('#storage-after').textContent=after>0?bytes(after):'Enter a valid size';$('#storage-reduction').textContent=reductionText(before,after);$('#storage-file-size').textContent=bytes(inspection.actual_size);$('#storage-exact-capacity').textContent=after>0?`${after.toLocaleString('en-US')} bytes`:'Enter a positive disk capacity.';
  const sourceParts=(inspection.partitions||[]).filter(part=>/^\/dev\/sda\d+$/.test(part.device));
  let plan;try { const body=storagePlanBody();const cached=studioSession().storage;if(cached?.signature===JSON.stringify(body)&&cached.snapshot===studioInspectionKey())plan=cached.plan;}catch{}
  let proposed=sourceParts.map(part=>({...part}));
  if(enabled&&plan?.layout?.partitions)proposed=plan.layout.partitions;
  else if(!enabled)proposed=proposed.map(part=>{const input=$$('[data-partition]').find(node=>node.dataset.partition===part.device);return {...part,size:input?.value?Number(input.value)*MiB:part.size};});
  const scale=Math.max(before,after||0,1);
  $('#storage-current-map').innerHTML=partitionMap(sourceParts,before,scale);$('#storage-current-map').setAttribute('aria-label',`Current disk ${bytes(before)}. ${sourceParts.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').innerHTML=partitionMap(proposed,after,scale);$('#storage-planned-map').setAttribute('aria-label',`Planned disk ${bytes(after)}. ${enabled&&!plan?'Partition positions require plan validation.':proposed.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').classList.toggle('unvalidated',enabled&&!plan);$('#storage-current-size').textContent=bytes(before);$('#storage-planned-size').textContent=after>0?bytes(after):'Invalid capacity';
  $('#storage-map-note').textContent=`Scale: ${bytes(scale)}. `+(enabled&&!plan?'Check sizes to update this layout.':enabled&&plan?.ready?'Validated layout.':enabled?'Resolve the size blockers.':'Hatched areas are unallocated.');
  let fsBefore=0,fsAfter=0;
  for(const fs of storageFilesystems()) {
    const row=$$('[data-fs-device]').find(node=>node.dataset.fsDevice===fs.device);if(!row)continue;
    const directField=$$('[data-partition]').find(node=>node.dataset.partition===fs.device),field=storageSizeInputs().find(node=>node.dataset.rebuildDevice===fs.device),selected=plan?.filesystems?.find(item=>item.device===fs.device)?.selected_size_mib,next=enabled&&field?(Number.isFinite(selected)?selected:Number(field.value))*MiB:!enabled&&directField?.value?Number(directField.value)*MiB:Number(fs.size),current=Number(fs.size)||0,used=Number.isFinite(fs.used)?fs.used:null;
    fsBefore+=current;fsAfter+=Number.isFinite(next)?next:current;
    $('[data-fs-planned]',row).textContent=next>0?bytes(next):'Invalid';
    const max=Math.max(current,next||0,1);
    for(const [kind,size] of [['current',current],['planned',next]]) { const track=$(`.fs-track.${kind}`,row),bar=$('.fs-capacity',track);bar.style.width=`${Math.max(0,Math.min(100,size/max*100))}%`;$('.fs-used',track).style.width=used===null?'0%':`${Math.min(100,used/Math.max(size,1)*100)}%`;track.setAttribute('aria-label',`${kind} ${bytes(size)}${used===null?', usage unavailable':', '+bytes(used)+' used'}`); }
    const slider=$('[data-rebuild-slider]',row);if(slider&&field) { slider.max=Math.max(Number(slider.max),Number(field.value)||0);slider.value=field.value;slider.setAttribute('aria-valuetext',`${field.value} MiB`); }
    const minimum=Number(fs.minimum_size_mib);const tooSmall=enabled&&field&&minimum&&Number(field.value)<minimum;const directShrink=!enabled&&directField?.value&&next<current&&fs.filesystem==='xfs';
    const alert=$('[data-fs-alert]',row);alert.hidden=!tooSmall&&!directShrink;alert.textContent=directShrink?'Enable filesystem resizing to shrink XFS.':tooSmall?`Use at least ${minimum.toLocaleString()} MiB.`:'';row.classList.toggle('size-blocked',Boolean(tooSmall||directShrink));
  }
  $$('[data-partition-slider]').forEach(slider=>{const field=$$('[data-partition]').find(node=>node.dataset.partition===slider.dataset.partitionSlider),part=sourceParts.find(item=>item.device===slider.dataset.partitionSlider);slider.max=Math.max(Number(slider.max),Number(field?.value)||0);slider.value=field?.value||Math.ceil((part?.size||0)/MiB);});
  $('#filesystem-reduction').textContent=fsBefore===fsAfter?'':reductionText(fsBefore,fsAfter);
  if(enabled&&plan)renderStoragePlan(plan);
  const button=$('#storage-plan-button');if(button)button.disabled=wizardInspectionPending()||button.getAttribute('aria-busy')==='true';
}
function renderStoragePlan(plan) {
  const container=$('#storage-plan'),signature=JSON.stringify(plan);
  if(container.dataset.renderedPlan===signature&&$('.plan-status',container))return;
  container.dataset.renderedPlan=signature;
  const lines=items=>(items||[]).map(item=>`<li>${esc(item)}</li>`).join('');
  $('#storage-plan').innerHTML=`<div role="status" class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${plan.ready?'Storage plan ready':'Resolve storage blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers" role="alert">${lines(plan.blockers)}</ul>`:''}<div class="plan-facts"><span>Minimum disk <strong>${bytes(plan.layout?.minimum_disk_size)}</strong></span><span>Working space <strong>${bytes(plan.estimated_temporary_bytes)}</strong></span></div>${plan.changes?.length?`<details><summary>Planned changes</summary><ul>${lines(plan.changes)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
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
  button.removeAttribute('aria-busy');button.disabled=wizardInspectionPending();
  button.innerHTML=icon('check')+(kind==='storage'?'Check sizes':'Check hardware');
}
async function previewStorage(config=undefined,beforeBuild=false,disk=undefined) {
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey(),button=$('#storage-plan-button'),requestId=beginStudioPlan(button);notice('#storage-plan-error','');
  try {
    const body=storagePlanBody(config,disk),signature=JSON.stringify(body);
    const plan=await api(`/images/${encodeURIComponent(imageId)}/storage/plan`,{method:'POST',body:signature});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot){if(beforeBuild)throw new Error('Storage choices changed. Check the current plan again.');return null;}
    studioSession().storage={signature,plan,snapshot};updateStorageStudio();renderStoragePlan(plan);
    if(beforeBuild&&(!plan.ready||plan.blockers?.length)){setTab('storage');throw new Error('Resolve the storage plan blockers before continuing.');}return plan;
  }catch(error){if(state.selected===imageId&&state.editorRevision===revision)notice('#storage-plan-error',errorText(error));if(beforeBuild){if(state.selected===imageId)setTab('storage');throw error;}return null;}
  finally{finishStudioPlan(button,requestId,'storage');}
}
function renderPlatformStudio() {
  return `<section id="platform-studio" class="platform-studio">
    <div class="studio-section-heading"><h3>Machine migration</h3>${helpHint('Prepares boot drivers, mounts and networking for another machine type. CPU architecture stays the same; test the output on the destination.','Machine migration')}</div>
    <label class="check-field feature-switch"><input type="checkbox" id="platform-enabled"><span>Prepare for different hardware</span></label>
    <div id="platform-controls" hidden>
      ${!studioImage()?.inspection?.platform?'<div class="notice warning">Refresh inspection to check hardware support. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh</button></div>':''}
      <div class="platform-direction"><label class="field">From<select id="platform-source"><option value="vm">Virtual machine</option><option value="bare_metal">Bare metal</option></select></label><span class="direction-arrow" aria-hidden="true">${icon('arrow')}</span><label class="field">To<select id="platform-target"><option value="bare_metal">Bare metal</option><option value="vm">Virtual machine</option></select></label></div>
      <div class="notice warning" id="platform-provider-warning"></div>
      <div class="form-grid"><label class="field">Boot attachment<select id="platform-boot"><option value="iscsi">Firmware iSCSI</option><option value="paravirtualized">Paravirtualized</option></select>${helpHint('Bare-metal boot needs an iBFT table from the target firmware. Target addresses and credentials are never invented.','Boot attachment')}</label><label class="field">Network attachment<select id="platform-network"><option value="vfio">Physical / VFIO</option><option value="paravirtualized">Paravirtualized</option></select>${helpHint('Choose the adapter type exposed by the destination. Physical networking needs a matching guest NIC driver.','Network attachment')}</label></div>
      <label class="field" id="platform-nic-field">NIC driver<select id="platform-nic"><option value="">Select target driver</option>${['ixgbe','ixgbevf','i40e','iavf','mlx4_en','mlx5_core','bnxt_en'].map(driver=>`<option value="${driver}">${driver}</option>`).join('')}</select>${helpHint('Select the module for the destination NIC. The plan checks every installed kernel.','NIC driver')}</label>
      <details class="editor-disclosure" data-disclosure="platform-options"><summary>Preparation options <span class="disclosure-meta">Network, console & packages</span></summary><div class="details-content platform-options">
        <label class="check-field"><input type="checkbox" id="platform-configure-network" checked><span>Configure network startup${helpHint('Replaces machine-bound network profiles with portable DHCP and prepares early networking when required.','Network startup')}</span></label>
        <label class="check-field"><input type="checkbox" id="platform-serial-console" checked><span>Enable serial console${helpHint('Enables ttyS0 at 115200 baud and a serial login service.','Serial console')}</span></label>
        <label class="check-field"><input type="checkbox" id="platform-install-packages"><span>Install required packages${helpHint('Uses the guest repositories. Guest network access must also be enabled.','Package installation')}</span></label>
        <label class="check-field"><input type="checkbox" id="platform-allow-network"><span>Allow guest network access</span></label>
      </div></details>
      <div class="platform-oci-note" id="platform-oci-note" hidden></div>
      <div class="plan-action-row"><button type="button" class="button secondary" id="platform-plan-button" data-studio-action="platform-preview">${icon('check')}Check hardware</button></div>
      <div id="platform-plan-error" class="notice error" role="alert" hidden></div><div id="platform-plan" class="studio-plan"></div>
    </div></section>`;
}
function getPlatformMigrationConfig() {
  if(!$('#platform-enabled')?.checked)return null;
  const config={enabled:true,source:$('#platform-source').value,target:$('#platform-target').value,boot_attachment:$('#platform-boot').value,network_attachment:$('#platform-network').value,nic_driver:$('#platform-nic').value||null,install_packages:$('#platform-install-packages').checked,configure_network:$('#platform-configure-network').checked,configure_serial_console:$('#platform-serial-console').checked};
  if(config.source===config.target)throw new Error('Choose different source and target platforms.');
  if((config.target==='bare_metal'||config.network_attachment==='vfio')&&!config.nic_driver)throw new Error('Choose the NIC driver for the destination hardware.');
  if(config.install_packages&&!$('#allow-network').checked)throw new Error('Enable networking to install platform packages.');
  return config;
}
function syncOciPlatformChoices() {
  if(!$('#platform-enabled')?.checked)return;
  if($('input[name="target"]:checked')?.value!=='oci'){studioSession().pendingOciPlatformSync=true;return;}
  studioSession().pendingOciPlatformSync=false;
  const boot=$('#platform-boot').value==='iscsi'?'ISCSI':'PARAVIRTUALIZED',network=$('#platform-network').value==='vfio'?'VFIO':'PARAVIRTUALIZED';
  const settings={'Storage.BootVolumeType':boot,'Network.AttachmentType':network,'Compute.LaunchMode':boot==='ISCSI'&&network==='VFIO'?'NATIVE':boot==='PARAVIRTUALIZED'&&network==='PARAVIRTUALIZED'?'PARAVIRTUALIZED':'CUSTOM'};
  if($('#platform-target').value==='bare_metal')settings['Compute.Firmware']='UEFI_64';
  const unavailable=[];
  for(const [key,value] of Object.entries(settings)) {
    const input=$$('[data-oci-default]').find(node=>node.dataset.ociDefault===key);
    if(!input||![...input.options].some(option=>option.value===JSON.stringify(value))){unavailable.push(key);continue;}
    input.value=JSON.stringify(value);$$('[data-oci-allowed]').filter(node=>node.dataset.ociAllowed===key).forEach(node=>node.checked=node.value===JSON.stringify(value));
    if(key==='Compute.Firmware'){state.ociFirmwareEdited=true;if($('#oci-firmware-confirm'))$('#oci-firmware-confirm').checked=true;}
  }
  if($('#oci-launch-mode'))$('#oci-launch-mode').value=settings['Compute.LaunchMode'];
  $('#platform-oci-note').textContent=unavailable.length?`The OCI schema cannot represent ${unavailable.join(', ')}. Review the schema and plan.`:'Attachments synced with OCI.';
  if($('#oci-enabled')?.checked)markOciChanged();
}
function updatePlatformStudio() {
  if(!$('#platform-studio'))return;
  const enabled=$('#platform-enabled').checked,bare=$('#platform-target').value==='bare_metal',oci=$('input[name="target"]:checked')?.value==='oci';
  $('#platform-controls').hidden=!enabled;
  $('#platform-provider-warning').hidden=!bare;
  $('#platform-provider-warning').textContent=oci?'Experimental: OCI BYOI does not support bare metal. Test the output on the target hardware.':'Experimental hardware preparation. A destination boot test is required.';
  $('#platform-nic-field').hidden=!bare&&$('#platform-network').value!=='vfio';
  const note=$('#platform-oci-note');note.hidden=!oci||!note.textContent;
  $('#platform-allow-network').checked=Boolean($('#allow-network')?.checked);
  const button=$('#platform-plan-button');button.disabled=wizardInspectionPending()||button.getAttribute('aria-busy')==='true';
}
function platformPlanBody(config=undefined,recipe=null) {
  const selected=config===undefined?getPlatformMigrationConfig():config;
  return {target:recipe?recipe.target:($('input[name="target"]:checked')?.value||'oci'),platform_migration:selected,allow_network:recipe?recipe.allow_network:$('#allow-network').checked,...((recipe?recipe.boot_migration:getBootMigrationConfig())?{boot_migration:recipe?recipe.boot_migration:getBootMigrationConfig()}:{}),...((recipe?recipe.oci:($('input[name="target"]:checked')?.value==='oci'&&$('#oci-enabled').checked?getOciConfig():null))?{oci:recipe?recipe.oci:getOciConfig()}:{} )};
}
function renderPlatformPlan(plan) {
  const container=$('#platform-plan'),signature=JSON.stringify(plan);
  if(container.dataset.renderedPlan===signature&&$('.plan-status',container))return;
  container.dataset.renderedPlan=signature;
  const lines=items=>(items||[]).map(item=>`<li>${esc(typeof item==='string'?item:JSON.stringify(item))}</li>`).join('');
  $('#platform-plan').innerHTML=`<div role="status" class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${plan.ready?'Hardware plan ready':'Resolve platform blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers" role="alert">${lines(plan.blockers)}</ul>`:''}<div class="plan-facts"><span>Firmware <strong>${esc(Array.isArray(plan.effective_firmware)?plan.effective_firmware.join(', '):plan.effective_firmware||'Not established')}</strong></span><span>Initramfs <strong>${esc(plan.initramfs_backend||'Not established')}</strong></span></div>${plan.required_modules?.length||plan.packages?.length?`<details><summary>Drivers & packages</summary>${plan.required_modules?.length?`<p class="module-list"><strong>Drivers</strong> ${plan.required_modules.map(esc).join(', ')}</p>`:''}${plan.packages?.length?`<p class="module-list"><strong>Packages</strong> ${plan.packages.map(esc).join(', ')}</p>`:''}</details>`:''}${plan.actions?.length?`<details><summary>Planned changes</summary><ul>${lines(plan.actions)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
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
function syncStudioEditor() { if($('#disk-size-unit'))$('#disk-size-unit').dataset.previousUnit=$('#disk-size-unit').value;updateStorageStudio();updatePlatformStudio();try { const cached=studioSession().platform;if(cached?.signature===JSON.stringify(platformPlanBody())&&cached.snapshot===studioInspectionKey())renderPlatformPlan(cached.plan); }catch{}compactStudioHelp($('#recipe-form')||document); }
function invalidateStudioPlans(kind) {
  const node=$(`#${kind}-plan`);
  if(node)node.innerHTML=studioSession()[kind]?'<p class="storage-note">Settings changed. Recheck the plan.</p>':'';
  if(kind==='storage')updateStorageStudio();
}
document.addEventListener('click',event=>{
  const help=event.target.closest('.help-toggle');if(help){event.preventDefault();const anchor=help.closest('.help-anchor'),pinned=anchor.classList.contains('pinned');closeHelp();if(!pinned){studioState.dismissedHelp.delete(anchor);openHelp(anchor);anchor.classList.add('pinned');}return;}
  if(!event.target.closest('.help-anchor'))closeHelp();
  const button=event.target.closest('[data-studio-action]');if(!button)return;
  if(button.dataset.studioAction==='storage-preview')previewStorage();
  if(button.dataset.studioAction==='platform-preview')previewPlatform();
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
  if(input.dataset.partitionSlider){const field=$$('[data-partition]').find(node=>node.dataset.partition===input.dataset.partitionSlider);if(field)field.value=input.value;}
  if(input.dataset.rebuildSlider){const field=storageSizeInputs().find(node=>node.dataset.rebuildDevice===input.dataset.rebuildSlider);if(field)field.value=input.value;}
  if(input.closest('#panel-storage'))invalidateStudioPlans('storage');
  if(input.closest('#platform-controls'))invalidateStudioPlans('platform');
});
document.addEventListener('change',event=>{
  const input=event.target;
  if(input.name==='target'){if(input.value==='oci'&&studioSession().pendingOciPlatformSync)syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
  if(input.id==='disk-size-unit'){const previous=input.dataset.previousUnit||'gib',value=getDiskCapacityBytes(previous);if(value!==null)$('#disk-size').value=String(value/(input.value==='gb'?1e9:GiB));input.dataset.previousUnit=input.value;invalidateStudioPlans('storage');}
  if(input.id==='storage-rebuild-enabled'){updateStorageStudio();invalidateStudioPlans('storage');}
  if(input.id==='platform-enabled'||['platform-source','platform-target'].includes(input.id)) {
    if(input.id==='platform-source')$('#platform-target').value=input.value==='vm'?'bare_metal':'vm';
    if(input.id==='platform-target')$('#platform-source').value=input.value==='vm'?'bare_metal':'vm';
    const bare=$('#platform-target').value==='bare_metal';$('#platform-boot').value=bare?'iscsi':'paravirtualized';$('#platform-network').value=bare?'vfio':'paravirtualized';
    syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');
  }
  if(['platform-boot','platform-network'].includes(input.id)){syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
  if(input.closest('#panel-storage'))updateStorageStudio();
  if(['allow-network','oci-allow-network','migration-allow-network','platform-allow-network'].includes(input.id)) {
    ['allow-network','oci-allow-network','migration-allow-network','platform-allow-network'].forEach(id=>{if($(`#${id}`))$(`#${id}`).checked=input.checked;});invalidateStudioPlans('platform');
  }
});

window.addEventListener('scroll',()=>{const anchor=$('.help-anchor.open');if(!anchor)return;const rect=$('.help-toggle',anchor).getBoundingClientRect();if(rect.bottom<0||rect.top>innerHeight)closeHelp();else positionHelp(anchor);},{passive:true});
window.addEventListener('resize',()=>closeHelp());
