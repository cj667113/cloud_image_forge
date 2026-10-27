'use strict';
const studioState = {plans:{},helpId:0};
const MiB = 1024 ** 2, GiB = 1024 ** 3;
function studioImage() { return state.images.find(image => image.id === state.selected); }
function studioSession() { return studioState.plans[state.selected] ||= {}; }
function studioInspectionKey() { const image=studioImage();return JSON.stringify([image?.inspected_at||image?.updated_at,image?.inspection?.storage,image?.inspection?.platform,image?.inspection?.boot]); }
function helpHint(text,label='More information') {
  const id = `help-${++studioState.helpId}`;
  return `<span class="help-anchor"><button type="button" class="help-toggle" aria-label="${esc(label)}" aria-expanded="false" aria-controls="${id}" aria-describedby="${id}">?</button><span class="help-popover" role="tooltip" id="${id}">${esc(text)}</span></span>`;
}
function closeHelp(except=null) { $$('.help-anchor.open').forEach(anchor => { if(anchor!==except) { anchor.classList.remove('open','pinned'); $('.help-toggle',anchor).setAttribute('aria-expanded','false'); } }); }
function openHelp(anchor) { closeHelp(anchor); anchor.classList.add('open'); const button=$('.help-toggle',anchor),popover=$('.help-popover',anchor); button.setAttribute('aria-expanded','true'); const box=button.getBoundingClientRect();popover.style.left=`${Math.max(14,Math.min(innerWidth-popover.offsetWidth-14,box.right-popover.offsetWidth))}px`;popover.style.top=`${box.bottom+8+popover.offsetHeight>innerHeight?Math.max(14,box.top-popover.offsetHeight-8):box.bottom+8}px`; }
function compactStudioHelp(root=document) {
  $$('.field-help,.check-field small',root).forEach(node => {
    if (node.dataset.visibleHelp || node.dataset.compacted || node.closest('.help-anchor') || node.closest('#storage-studio,#platform-studio')) return;
    const owner = node.closest('label'); if (!owner || !node.textContent.trim()) return;
    const text=node.textContent.trim(),label=[...owner.childNodes].find(child=>child.nodeType===3&&child.textContent.trim())?.textContent.trim()||$(':scope > span',owner)?.firstChild?.textContent?.trim()||'this setting';node.dataset.compacted='true';
    const holder=document.createElement('span');holder.innerHTML=helpHint(text,`Help: ${label.slice(0,90)}`);
    owner.classList.add('has-help');owner.append(holder.firstElementChild);node.remove();
  });
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
    return `<article class="filesystem-row" data-fs-device="${esc(fs.device)}"><div class="filesystem-heading"><div><span class="filesystem-dot color-${index%5}"></span><strong>${esc(fs.mountpoint||fs.device)}</strong><span class="badge">${esc(fs.filesystem||'Unknown')}</span>${fs.kind==='lv'?'<span class="filesystem-kind">Logical volume</span>':''}</div><code>${esc(fs.device)}</code></div><div class="filesystem-sizes"><span>Current <strong>${bytes(fs.size)}</strong></span><span>Planned <strong data-fs-planned>${bytes(fs.size)}</strong></span><span>${known?'Used <strong>'+bytes(fs.used)+'</strong>':'Usage not inspected'}</span></div><div class="filesystem-tracks"><div class="fs-track current" aria-label="Current capacity"><span class="fs-capacity"><i class="fs-used"></i></span></div><div class="fs-track planned" aria-label="Planned capacity"><span class="fs-capacity"><i class="fs-used"></i></span></div></div>${fs.editable?`<div class="filesystem-resize" data-rebuild-controls hidden><label class="slider-field"><span class="sr-only">Resize ${esc(fs.mountpoint||fs.device)} in MiB</span><input type="range" min="${minimum}" max="${Math.max(current*2,minimum+1024)}" step="1" value="${current}" data-rebuild-slider="${esc(fs.device)}"></label><label class="size-field"><input type="number" min="32" step="1" value="${current}" data-rebuild-device="${esc(fs.device)}" aria-label="Capacity of ${esc(fs.device)} in MiB"><span>MiB</span></label></div><div class="filesystem-minimum" data-rebuild-controls hidden>Estimated minimum: ${minimum.toLocaleString()} MiB ${helpHint('This estimate includes data and headroom. Logical volume sizes round up to 4 MiB extents. The server checks the layout and verifies the rebuild; a minimum estimate is not a guarantee.','Minimum size estimate')}</div>`:`<span class="filesystem-locked">${fs.kind==='efi'?'EFI partition preserved':'Read-only layout evidence'}${helpHint(fs.kind==='efi'?'The EFI partition is copied at its original size to retain boot files.':'Refresh inspection to collect supported filesystem and usage evidence.','Why this capacity is fixed')}</span>`}<div class="filesystem-alert" data-fs-alert role="status" hidden></div></article>`;
  }).join('') || '<p class="muted">No filesystem layout is available. Refresh inspection to collect storage evidence.</p>';
}
function renderStorageStudio() {
  const evidence=studioImage()?.inspection?.storage;
  return `<div id="storage-studio"><div class="studio-section-heading"><div><span class="eyebrow">DISK DESIGNER</span><h3>Shape your image</h3></div>${helpHint('Virtual capacity is the size the guest sees. File length is the amount transferred. Shrinking filesystems or a virtual disk does not predict the final compressed file size.','Capacity and file size')}</div><div class="storage-summary" aria-live="polite"><div><span>Current disk</span><strong id="storage-before"></strong></div><div><span>Planned disk</span><strong id="storage-after"></strong></div><div class="storage-saving"><span>Disk reduction</span><strong id="storage-reduction"></strong></div><div><span>Source file length</span><strong id="storage-file-size"></strong></div></div><div id="storage-capacity-field"></div><div class="disk-comparison"><div class="disk-caption"><span>Current partition layout</span><span id="storage-current-size"></span></div><div class="disk-track" id="storage-current-map" role="img"></div><div class="disk-caption"><span>Planned partition layout</span><span id="storage-planned-size"></span></div><div class="disk-track" id="storage-planned-map" role="img"></div><div id="storage-map-note" class="storage-note"></div></div><label class="check-field feature-switch"><input type="checkbox" id="storage-rebuild-enabled"><span>Rebuild filesystems at new sizes${helpHint('Copies supported filesystems into a new layout. This supports smaller XFS filesystems and logical volumes without truncating live data. The imported source remains unchanged.','Filesystem rebuild')}</span></label><div id="storage-rebuild-scope" class="notice info" hidden>Creates new filesystems and copies their data. Source preserved.</div>${!evidence?'<div class="notice warning">Usage and rebuild evidence need a fresh inspection. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh inspection</button></div>':''}<div class="storage-row-heading"><h4>Filesystems</h4><span id="filesystem-reduction" aria-live="polite"></span></div><div class="storage-legend"><span><i class="legend-current"></i>Current</span><span><i class="legend-planned"></i>Planned</span><span><i class="legend-used"></i>Used data</span></div><div class="filesystem-list">${storageRows()}</div><div id="storage-plan-controls" hidden><div class="plan-action-row"><span>Validate sizes and the rebuilt layout</span><button type="button" class="button secondary" id="storage-plan-button" data-studio-action="storage-preview">${icon('check')}Check storage plan</button></div><div id="storage-plan-error" class="notice error" role="alert" hidden></div><div id="storage-plan" class="studio-plan" aria-live="polite"></div></div><p class="storage-note">Output file size is measured after export. Disk growth for boot migration is checked separately.</p></div>`;
}
function prepareStudioEditor() {
  const panel=$('#panel-storage');if(!panel||$('#storage-studio'))return;
  const capacity=$('#disk-size').closest('label');capacity.remove();
  $('h3',panel)?.remove();$('.panel-intro',panel)?.remove();
  const direct=document.createElement('details');direct.id='storage-direct-options';direct.className='studio-details';
  direct.innerHTML='<summary>Direct partition resize & expansion</summary><div class="details-content"></div>';
  const content=$('.details-content',direct);while(panel.firstChild)content.append(panel.firstChild);
  panel.innerHTML=renderStorageStudio();$('#storage-capacity-field').append(capacity);panel.append(direct);
  const disk=$('#disk-size');disk.setAttribute('aria-label','Target disk capacity');disk.step='any';const title=[...capacity.childNodes].find(node=>node.nodeType===3&&node.textContent.trim());if(title)title.textContent='Target disk capacity';const units=document.createElement('div');units.className='capacity-input';disk.replaceWith(units);units.append(disk);units.insertAdjacentHTML('beforeend','<select id="disk-size-unit" aria-label="Capacity unit" data-previous-unit="gib"><option value="gib">GiB (1024³)</option><option value="gb">GB (1000³)</option></select>');const oldHelp=$('.field-help',capacity);if(oldHelp)oldHelp.remove();capacity.insertAdjacentHTML('beforeend','<span id="storage-exact-capacity" class="storage-note" aria-live="polite"></span>');
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
  $('#storage-direct-options').hidden=enabled;$('#storage-plan-controls').hidden=!enabled;$('#storage-rebuild-scope').hidden=!enabled;
  $$('[data-rebuild-controls]').forEach(node=>node.hidden=!enabled);
  const before=Number(inspection.virtual_size)||0,raw=$('#disk-size').value,after=raw?getDiskCapacityBytes():before;
  $('#storage-before').textContent=bytes(before);$('#storage-after').textContent=after>0?bytes(after):'Enter a valid size';$('#storage-reduction').textContent=reductionText(before,after);$('#storage-file-size').textContent=bytes(inspection.actual_size);$('#storage-exact-capacity').textContent=after>0?`${after.toLocaleString('en-US')} bytes${raw?' · rounded up to 512-byte sectors':' · source capacity retained'}`:'Enter a positive disk capacity.';
  const sourceParts=(inspection.partitions||[]).filter(part=>/^\/dev\/sda\d+$/.test(part.device));
  let plan;try { const body=storagePlanBody();const cached=studioSession().storage;if(cached?.signature===JSON.stringify(body)&&cached.snapshot===studioInspectionKey())plan=cached.plan;}catch{}
  let proposed=sourceParts.map(part=>({...part}));
  if(enabled&&plan?.layout?.partitions)proposed=plan.layout.partitions;
  else if(!enabled)proposed=proposed.map(part=>{const input=$$('[data-partition]').find(node=>node.dataset.partition===part.device);return {...part,size:input?.value?Number(input.value)*MiB:part.size};});
  const scale=Math.max(before,after||0,1);
  $('#storage-current-map').innerHTML=partitionMap(sourceParts,before,scale);$('#storage-current-map').setAttribute('aria-label',`Current disk ${bytes(before)}. ${sourceParts.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').innerHTML=partitionMap(proposed,after,scale);$('#storage-planned-map').setAttribute('aria-label',`Planned disk ${bytes(after)}. ${enabled&&!plan?'Partition positions require plan validation.':proposed.map(part=>part.device+' '+bytes(part.size)).join(', ')}`);
  $('#storage-planned-map').classList.toggle('unvalidated',enabled&&!plan);$('#storage-current-size').textContent=bytes(before);$('#storage-planned-size').textContent=after>0?bytes(after):'Invalid capacity';
  $('#storage-map-note').textContent=`Shared ${bytes(scale)} scale. `+(enabled&&!plan?'Check the storage plan to calculate partition positions.':enabled?'Validated rebuild layout. Final boot-migration growth may add capacity.':'Unallocated space is hatched. Filesystem usage appears below.');
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
    const alert=$('[data-fs-alert]',row);alert.hidden=!tooSmall&&!directShrink;alert.textContent=directShrink?'XFS cannot shrink in place. Enable filesystem rebuild above.':tooSmall?`Below estimated minimum of ${minimum.toLocaleString()} MiB. Increase capacity or review the server blockers.`:'';row.classList.toggle('size-blocked',Boolean(tooSmall||directShrink));
  }
  $$('[data-partition-slider]').forEach(slider=>{const field=$$('[data-partition]').find(node=>node.dataset.partition===slider.dataset.partitionSlider),part=sourceParts.find(item=>item.device===slider.dataset.partitionSlider);slider.max=Math.max(Number(slider.max),Number(field?.value)||0);slider.value=field?.value||Math.ceil((part?.size||0)/MiB);});
  $('#filesystem-reduction').textContent=`Filesystem capacity: ${reductionText(fsBefore,fsAfter)}`;
  if(enabled&&plan)renderStoragePlan(plan);
  const button=$('#storage-plan-button');if(button)button.disabled=wizardInspectionPending();
}
function renderStoragePlan(plan) {
  const lines=items=>(items||[]).map(item=>`<li>${esc(item)}</li>`).join('');
  $('#storage-plan').innerHTML=`<div class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${plan.ready?'Storage plan ready':'Resolve storage blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers">${lines(plan.blockers)}</ul>`:''}<div class="plan-facts"><span>Minimum disk <strong>${bytes(plan.layout?.minimum_disk_size)}</strong></span><span>Temporary workspace <strong>${bytes(plan.estimated_temporary_bytes)}</strong></span></div>${plan.changes?.length?`<details><summary>Planned changes</summary><ul>${lines(plan.changes)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
}
async function previewStorage(config=undefined,beforeBuild=false,disk=undefined) {
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey(),button=$('#storage-plan-button');if(button)button.disabled=true;notice('#storage-plan-error','');
  try {
    const body=storagePlanBody(config,disk),signature=JSON.stringify(body);
    const plan=await api(`/images/${encodeURIComponent(imageId)}/storage/plan`,{method:'POST',body:signature});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot)throw new Error('Storage choices changed. Check the current plan again.');
    studioSession().storage={signature,plan,snapshot};updateStorageStudio();renderStoragePlan(plan);
    if(beforeBuild&&(!plan.ready||plan.blockers?.length)){setTab('storage');throw new Error('Resolve the storage plan blockers before continuing.');}return plan;
  }catch(error){if(state.selected===imageId)notice('#storage-plan-error',errorText(error));if(beforeBuild){if(state.selected===imageId)setTab('storage');throw error;}return null;}
  finally{if(button?.isConnected)button.disabled=wizardInspectionPending();}
}
function renderPlatformStudio() {
  return `<section id="platform-studio" class="platform-studio"><div class="studio-section-heading"><div><span class="eyebrow">TARGET HARDWARE</span><h3>VM & bare-metal preparation</h3></div>${helpHint('Changes drivers, early-boot networking, mounts and startup configuration when supported by the guest. It does not convert CPU architectures or prove compatibility with a cloud shape.','Platform preparation')}</div><label class="check-field feature-switch"><input type="checkbox" id="platform-enabled"><span>Prepare this image for a different platform</span></label><div id="platform-controls" hidden>${!studioImage()?.inspection?.platform?'<div class="notice warning">Platform evidence needs a fresh inspection. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh inspection</button></div>':''}<div class="platform-direction"><label class="field">Source platform<select id="platform-source"><option value="vm">Virtual machine</option><option value="bare_metal">Bare metal</option></select></label><span class="direction-arrow" aria-hidden="true">${icon('arrow')}</span><label class="field">Target platform<select id="platform-target"><option value="bare_metal">Bare metal</option><option value="vm">Virtual machine</option></select></label></div><div class="notice warning" id="platform-provider-warning">Experimental. OCI BYOI does not support bare-metal instances. Prepare only for hardware you will validate separately.</div><div class="form-grid"><label class="field">Boot attachment<select id="platform-boot"><option value="iscsi">Firmware-discovered iSCSI</option><option value="paravirtualized">Paravirtualized</option></select>${helpHint('iSCSI boot requires the target firmware to supply an iBFT discovery table. No target IP address or IQN is invented. Bare-metal preparation requires this boot path.','Boot attachment')}</label><label class="field">Network attachment<select id="platform-network"><option value="vfio">Physical / VFIO</option><option value="paravirtualized">Paravirtualized</option></select>${helpHint('Physical and VFIO network adapters need a guest driver matching the destination hardware. VFIO itself is not a guest Ethernet driver.','Network attachment')}</label></div><label class="field" id="platform-nic-field">Target NIC driver<select id="platform-nic"><option value="">Choose a driver for the target hardware</option>${['ixgbe','ixgbevf','i40e','iavf','mlx4_en','mlx5_core','bnxt_en'].map(driver=>`<option value="${driver}">${driver}</option>`).join('')}</select>${helpHint('Choose the module for the destination NIC. Installed modules and initramfs support are checked before export; the target hardware must still be verified.','NIC driver')}</label><div class="platform-options"><label class="check-field"><input type="checkbox" id="platform-configure-network" checked><span>Configure early network startup</span></label><label class="check-field"><input type="checkbox" id="platform-serial-console" checked><span>Configure serial console</span></label><label class="check-field"><input type="checkbox" id="platform-install-packages"><span>Install required packages${helpHint('Installs the planner’s required packages from guest repositories. Guest networking must also be explicitly enabled.','Package installation')}</span></label><label class="check-field"><input type="checkbox" id="platform-allow-network"><span>Allow networking during customization</span></label></div><div class="platform-oci-note" id="platform-oci-note">Attachment choices are mirrored into the OCI controls. Review the compatibility step before exporting.</div><div class="plan-action-row"><span>Check firmware, drivers and startup support</span><button type="button" class="button secondary" id="platform-plan-button" data-studio-action="platform-preview">${icon('check')}Check platform plan</button></div><div id="platform-plan-error" class="notice error" role="alert" hidden></div><div id="platform-plan" class="studio-plan" aria-live="polite"></div><p class="storage-note">A successful boot on the destination hardware remains unverified.</p></div></section>`;
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
  $('#platform-oci-note').textContent=unavailable.length?`The OCI schema cannot represent ${unavailable.join(', ')}. Review the schema and plan.`:'Attachments copied to OCI controls. Later OCI edits stay until you change this profile.';
  if($('#oci-enabled')?.checked)markOciChanged();
}
function updatePlatformStudio() {
  if(!$('#platform-studio'))return;
  const enabled=$('#platform-enabled').checked,bare=$('#platform-target').value==='bare_metal';$('#platform-controls').hidden=!enabled;$('#platform-provider-warning').hidden=!bare;$('#platform-nic-field').hidden=!bare&&$('#platform-network').value!=='vfio';
  $('#platform-allow-network').checked=Boolean($('#allow-network')?.checked);$('#platform-plan-button').disabled=wizardInspectionPending();
}
function platformPlanBody(config=undefined,recipe=null) {
  const selected=config===undefined?getPlatformMigrationConfig():config;
  return {target:recipe?recipe.target:($('input[name="target"]:checked')?.value||'oci'),platform_migration:selected,allow_network:recipe?recipe.allow_network:$('#allow-network').checked,...((recipe?recipe.boot_migration:getBootMigrationConfig())?{boot_migration:recipe?recipe.boot_migration:getBootMigrationConfig()}:{}),...((recipe?recipe.oci:($('input[name="target"]:checked')?.value==='oci'&&$('#oci-enabled').checked?getOciConfig():null))?{oci:recipe?recipe.oci:getOciConfig()}:{} )};
}
function renderPlatformPlan(plan) {
  const lines=items=>(items||[]).map(item=>`<li>${esc(typeof item==='string'?item:JSON.stringify(item))}</li>`).join('');
  $('#platform-plan').innerHTML=`<div class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${plan.ready?'Guest preparation plan ready':'Resolve platform blockers'}</strong></div>${plan.blockers?.length?`<ul class="plan-blockers">${lines(plan.blockers)}</ul>`:''}${plan.experimental||plan.provider_supported===false?'<div class="notice warning">Experimental guest preparation. Provider support is not established.</div>':''}<div class="plan-facts"><span>Firmware <strong>${esc(Array.isArray(plan.effective_firmware)?plan.effective_firmware.join(', '):plan.effective_firmware||'Not established')}</strong></span><span>Initramfs <strong>${esc(plan.initramfs_backend||'Not established')}</strong></span></div>${plan.required_modules?.length?`<p class="module-list"><strong>Drivers</strong> ${plan.required_modules.map(esc).join(', ')}</p>`:''}${plan.packages?.length?`<p class="module-list"><strong>Packages</strong> ${plan.packages.map(esc).join(', ')}</p>`:''}${plan.actions?.length?`<details><summary>Planned changes</summary><ul>${lines(plan.actions)}</ul></details>`:''}${plan.warnings?.length?`<details><summary>Checks & limitations (${plan.warnings.length})</summary><ul>${lines(plan.warnings)}</ul></details>`:''}`;
}
async function previewPlatform(config=undefined,beforeBuild=false,recipe=null) {
  const imageId=state.selected,revision=state.editorRevision,snapshot=studioInspectionKey(),button=$('#platform-plan-button');if(button)button.disabled=true;notice('#platform-plan-error','');
  try {
    const body=platformPlanBody(config,recipe);if(!body.platform_migration)throw new Error('Enable platform preparation to check its prerequisites.');
    const plan=await api(`/images/${encodeURIComponent(imageId)}/platform/plan`,{method:'POST',body:JSON.stringify(body)});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot)throw new Error('Platform choices changed. Check the current plan again.');
    studioSession().platform={signature:JSON.stringify(body),plan,snapshot};renderPlatformPlan(plan);
    if(beforeBuild&&(!plan.ready||plan.blockers?.length)){setTab('export');throw new Error('Resolve the platform plan blockers before continuing.');}return plan;
  }catch(error){if(state.selected===imageId)notice('#platform-plan-error',errorText(error));if(beforeBuild){if(state.selected===imageId)setTab('export');throw error;}return null;}
  finally{if(button?.isConnected)button.disabled=wizardInspectionPending();}
}
function syncStudioEditor() { if($('#disk-size-unit'))$('#disk-size-unit').dataset.previousUnit=$('#disk-size-unit').value;updateStorageStudio();updatePlatformStudio();try { const cached=studioSession().platform;if(cached?.signature===JSON.stringify(platformPlanBody())&&cached.snapshot===studioInspectionKey())renderPlatformPlan(cached.plan); }catch{}compactStudioHelp($('#recipe-form')||document); }
function invalidateStudioPlans(kind) {
  const node=$(`#${kind}-plan`);if(node)node.innerHTML='<p class="storage-note">Choices changed. Check the plan again.</p>';
  if(kind==='storage')updateStorageStudio();
}
document.addEventListener('click',event=>{
  const help=event.target.closest('.help-toggle');if(help){event.preventDefault();const anchor=help.closest('.help-anchor'),pinned=anchor.classList.contains('pinned');closeHelp();if(!pinned){openHelp(anchor);anchor.classList.add('pinned');}return;}
  if(!event.target.closest('.help-anchor'))closeHelp();
  const button=event.target.closest('[data-studio-action]');if(!button)return;
  if(button.dataset.studioAction==='storage-preview')previewStorage();
  if(button.dataset.studioAction==='platform-preview')previewPlatform();
});
document.addEventListener('mouseover',event=>{const anchor=event.target.closest('.help-anchor');if(anchor)openHelp(anchor);});
document.addEventListener('mouseout',event=>{const anchor=event.target.closest('.help-anchor');if(anchor&&!anchor.contains(event.relatedTarget)&&!anchor.classList.contains('pinned')&&!anchor.contains(document.activeElement))closeHelp();});
document.addEventListener('focusin',event=>{const anchor=event.target.closest('.help-anchor');if(anchor)openHelp(anchor);});
document.addEventListener('focusout',event=>{const anchor=event.target.closest('.help-anchor');if(anchor&&!anchor.contains(event.relatedTarget)&&!anchor.classList.contains('pinned'))closeHelp();});
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeHelp();});
document.addEventListener('input',event=>{
  const input=event.target;
  if(input.dataset.partitionSlider){const field=$$('[data-partition]').find(node=>node.dataset.partition===input.dataset.partitionSlider);if(field)field.value=input.value;}
  if(input.dataset.rebuildSlider){const field=storageSizeInputs().find(node=>node.dataset.rebuildDevice===input.dataset.rebuildSlider);if(field)field.value=input.value;}
  if(input.closest('#panel-storage'))invalidateStudioPlans('storage');
  if(input.closest('#platform-controls'))invalidateStudioPlans('platform');
});
document.addEventListener('change',event=>{
  const input=event.target;
  if(input.id==='disk-size-unit'){const previous=input.dataset.previousUnit||'gib',value=getDiskCapacityBytes(previous);if(value!==null)$('#disk-size').value=String(value/(input.value==='gb'?1e9:GiB));input.dataset.previousUnit=input.value;invalidateStudioPlans('storage');}
  if(input.id==='storage-rebuild-enabled'){updateStorageStudio();invalidateStudioPlans('storage');}
  if(input.id==='platform-enabled'||['platform-source','platform-target'].includes(input.id)) {
    if(input.id==='platform-source')$('#platform-target').value=input.value==='vm'?'bare_metal':'vm';
    if(input.id==='platform-target')$('#platform-source').value=input.value==='vm'?'bare_metal':'vm';
    const bare=$('#platform-target').value==='bare_metal';$('#platform-boot').value=bare?'iscsi':'paravirtualized';$('#platform-network').value=bare?'vfio':'paravirtualized';
    updatePlatformStudio();syncOciPlatformChoices();invalidateStudioPlans('platform');
  }
  if(['platform-boot','platform-network'].includes(input.id)){updatePlatformStudio();syncOciPlatformChoices();invalidateStudioPlans('platform');}
  if(input.closest('#panel-storage'))updateStorageStudio();
  if(['allow-network','oci-allow-network','migration-allow-network','platform-allow-network'].includes(input.id)) {
    ['allow-network','oci-allow-network','migration-allow-network','platform-allow-network'].forEach(id=>{if($(`#${id}`))$(`#${id}`).checked=input.checked;});invalidateStudioPlans('platform');
  }
});

window.addEventListener('scroll',()=>{const anchor=$('.help-anchor.open');if(!anchor)return;const rect=$('.help-toggle',anchor).getBoundingClientRect();if(rect.bottom<0||rect.top>innerHeight)closeHelp();else openHelp(anchor);},{passive:true});
window.addEventListener('resize',()=>closeHelp());
