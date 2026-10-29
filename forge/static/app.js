'use strict';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const state = {editorRevision:0,buildSubmitting:false,editorDrafts:{},migrationAutoFirmware:null,ociFirmwareEdited:false,inspectionRefreshing:null,ociCatalog:null,ociBaseCatalog:null,ociCatalogError:null,ociLoadedSchema:null,images:[], jobs:[], artifacts:[], health:null, selected:null, renderedImage:null, view:'images', importMode:'file', selectedFile:null, s3Artifact:null, uploadXhr:null, uploadCancelled:false, polling:false, authPending:false, busy:false};
const profiles = {
  oci:{label:'Oracle Cloud',format:'qcow2',title:'OCI · compressed QCOW2',description:'Standalone QCOW2 with zlib compression and 128 KiB clusters. Review firmware and launch options when importing into OCI.'},
  aws:{label:'Amazon AWS',format:'raw',title:'AWS · RAW disk image',description:'A raw disk image for the EC2 VM Import/Export workflow. Your guest OS, drivers, and boot configuration must meet AWS requirements.'},
  azure:{label:'Microsoft Azure',format:'vhd',title:'Azure · fixed VHD',description:'A fixed-size VHD with virtual capacity aligned to 1 MiB. Match the Azure VM generation to your source firmware.'},
  gcp:{label:'Google Cloud',format:'gcp',title:'Google Cloud · disk.raw archive',description:'A gzip-compressed tar archive containing disk.raw for the Compute Engine image import workflow.'},
  generic:{label:'Other / generic',format:'qcow2',title:'Generic · your choice of disk format',description:'Export a standalone QCOW2, RAW disk, or fixed VHD for a compatible hypervisor or cloud import service.'}
};
function normalizeArchitecture(value) { const arch=String(value||'').toLowerCase();return ({arm64:'aarch64',amd64:'x86_64'})[arch]||arch; }
function sourceArchitecture() { return normalizeArchitecture(state.images.find(image=>image.id===state.selected)?.inspection?.os?.arch); }
function architectureName(value=sourceArchitecture()) { return ({aarch64:'ARM64 (aarch64)',x86_64:'x86_64'})[normalizeArchitecture(value)]||value||'Not inspected'; }
function updateArchitectureHints() {
  const arch=sourceArchitecture(),engine=state.health?.engine||{},worker=normalizeArchitecture(engine.worker_arch);
  const executable=(engine.guest_execution_architectures||[worker]).map(normalizeArchitecture);
  const restricted=Boolean(['aarch64','x86_64'].includes(arch)&&worker&&!executable.includes(arch));
  const note=$('#architecture-worker-notice');
  if(note){note.hidden=!restricted;const signature=JSON.stringify([arch,worker,restricted]);if(note.dataset.signature!==signature){note.dataset.signature=signature;note.innerHTML=`Guest commands require an ${esc(architectureName(arch))} worker.${helpHint(`Current worker: ${architectureName(worker)}. Inspection, file edits, storage changes, preservation and export remain available. Packages, initramfs/GRUB rebuilds, service actions, SSH access changes, OCI preparation and reconfiguration need a worker that can execute this guest architecture. Your draft is kept. CPU architecture is not converted.`, 'Guest execution architecture')}`;}}
  const source=$('#oci-source-architecture');if(source)source.textContent=arch?`${architectureName()} source`:'Architecture not inspected';
  $$('[data-shape-field="shape"]').forEach(input=>input.placeholder=arch==='aarch64'?'VM.Standard.A1.Flex':arch==='x86_64'?'VM.Standard.E5.Flex':'Exact OCI shape name');
  const migration=$('#boot-migration-enabled'),section=$('#boot-migration-section');
  if(migration&&section){const arm=arch==='aarch64',uefi=state.images.find(image=>image.id===state.selected)?.inspection?.boot?.mode==='uefi';migration.disabled=arm&&!migration.checked;section.hidden=arm&&uefi&&!migration.checked;notice('#migration-architecture-error',arm&&migration.checked?'ARM64 requires existing ARM64 UEFI. Clear BIOS-to-UEFI conversion; it cannot convert CPU architecture.':'');}
}
function bytes(value) { const size = Number(value); if (!Number.isFinite(size)) return '—'; if (size === 0) return '0 B'; const n = Math.min(Math.floor(Math.log(size) / Math.log(1024)), 4); return `${(size / 1024 ** n).toLocaleString(undefined,{maximumFractionDigits:n ? 2 : 0})} ${['B','KiB','MiB','GiB','TiB'][n]}`; }
function badge(status) { return `<span class="badge ${['ready','succeeded','failed','running','importing','queued'].includes(status) ? status : ''}">${esc(status || 'unknown')}</span>`; }
function errorText(error) { return error?.message || String(error); }
function notice(id, message) { const node = $(id); if (!node) return; node.textContent = message || ''; node.hidden = !message; }
function editorError(message, field) { const error = new Error(message); error.field = typeof field === 'string' ? $(field) : field; return error; }
function revealEditorField(field) {
  if (!field) return;
  for (let parent = field.parentElement; parent; parent = parent.parentElement) if (parent.tagName === 'DETAILS') parent.open = true;
  field.focus({preventScroll:true});
  field.scrollIntoView({block:'center',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
}
function updateOciVisibility() { const settings = $('#oci-settings'); if (settings) settings.hidden = !$('#oci-enabled').checked; }
function ociValueLabel(value) { return value === 'ACCELERATEDPV' ? 'Accelerated PV' : value; }
function ociAcceleratedKeys(capabilities = readOciCapabilities(false)) {
  const keys = new Set(['Compute.LaunchMode','Network.AttachmentType'].filter(key => capabilities[key]?.default_value === 'ACCELERATEDPV' || capabilities[key]?.values?.includes('ACCELERATEDPV')));
  if ($('#platform-enabled')?.checked && $('#platform-network')?.value === 'accelerated') keys.add('Network.AttachmentType');
  return [...keys];
}
function ociAcceleratedSchemaError(catalog = state.ociCatalog, capabilities) {
  const missing = ociAcceleratedKeys(capabilities).filter(key => !catalog?.capabilities?.find(item => item.key === key)?.values?.includes('ACCELERATEDPV'));
  return missing.length ? `This OCI schema does not allow Accelerated PV for ${missing.join(', ')}. Use a regional schema that supports it or change the accelerated selections.` : '';
}
function updateDisclosureSummaries() {
  updateOciVisibility();
  updatePlatformPreserveConflict();
  updateArchitectureHints();
  syncSshAccess();
  updateMountPolicy();
  const serviceSummary=$('[data-service-change-count]');
  if(serviceSummary) { const count=$$('.rule-row').length;serviceSummary.textContent=count?`${count} ${count===1?'action':'actions'}`:'None'; }
  const firmwareAlert = $('#oci-firmware-alert');
  if (firmwareAlert) firmwareAlert.hidden = studioImage()?.inspection?.boot?.mode === 'dual' && state.ociFirmwareEdited;
  $$('[data-oci-group]').forEach(group => {
    const controls = $$('[data-oci-default]',group);
    const choices = Object.fromEntries(controls.map(node => [node.dataset.ociDefault,node.type === 'checkbox' ? node.checked : node.selectedOptions?.[0]?.textContent || node.value]));
    const friendly = value => ({UEFI_64:'UEFI',PARAVIRTUALIZED:'PV',NATIVE:'Native',EMULATED:'Emulated',CUSTOM:'Custom',ACCELERATEDPV:'Accelerated PV',ISCSI:'iSCSI',IDE:'IDE',SCSI:'SCSI',VFIO:'VFIO'}[value] || value);
    let values;
    if ('Compute.Firmware' in choices) values = [friendly(choices['Compute.Firmware']),...(choices['Compute.LaunchMode'] ? [friendly(choices['Compute.LaunchMode'])+' launch'] : [])];
    else if ('Network.AttachmentType' in choices) values = [friendly(choices['Network.AttachmentType']),...(choices['Network.IPv6Only'] ? ['IPv6-only'] : [])];
    else if ('Storage.BootVolumeType' in choices) {
      const boot = choices['Storage.BootVolumeType'];
      values = [friendly(boot)+' boot',...['Local','Remote'].filter(kind => choices[`Storage.${kind}DataVolumeType`] && choices[`Storage.${kind}DataVolumeType`] !== boot).map(kind => `${friendly(choices[`Storage.${kind}DataVolumeType`])} ${kind.toLowerCase()}`)];
    } else values = controls.slice(0,2).map(node => {
      const label = node.closest('.oci-capability')?.querySelector('h4')?.textContent || node.dataset.ociDefault;
      const value = node.type === 'checkbox' ? node.checked ? 'On' : 'Off' : friendly(node.selectedOptions?.[0]?.textContent || node.value);
      return `${label}: ${value}`;
    });
    const summary = $('.oci-group-summary',group); if (summary) summary.textContent = values.join(' · ');
  });
  $$('[data-allowed-summary]').forEach(node => {
    node.textContent = $$('[data-oci-allowed]',node.closest('details')).filter(input => input.checked).map(input => ociValueLabel(JSON.parse(input.value))).join(', ') || 'None selected';
  });
  const accelerated = $('#oci-accelerated-note'); if (accelerated) { const issue=ociAcceleratedSchemaError(); accelerated.hidden=!ociAcceleratedKeys().length&&$('#oci-launch-mode')?.value!=='ACCELERATEDPV'; accelerated.className=`notice ${issue?'error':'warning'}`; accelerated.textContent=issue||'Accelerated PV requires a supported Acceleron shape and compatible image. Advertised image capabilities must match the regional schema. Validate with an OCI test launch.'; }
  const preparation = $('#oci-preparation-summary'); if (preparation) preparation.textContent = $('#oci-prepare').checked ? 'Enabled' : 'Validate only';
}
function toast(message) { const node = $('#toast'); node.textContent = message; node.hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => node.hidden = true, 5000); }
async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {credentials:'same-origin',...options,headers:{...(options.body && !(options.body instanceof FormData) ? {'Content-Type':'application/json'} : {}),...options.headers}});
  if (response.status === 401) { state.authPending = true; if (!$('#auth-dialog').open) $('#auth-dialog').showModal(); throw new Error('Connect with your server access token to continue.'); }
  if (!response.ok) { let detail; try { detail = (await response.json()).detail; } catch { /* plain response */ } if (Array.isArray(detail)) detail = detail.map(item => `${item.loc?.slice(1).join('.') || 'Request'}: ${item.msg}`).join('; '); throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status}).`); }
  if (response.status === 204) return null;
  return response.json();
}
function setView(view) {
  if (!['images','jobs','artifacts'].includes(view)) view = 'images';
  if (state.view==='jobs' && view!=='jobs') captureActivityView();
  state.view = view;
  $$('.view').forEach(el => el.hidden = el.id !== `view-${view}`);
  $$('.nav-item').forEach(el => {
    el.classList.toggle('active',el.dataset.view===view);
    if(el.dataset.view===view) el.setAttribute('aria-current','page');
    else el.removeAttribute('aria-current');
  });
  document.title = `${{images:'Image studio',jobs:'Activity',artifacts:'Exports'}[view]} · Cloud Image Forge`;
  history.replaceState(null,'',`#${view}`);
  if(view==='jobs') renderActivity();
}
function updateHealth(health) {
  state.health = health;
  const available = Boolean(health.engine?.available);
  $('#engine-label').textContent = available ? 'Image engine connected' : 'Image engine unavailable';
  $('#engine-dot').className = `status-dot${available ? '' : ' unavailable'}`;
  const missing = health.engine?.missing || [];
  notice('#engine-notice', available ? '' : `The web UI is running. Image processing requires the Linux container with QEMU and libguestfs${missing.length ? ` (missing: ${missing.join(', ')})` : ''}. Start the Docker service to import and build images.`);
  $('#upload-limit').textContent = health.limits?.max_upload_gib ? `Maximum upload: ${health.limits.max_upload_gib} GiB. Disk space is also required for working copies and exports.` : 'Disk space is required for the source, working copy, and exported image.';
  $('#connection-button').hidden = health.auth_required === false;
  updateArchitectureHints();
}
function renderEmpty() { renderWizardEmpty(); }
function fileEditor(path, label, description = '', rows = 8) {
  const image = state.images.find(item => item.id === state.selected);
  const content = image?.inspection?.files?.[path] || '';
  return `<label class="field"><span>${esc(label)}</span><span class="code-label">${esc(path)}</span><textarea class="code-editor" data-file="${esc(path)}" rows="${rows}" spellcheck="false" aria-label="${esc(label)}">${esc(content)}</textarea>${description ? `<span class="field-help">${esc(description)}</span>` : ''}</label>`;
}
function partitionTable(partitions, editable = false) {
  if (!partitions?.length) return '<p class="muted">No partition layout was reported by the image inspection.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Device</th><th>Filesystem</th><th>Mount</th><th>Current size</th>${editable ? '<th>New size (MiB)</th>' : ''}</tr></thead><tbody>${partitions.map(partition => `<tr><td><code>${esc(partition.device)}</code></td><td>${esc(partition.filesystem || '—')}</td><td>${esc(partition.mountpoint || '—')}</td><td>${bytes(partition.size)}</td>${editable ? `<td>${/^\/dev\/sda\d+$/.test(partition.device) ? `<input class="table-input" type="number" min="32" step="1" data-partition="${esc(partition.device)}" aria-label="New size of ${esc(partition.device)} in MiB" placeholder="Unchanged">` : '<span class="field-help">Use LVM expansion below</span>'}</td>` : ''}</tr>`).join('')}</tbody></table></div>`;
}
function bootModeLabel(boot) {
  if (!boot) return 'Not inspected';
  return {uefi:'UEFI',bios:'Legacy BIOS',dual:'UEFI + legacy BIOS',unknown:'Unknown'}[boot.mode] || 'Unknown';
}
function bootSummary(inspection, location) {
  const boot = inspection.boot;
  const image = state.images.find(item => item.id === state.selected);
  const refreshing = ['queued','running'].includes(image?.inspection_status);
  const refreshNotice = refreshing ? '<div class="notice info boot-refresh-notice">Inspection is refreshing. Existing findings remain visible; image builds and OCI previews wait for the refreshed result.</div>' : image?.inspection_status === 'failed' ? `<div class="notice warning boot-refresh-notice">Inspection refresh failed: ${esc(image.inspection_error || 'See Activity for details.')} Previous findings were retained.</div>` : '';
  const mode = boot?.mode || 'missing';
  const message = !boot ? 'This image predates boot-mode detection. Refresh its inspection to check the boot files and disk structures.' : mode === 'dual' ? 'Both UEFI and legacy BIOS boot support were detected. Choose the firmware to use for your cloud deployment.' : mode === 'unknown' ? 'The available evidence does not establish a boot mode. Review the findings before selecting cloud firmware.' : `${bootModeLabel(boot)} boot support was detected in the source image.`;
  const rows = (boot?.efi_loaders || []).map(loader => `<tr><td><code>${esc(loader.device)}</code></td><td><code>${esc(loader.path)}</code></td><td>${esc(loader.architecture || 'Unknown')}</td><td>${loader.fallback ? 'Yes' : 'No'}</td></tr>`).join('');
  const evidence = boot?.evidence || [];
  return `<div class="boot-card ${mode === 'unknown' || mode === 'missing' ? 'boot-uncertain' : ''}" data-boot-summary="${esc(location)}"><div class="boot-card-heading"><div class="boot-card-title"><span class="boot-icon">${icon('settings')}</span><div><span class="eyebrow">DETECTED BOOT SUPPORT</span><h3>${esc(bootModeLabel(boot))}</h3></div></div><button type="button" class="button secondary small" data-action="refresh-inspection"${refreshing ? ' disabled' : ''}>${icon('activity')}${refreshing ? 'Refreshing…' : 'Refresh inspection'}</button></div>${refreshNotice}${['missing','dual','unknown'].includes(mode) ? `<p class="boot-description">${esc(message)}</p>` : ''}${boot ? `<p class="boot-scope">Detected offline · boot not verified. ${helpHint("Detection checks installed boot files and disk structures. It does not identify the last VM firmware or prove the image boots.","About boot detection")}</p><details class="boot-evidence"><summary>Detection evidence</summary><div class="details-content"><dl class="detail-list"><div><dt>Partition table</dt><dd>${esc(boot.partition_table || 'Unknown')}</dd></div><div><dt>Supported firmware</dt><dd>${esc((boot.supported_firmware || []).join(', ') || 'Not established')}</dd></div><div><dt>Recommended firmware</dt><dd>${esc(boot.recommended_firmware || (mode === 'dual' ? 'Choose a firmware mode' : 'Not established'))}</dd></div></dl>${evidence.length ? `<ul>${evidence.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p class="field-help">No detailed boot evidence was recorded.</p>'}${boot.bios_evidence?.length ? `<h4>Legacy BIOS evidence</h4><ul>${boot.bios_evidence.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}${rows ? `<h4>EFI boot loaders</h4><div class="table-wrap"><table><thead><tr><th>Device</th><th>Loader</th><th>Architecture</th><th>Fallback path</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}${(boot.warnings || []).map(warning => `<div class="notice warning">${esc(warning)}</div>`).join('')}</div></details>` : '<p class="boot-scope">Source and draft preserved.</p>'}</div>`;
}
function captureEditorDraft() {
  const form = $('#recipe-form'); if (!form) return;
  captureSystemdExplorerState(form.dataset.imageId);
  const fields = [];
  for (const node of $$('input,select,textarea',form)) {
    if (node.closest('.ssh-user-row')) continue;
    let key;
    if (node.dataset.ociDefault) key = ['oci-default',node.dataset.ociDefault];
    else if (node.dataset.ociAllowed) key = ['oci-allowed',node.dataset.ociAllowed,node.value];
    else if (node.dataset.file) { if (node.value === node.defaultValue) continue; key = ['file',node.dataset.file]; }
    else if (node.dataset.partition) key = ['partition',node.dataset.partition];
    else if (node.dataset.rebuildDevice) key = ['rebuild',node.dataset.rebuildDevice];
    else if (node.id) key = ['id',node.id];
    else continue;
    if (!state.ociFirmwareEdited && ['oci-default','oci-allowed'].includes(key[0]) && key[1] === 'Compute.Firmware') continue;
    fields.push({key,value:node.value,checked:node.checked});
  }
  const disclosures = Object.fromEntries($$('details[data-disclosure]',form).map(node => [node.dataset.disclosure,node.open]));
  state.editorDrafts[form.dataset.imageId] = {fields,disclosures,sshUsers:captureSshAccessDraft(),tab:wizardCurrentStep(form.dataset.imageId),catalog:state.ociCatalog,loadedSchema:state.ociLoadedSchema,firmwareEdited:state.ociFirmwareEdited,migrationAutoFirmware:state.migrationAutoFirmware,services:$('#service-rules').innerHTML,serviceValues:$$('.rule-row').map(row => ({name:$('.service-name',row).value,action:$('.service-action',row).value})),shapes:$('#oci-shapes').innerHTML,shapeValues:$$('[data-shape-field]').map(input => input.value)};
}
function restoreEditorDraft(draft) {
  if (!draft) return;
  restoreSshAccessDraft(draft.sshUsers);
  $('#service-rules').innerHTML = draft.services;
  $$('.rule-row').forEach((row,index) => { $('.service-name',row).value = draft.serviceValues[index].name; $('.service-action',row).value = draft.serviceValues[index].action; });
  $('#oci-shapes').innerHTML = draft.shapes;
  $$('[data-shape-field]').forEach((input,index) => input.value = draft.shapeValues[index]);
  const fields = $$('input,select,textarea',$('#recipe-form'));
  for (const item of draft.fields) {
    const [kind,key,value] = item.key;
    const node = fields.find(element => kind === 'id' ? element.id === key : kind === 'file' ? element.dataset.file === key : kind === 'partition' ? element.dataset.partition === key : kind === 'rebuild' ? element.dataset.rebuildDevice === key : kind === 'oci-default' ? element.dataset.ociDefault === key : element.dataset.ociAllowed === key && element.value === value);
    if (!node) continue;
    if (node.type === 'checkbox' || node.type === 'radio') node.checked = item.checked;
    else if (node.tagName !== 'SELECT' || [...node.options].some(option => option.value === item.value)) node.value = item.value;
  }
  if(!draft.fields.some(item=>item.key[0]==='id'&&item.key[1]==='destination-profile'))$('#destination-profile').value='custom';
  if(!draft.fields.some(item=>item.key[0]==='id'&&item.key[1]==='platform-strategy'))$('#platform-strategy').value='reconfigure';
  $('#oci-schema-status').textContent = state.ociLoadedSchema ? 'Current OCI schema loaded' : 'Bundled catalog';
  $$('details[data-disclosure]').forEach(node => { if (node.dataset.disclosure in (draft.disclosures || {})) node.open = draft.disclosures[node.dataset.disclosure]; });
  setTab(draft.tab);
}
function detectedOciFirmware() {
  const boot = state.images.find(image => image.id === state.selected)?.inspection?.boot;
  if (!boot || !['uefi','bios'].includes(boot.mode) || boot.supported_firmware?.length !== 1 || boot.supported_firmware[0] !== boot.recommended_firmware) return null;
  return boot.recommended_firmware;
}
function ociFirmwareHint() {
  const boot = state.images.find(image => image.id === state.selected)?.inspection?.boot;
  if (!boot) return '<p class="oci-firmware-hint">Boot support has not been inspected. Refresh inspection in Overview to establish a firmware recommendation.</p>';
  if (boot.mode === 'dual') return `<p class="oci-firmware-hint">Both boot modes were detected. Choose the preferred and allowed modes for this image.</p><label class="check-field"><input type="checkbox" id="oci-firmware-confirm"${state.ociFirmwareEdited ? ' checked' : ''}><span>Use these firmware choices for this dual-mode image</span></label>`;
  if (boot.mode === 'unknown') return '<p class="oci-firmware-hint">No firmware mode could be inferred. The displayed initial value comes from the OCI catalog; review the detection evidence and compatibility plan.</p>';
  return `<p class="oci-firmware-hint">Detected source support: ${esc(bootModeLabel(boot))}. ${state.ociFirmwareEdited ? 'Your selected firmware choices are preserved.' : 'The initial choice follows the detected firmware when the schema allows it.'}</p>`;
}
async function refreshInspection() {
  if (state.inspectionRefreshing || ['queued','running'].includes(state.images.find(image => image.id === state.selected)?.inspection_status)) return;
  const imageId = state.selected;
  state.inspectionRefreshing = imageId;
  $$('[data-action="refresh-inspection"]').forEach(button => button.disabled = true);
  captureEditorDraft();
  try {
    const result = await api(`/images/${encodeURIComponent(imageId)}/inspect`,{method:'POST'});
    toast('Refreshing source inspection. Your customization draft is preserved.');
    await refresh();
    return result;
  } catch (error) { notice('#global-error',errorText(error)); }
  finally { state.inspectionRefreshing = null; const pending = ['queued','running'].includes(state.images.find(image => image.id === state.selected)?.inspection_status); $$('[data-action="refresh-inspection"]').forEach(button => button.disabled = pending); }
}

function renderImages(force = false) {
  if (!state.images.length) { state.selected = null; state.renderedImage = null; renderEmpty(); return; }
  if (!state.images.some(image => image.id === state.selected)) state.selected = state.images[0].id;
  const image = state.images.find(item => item.id === state.selected);
  const signature = `${image.id}:${image.status}:${image.updated_at || ''}:${image.inspected_at || ''}:${image.inspection_status || ''}:${Boolean(image.inspection)}:${JSON.stringify(image.inspection?.boot || null)}`;
  if (!force && signature === state.renderedImage) { const selector = $('#image-select'); if (selector) selector.innerHTML = state.images.map(item => `<option value="${esc(item.id)}"${item.id === state.selected ? ' selected' : ''}>${esc(item.name)} · ${esc(item.status)}</option>`).join(''); return; }
  captureEditorDraft();
  state.renderedImage = signature;
  const draft = state.editorDrafts[image.id];
  state.ociCatalog = draft?.catalog || state.ociBaseCatalog; state.ociLoadedSchema = draft?.loadedSchema || null; state.ociFirmwareEdited = draft?.firmwareEdited || false; state.migrationAutoFirmware = draft?.migrationAutoFirmware || null;
  const inspection = image.inspection || {}, os = inspection.os || {}, partitions = inspection.partitions || [];
  const startupFiles = Object.keys(inspection.files || {}).filter(path => /^\/etc\/(cron\.d\/[^/]+|systemd\/system\/[^/]+\.service)$/.test(path));
  const banner = `<div class="image-banner"><span class="image-banner-icon">${icon('image')}</span><div><h2>${esc(image.name)}</h2><p>${esc(os.name || os.distro || 'Linux disk image')}${os.arch ? ` · ${esc(architectureName(os.arch))}` : ''} · ${esc((inspection.format || 'inspecting').toUpperCase())}</p></div>${badge(image.status)}</div>`;
  if (image.status !== 'ready') { renderWizardEmpty(image); return; }
  $('#image-workspace').innerHTML = banner + `<div id="architecture-worker-notice" class="notice warning compact-notice" hidden></div><form id="recipe-form" data-image-id="${esc(image.id)}" novalidate><div class="editor-tabs" role="tablist" aria-label="Image customization">${[['overview','Overview'],['storage','Storage'],['startup','Startup & cron'],['access','Access'],['mounts','Mounts'],['boot','Boot & kernel'],['oci','OCI compatibility'],['export','Export']].map(([key,label],i) => `<button type="button" role="tab" aria-selected="${!i}" aria-controls="panel-${key}" id="tab-${key}" tabindex="${i ? -1 : 0}" class="editor-tab${i ? '' : ' selected'}" data-tab="${key}">${label}</button>`).join('')}</div><div class="editor-body">
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-overview" id="panel-overview">${bootSummary(inspection,'overview')}<div class="metric-grid"><div class="metric"><span class="metric-label">Disk capacity ${helpHint('Virtual disk capacity seen by the guest, independent of the compressed file length.','Disk capacity')}</span><strong class="metric-value">${bytes(inspection.virtual_size)}</strong></div><div class="metric"><span class="metric-label">File size ${helpHint('Source file length: the amount transferred when downloading the imported file.','Source file size')}</span><strong class="metric-value">${bytes(inspection.actual_size)}</strong></div><div class="metric"><span class="metric-label">Filesystems / devices</span><strong class="metric-value">${partitions.length}</strong></div><div class="metric"><span class="metric-label">Format</span><strong class="metric-value">${esc((inspection.format || '—').toUpperCase())}</strong></div></div><details class="editor-disclosure" data-disclosure="source-layout"><summary>Disk layout <span class="disclosure-meta">${partitions.length} devices</span></summary><div class="details-content">${partitionTable(partitions)}</div></details><details class="editor-disclosure" data-disclosure="source-guest"><summary>Guest details <span class="disclosure-meta">${esc(architectureName(os.arch))}</span></summary><div class="details-content"><dl class="detail-list"><div><dt>Operating system</dt><dd>${esc(os.name || os.distro || 'Unknown')}</dd></div><div><dt>Detected architecture ${helpHint('The exported image keeps this CPU architecture. Choose a destination shape with the same instruction set.','Detected architecture')}</dt><dd>${esc(architectureName(os.arch))}</dd></div><div><dt>Root device</dt><dd><code>${esc(os.root || 'Unknown')}</code></dd></div></dl></div></details>${(inspection.warnings || []).map(warning => `<div class="notice warning compact-notice">${esc(warning)}</div>`).join('')}</section>
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-storage" id="panel-storage" hidden><h3>Shape the disk</h3><p class="panel-intro">Leave a field blank to preserve its current size. Partition and filesystem changes are validated before the working disk is modified.</p><div class="form-grid"><label class="field">Target disk capacity (GiB)<input id="disk-size" type="number" min="0.001" step="any" placeholder="Current: ${(Number(inspection.virtual_size || 0)/1073741824).toFixed(2)} GiB"><span class="field-help">GiB uses powers of 1024. The original capacity is kept when blank.</span></label><label class="field">Expand partition to fill available space<select id="expand-partition"><option value="">Keep partition sizes</option>${partitions.filter(p => /^\/dev\/(sd[a-z]|vd[a-z]|hd[a-z]|nvme\d+n\d+p)\d+$/.test(p.device)).map(p => `<option value="${esc(p.device)}">${esc(p.device)}${p.mountpoint ? ` · ${esc(p.mountpoint)}` : ''}</option>`).join('')}</select><span class="field-help">Choose a partition, or set explicit sizes below.</span></label></div>${partitionTable(partitions,true)}<label class="field">Expand an LVM logical volume <span class="optional">optional</span><input id="expand-lv" list="logical-volumes" placeholder="/dev/volume-group/root"><datalist id="logical-volumes">${partitions.filter(p => p.device.split('/').length > 3).map(p => `<option value="${esc(p.device)}">`).join('')}</datalist><span class="field-help">Use with partition growth to extend a logical volume into the available space.</span></label><div class="notice warning">Direct resize: ext2/3/4 may shrink offline. Use filesystem rebuild above to reduce XFS or LVM. Keep enough space for the filesystem and set the target disk capacity separately.</div></section>
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-startup" id="panel-startup" hidden>${renderSystemdExplorer(inspection)}<details class="editor-disclosure" id="service-changes" data-disclosure="startup-service-actions"><summary>Service changes <span class="disclosure-meta" data-service-change-count>None</span></summary><div class="details-content"><div id="service-rules"></div><datalist id="known-services">${(inspection.services || []).map(name => `<option value="${esc(name)}">`).join('')}</datalist><button type="button" class="button secondary small" data-action="add-service">${icon('plus')}Add service action</button>${helpHint('Enable, disable, mask or unmask services in the exported image. These actions do not change the source tree.','Service changes')}</div></details><details class="editor-disclosure" data-disclosure="startup-crontab"><summary>System crontab <span class="disclosure-meta">/etc/crontab</span></summary><div class="details-content">${fileEditor('/etc/crontab','Scheduled jobs','System crontab lines must include a username after the schedule.')}</div></details>${startupFiles.length ? `<details class="editor-disclosure" data-disclosure="startup-existing"><summary>Existing units & cron files <span class="disclosure-meta">${startupFiles.length} files</span></summary><div class="details-content">${startupFiles.map(path => `<details class="startup-file" data-disclosure="${esc(path)}"><summary class="code-label">${esc(path)}</summary><div class="details-content">${fileEditor(path,'File contents','Only modified contents are applied to the new image.',9)}</div></details>`).join('')}</div></details>` : ''}<details class="editor-disclosure" data-disclosure="startup-custom"><summary>Add a unit or cron file <span class="disclosure-meta">Optional</span></summary><div class="details-content"><label class="field">Guest file path<input id="custom-file-path" placeholder="/etc/systemd/system/my-app.service"><span class="field-help">A .service file under /etc/systemd/system/ or a file under /etc/cron.d/. Add an enable action above to start a new service at boot.</span></label><label class="field">File contents<textarea id="custom-file-content" class="code-editor" rows="9" spellcheck="false" placeholder="[Unit]&#10;Description=My application"></textarea></label></div></details></section>
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-access" id="panel-access" hidden>${renderSshAccess(inspection)}</section>
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-mounts" id="panel-mounts" hidden>${renderMountPolicy()}<details class="editor-disclosure" data-disclosure="mount-fstab"><summary>Edit fstab <span class="disclosure-meta">Advanced</span></summary><div class="details-content">${fileEditor('/etc/fstab','Filesystem table','Manual edits are applied before the mount policy. Preserve root, boot and EFI mounts; invalid entries can prevent boot.',13)}</div></details><details class="editor-disclosure" data-disclosure="mount-identifiers"><summary>Filesystem identifiers <span class="disclosure-meta">UUID reference</span></summary><div class="details-content"><div class="table-wrap"><table><thead><tr><th>Device</th><th>Mount</th><th>UUID</th></tr></thead><tbody>${partitions.map(p => `<tr><td><code>${esc(p.device)}</code></td><td>${esc(p.mountpoint || '—')}</td><td><code>${esc(p.uuid || '—')}</code></td></tr>`).join('')}</tbody></table></div></div></details></section>
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-boot" id="panel-boot" hidden>${bootSummary(inspection,'boot')}${renderBootMigration()}<div class="form-grid"><label class="field">Default kernel<select id="kernel-default"><option value="">Keep current default</option>${(inspection.kernels || []).map(kernel => `<option value="${esc(kernel)}">${esc(kernel)}</option>`).join('')}</select><span class="field-help">Selecting a default requires grubby in the guest.</span></label><label class="field">Kernel arguments<input id="kernel-args" placeholder="Unchanged"><span class="field-help">Sets GRUB_CMDLINE_LINUX and updates installed kernels with grubby. Existing unrelated entry arguments are retained; leave blank for no change.</span></label></div><details class="editor-disclosure" data-disclosure="boot-grub"><summary>GRUB configuration <span class="disclosure-meta">Bootloader defaults</span></summary><div class="details-content">${fileEditor('/etc/default/grub','GRUB defaults','Enable regeneration below to apply changes.',8)}<label class="check-field"><input type="checkbox" id="regenerate-grub"><span>Regenerate GRUB configuration<small>Apply /etc/default/grub changes using the guest’s supported GRUB tooling.</small></span></label></div></details><details class="editor-disclosure" data-disclosure="boot-packages"><summary>Packages & repository access <span class="disclosure-meta">Optional</span></summary><div class="details-content"><div class="form-grid"><label class="field">Install packages<input id="packages-install" placeholder="kernel cloud-init"><span class="field-help">Space- or comma-separated guest package names.</span></label><label class="field">Remove packages<input id="packages-remove" placeholder="unused-kernel-package"><span class="field-help">Keep a bootable kernel and the storage drivers required by your cloud.</span></label></div><label class="check-field"><input type="checkbox" id="allow-network"><span>Allow networking during customization<small>Required for downloads from guest repositories. Shared with migration and compatibility settings.</small></span></label></div></details><details class="editor-disclosure" data-disclosure="boot-modules"><summary>Kernel modules & initramfs <span class="disclosure-meta">Drivers and options</span></summary><div class="details-content"><div class="form-grid">${fileEditor('/etc/modules-load.d/cloud-image-forge.conf','Modules to load','One module name per line.',6)}${fileEditor('/etc/modprobe.d/cloud-image-forge.conf','Module options and blacklists','Use modprobe.d options or blacklist directives.',6)}</div><label class="check-field"><input type="checkbox" id="rebuild-initramfs"><span>Rebuild initramfs<small>Refresh the guest’s initial RAM filesystem after kernel or driver changes.</small></span></label></div></details></section>
${renderOciPanel()}
  <section class="editor-panel" role="tabpanel" aria-labelledby="tab-export" id="panel-export" hidden><div class="export-options">${Object.entries(profiles).map(([key,p],i) => `<div class="export-option"><input type="radio" name="target" id="target-${key}" value="${key}"${i ? '' : ' checked'}><label for="target-${key}">${esc(p.label)}<small>${{oci:'QCOW2 · zlib',aws:'RAW disk',azure:'Fixed VHD',gcp:'tar.gz',generic:'Choose format'}[key]}</small></label></div>`).join('')}</div><div class="export-summary" id="export-summary"></div><label class="field" id="generic-format-wrap" hidden>Output format<select id="output-format"><option value="qcow2">QCOW2</option><option value="raw">RAW</option><option value="vhd">Fixed VHD</option></select></label><details class="editor-disclosure" data-disclosure="export-options"><summary>Output options <span class="disclosure-meta">Space and compression</span></summary><div class="details-content"><label class="check-field"><input type="checkbox" id="sparsify" checked><span>Reclaim unused filesystem space<small>Run offline sparsification on the working image before export.</small></span></label><label class="check-field"><input type="checkbox" id="compress" checked><span>Compress QCOW2 output with zlib<small>Reduces the file footprint without shrinking the virtual disk.</small></span></label></div></details><p class="validation-note">A test launch is required to confirm provider compatibility.</p></section>
  </div><div class="build-bar"><div><strong id="build-summary">OCI export · Original source preserved</strong><p>Only your chosen changes are applied. Follow progress in Activity.</p></div><button type="submit" id="build-button" class="button primary">${icon('stack')}Build image${icon('arrow')}</button></div><div id="build-error" class="notice error compact-notice" role="alert" hidden></div></form>`;
  $('#recipe-form').addEventListener('submit', buildImage);
  renderOciCapabilities();
  prepareStudioEditor();
  restoreEditorDraft(draft);
  updateArchitectureHints();
  $('#migration-controls').hidden = !$('#boot-migration-enabled').checked;
  updateExport();
  const refreshing = ['queued','running'].includes(image.inspection_status);
  $('#build-button').disabled = refreshing;
  $('#oci-plan-button').disabled = refreshing;
  $('#migration-plan-button').disabled = refreshing;
  wizardReady();
  syncStudioEditor();
  mountSystemdExplorer();
}
function setTab(tab) { wizardShowStep(tab,{focus:false}); }
function updateExport() { const target = $('input[name="target"]:checked')?.value || 'oci', profile = profiles[target]; $('#export-summary').innerHTML = `<strong>${esc(profile.title)}</strong>${helpHint(profile.description,'Output format details')}`; $('#generic-format-wrap').hidden = target !== 'generic'; const format = target === 'generic' ? $('#output-format').value : profile.format; $('#compress').disabled = format !== 'qcow2'; $('#build-summary').textContent = `${profile.label} · ${format.toUpperCase()}`; if ($('#oci-target-notice')) $('#oci-target-notice').hidden = target === 'oci'; if ($('.wizard-stepper')) wizardUpdate(); }
function addService() { const row = document.createElement('div'); row.className = 'rule-row'; row.innerHTML = `<input class="service-name" list="known-services" placeholder="sshd.service" aria-label="Systemd service name"><select class="service-action" aria-label="Service action"><option value="enable">Enable</option><option value="disable">Disable</option><option value="mask">Mask</option><option value="unmask">Unmask</option></select><button type="button" class="icon-button" data-action="remove-service" aria-label="Remove service action">${icon('close')}</button>`; $('#service-rules').append(row); $('#service-changes').open=true; updateDisclosureSummaries(); revealEditorField($('.service-name',row)); }
function getRecipe() {
  const source = state.images.find(image => image.id === state.selected);
  const storage_rebuild = getStorageRebuildConfig(), platform_migration = getPlatformMigrationConfig();
  const originalFiles = source.inspection?.files || {};
  const files = $$('[data-file]').filter(el => el.value !== (originalFiles[el.dataset.file] || '')).map(el => ({path:el.dataset.file,content:el.value}));
  const customPath = $('#custom-file-path').value.trim(), customContent = $('#custom-file-content').value;
  if (customPath || customContent) { if (!customPath || !customContent) throw new Error('Enter both a guest file path and content for the custom startup file.'); const existing = files.findIndex(file => file.path === customPath); if (existing >= 0) throw new Error('This path is already edited above. Use a different path for the new startup file.'); if (customContent !== (originalFiles[customPath] || '')) files.push({path:customPath,content:customContent}); }
  const services = $$('.rule-row').map(row => ({name:$('.service-name',row).value.trim(),action:$('.service-action',row).value})).filter(service => service.name);
  const partition_changes = $$('[data-partition]').filter(el => el.value.trim()).map(el => ({device:el.dataset.partition,size_mib:Number(el.value)}));
  const expand_partition = $('#expand-partition').value || null;
  if (!storage_rebuild && partition_changes.some(p => p.device === expand_partition)) throw new Error('Choose either an explicit size or automatic expansion for a partition.');
  const target = $('input[name="target"]:checked').value;
  const splitPackages = selector => $(selector).value.trim().split(/[\s,]+/).filter(Boolean);
  const packages_install = splitPackages('#packages-install');
  if (packages_install.length && !$('#allow-network').checked) throw new Error('Enable networking in Boot & kernel to install packages from guest repositories.');
  if (files.some(file => file.path === '/etc/default/grub') && !$('#regenerate-grub').checked) throw new Error('Enable GRUB regeneration in Boot & kernel to apply your GRUB defaults changes.');
  const boot_migration = getBootMigrationConfig();
  const ssh_access = getSshAccessConfig();
  return {mount_policy:getMountPolicy(),...(ssh_access ? {ssh_access} : {}),...(storage_rebuild ? {storage_rebuild} : {}),...(platform_migration ? {platform_migration} : {}),...(boot_migration ? {boot_migration} : {}),...(target === 'oci' && $('#oci-enabled')?.checked ? {oci:getOciConfig()} : {}),target,output_format:target === 'generic' ? $('#output-format').value : profiles[target].format,disk_size_gib:getDiskSizeGiB(),partition_changes:storage_rebuild?[]:partition_changes,expand_partition:storage_rebuild?null:expand_partition,expand_lv:storage_rebuild?null:($('#expand-lv').value.trim() || null),files,services,packages_install,packages_remove:splitPackages('#packages-remove'),kernel_default:$('#kernel-default').value || null,kernel_args:$('#kernel-args').value.trim() || null,rebuild_initramfs:$('#rebuild-initramfs').checked,regenerate_grub:$('#regenerate-grub').checked,sparsify:$('#sparsify').checked,compress:!$('#compress').disabled && $('#compress').checked,allow_network:$('#allow-network').checked};
}
async function buildImage(event) {
  event.preventDefault();
  if (state.buildSubmitting) return;
  if (wizardBuildPending()) { wizardShowStep('result',{focus:true}); return; }
  const imageId = state.selected;
  state.buildSubmitting = true;
  notice('#build-error','');
  try {
    if (!await wizardBeforeBuild()) return;
    if (state.selected !== imageId) throw new Error('The selected source changed. Review this image before building.');
    wizardSetBusy(true);
    const recipe = getRecipe(), revision = state.editorRevision, recipeSignature = JSON.stringify(recipe);
    const unchanged = () => { if (state.selected !== imageId || state.editorRevision !== revision || JSON.stringify(getRecipe()) !== recipeSignature) throw new Error('The source or customization changed. Review the current choices before building.'); };
    if (recipe.storage_rebuild) { await previewStorage(recipe.storage_rebuild,true,recipe.disk_size_gib,recipe.mount_policy); unchanged(); }
    if (recipe.boot_migration) { await previewBootMigration(recipe.boot_migration,true,recipe.allow_network); unchanged(); }
    if (recipe.platform_migration) { await previewPlatform(recipe.platform_migration,true,recipe); unchanged(); }
    if (recipe.oci) { await previewOci(recipe.oci,true,recipe.boot_migration || null,recipe.allow_network,recipe.platform_migration || null,recipe.mount_policy); unchanged(); }
    unchanged();
    const job = await api(`/images/${encodeURIComponent(imageId)}/build`,{method:'POST',body:JSON.stringify(recipe)});
    wizardBuildQueued(imageId,job.job_id);
    toast('Image build queued. Follow its progress in the final step.');
    await refresh();
    if (state.selected === imageId) setView('images');
  } catch(error) { notice('#build-error',errorText(error)); }
  finally { state.buildSubmitting = false; wizardSetBusy(false); }
}
function renderArtifacts() { renderExports(); }
function renderJobs() { renderActivity(); }
function openJob(id) { return openActivityJob(id); }
async function refresh() {
  if (state.polling) return;
  state.polling = true;
  try { const [images,jobs,artifacts] = await Promise.all([api('/images'),api('/jobs'),api('/artifacts')]); state.images = images; state.jobs = jobs; state.artifacts = artifacts; $('#image-count').textContent = images.length; $('#artifact-count').textContent = artifacts.length; const active = jobs.filter(job => ['running','queued'].includes(job.status)).length; $('#job-count').textContent = active || jobs.length; renderImages(); renderArtifacts(); renderJobs(); wizardUpdate(); notice('#global-error',''); state.authPending = false; }
  catch(error) { notice('#global-error',errorText(error)); }
  finally { state.polling = false; }
}
function showImport() { notice('#import-error',''); compactStudioHelp($('#import-dialog')); $('#import-dialog').showModal(); }
function setImportMode(mode) { state.importMode = mode; $$('[data-import-mode]').forEach(button => button.classList.toggle('selected',button.dataset.importMode === mode)); $('#import-local').hidden = mode !== 'file'; $('#import-remote').hidden = mode !== 'url'; $('#import-url').required = mode === 'url'; }
function selectFile(file) { state.selectedFile = file || null; $('#file-label').textContent = file ? `${file.name} · ${bytes(file.size)}` : 'Click to browse or drop an image'; }
function uploadFile(file) {
  return new Promise((resolve,reject) => {
    const xhr = new XMLHttpRequest(); state.uploadXhr = xhr; xhr.open('POST','/api/images/upload'); xhr.responseType = 'json'; xhr.withCredentials = true;
    xhr.upload.addEventListener('progress',event => { if (event.lengthComputable) { const progress = Math.round(event.loaded / event.total * 100); $('#upload-progress').value = progress; $('#upload-percent').textContent = `${progress}%`; } });
    xhr.addEventListener('load',() => { if(xhr.status >= 200 && xhr.status < 300) resolve(xhr.response); else { if(xhr.status === 401 && !$('#auth-dialog').open) $('#auth-dialog').showModal(); const detail = xhr.response?.detail; reject(new Error(typeof detail === 'string' ? detail : `Upload failed (${xhr.status}).`)); } });
    xhr.addEventListener('abort',() => reject(new Error('Upload cancelled.')));
    xhr.addEventListener('error',() => reject(new Error('The upload connection was interrupted. Check your connection and try again.')));
    const data = new FormData(); data.append('file',file); xhr.send(data);
  });
}
$('#import-form').addEventListener('submit',async event => {
  event.preventDefault(); if(state.busy) return; state.uploadCancelled = false; notice('#import-error','');
  try { state.busy = true; $('#import-submit').disabled = true; let result;
    if (state.importMode === 'file') { if(!state.selectedFile) throw new Error('Choose a local disk image to import.'); const limit = Number(state.health?.limits?.max_upload_gib); if(limit && state.selectedFile.size > limit * 1073741824) throw new Error(`This file exceeds the ${limit} GiB upload limit.`); $('#upload-progress-wrap').hidden = false; $('#upload-progress').value = 0; $('#upload-percent').textContent = '0%'; result = await uploadFile(state.selectedFile); }
    else { const url = $('#import-url').value.trim(); if(!url) throw new Error('Enter an S3 URI or HTTPS URL.'); result = await api('/images/import',{method:'POST',body:JSON.stringify({url,endpoint_url:$('#import-endpoint').value.trim() || null,region:$('#import-region').value.trim() || null})}); }
    captureEditorDraft(); state.selected = result.image_id; state.editorRevision++; state.renderedImage = null; wizardImported(result.image_id,result.job_id); $('#import-dialog').close(); toast('Source imported. The engine will inspect the disk now.'); await refresh(); setView('images');
  } catch(error) { if(!state.uploadCancelled) notice('#import-error',errorText(error)); }
  finally { state.uploadXhr = null; state.busy = false; $('#import-submit').disabled = false; $('#upload-progress-wrap').hidden = true; }
});
$('#auth-form').addEventListener('submit',async event => { event.preventDefault(); notice('#auth-error',''); const button = $('button[type="submit"]',event.target); button.disabled = true; try { await api('/session',{method:'POST',body:JSON.stringify({token:$('#auth-token').value})}); $('#auth-token').value = ''; $('#auth-dialog').close(); state.authPending = false; toast('Connected to your workspace.'); updateHealth(await api('/health')); try { await loadOciCatalog(); } catch(error) { state.ociCatalogError = errorText(error); } await loadDestinationCatalog(); await refresh(); } catch(error) { notice('#auth-error',errorText(error)); } finally { button.disabled = false; } });
$('#s3-form').addEventListener('submit',async event => {
  event.preventDefault(); notice('#s3-error','');
  const button = $('button[type="submit"]',event.target), artifactId = state.s3Artifact, wizardImage = state.s3WizardImage;
  button.disabled = true;
  try {
    const result = await api(`/artifacts/${encodeURIComponent(artifactId)}/upload`,{method:'POST',body:JSON.stringify({url:$('#s3-url').value.trim(),endpoint_url:$('#s3-endpoint').value.trim() || null,region:$('#s3-region').value.trim() || null})});
    $('#s3-dialog').close(); toast('S3 upload queued.');
    if (wizardImage) wizardUploadQueued(wizardImage,result.job_id);
    await refresh();
    if (wizardImage) { if (state.selected === wizardImage) setView('images'); }
    else { setView('jobs'); openJob(result.job_id); }
  } catch(error) { notice('#s3-error',errorText(error)); }
  finally { button.disabled = false; }
});
$('#import-dialog').addEventListener('cancel',() => { if(state.uploadXhr) { state.uploadCancelled = true; state.uploadXhr.abort(); } });
$('#image-file').addEventListener('change',event => selectFile(event.target.files[0]));
const dropZone = $('#drop-zone');
['dragenter','dragover'].forEach(type => dropZone.addEventListener(type,event => { event.preventDefault(); dropZone.classList.add('dragging'); }));
['dragleave','drop'].forEach(type => dropZone.addEventListener(type,event => { event.preventDefault(); dropZone.classList.remove('dragging'); }));
dropZone.addEventListener('drop',event => { if(event.dataTransfer.files.length) selectFile(event.dataTransfer.files[0]); });
$('#connection-button').addEventListener('click',() => { notice('#auth-error',''); $('#auth-dialog').showModal(); });
document.addEventListener('click',event => {
  const button = event.target.closest('button,a'); if(!button) return;
  if(button.dataset.view) { event.preventDefault(); setView(button.dataset.view); }
  if(button.dataset.close) { if(button.dataset.close === 'import-dialog' && state.uploadXhr) { state.uploadCancelled = true; state.uploadXhr.abort(); } $(`#${button.dataset.close}`).close(); }
  if(button.dataset.importMode) setImportMode(button.dataset.importMode);
  if(button.dataset.tab) wizardGo(button.dataset.tab);
  if (['add-service','remove-service','oci-add-shape','oci-remove-shape','oci-use-target'].includes(button.dataset.action)) state.editorRevision++;
  if(button.dataset.s3) { state.s3WizardImage = button.closest('#panel-result') ? state.selected : null; state.s3Artifact = button.dataset.s3; const artifact = state.artifacts.find(item => item.id === state.s3Artifact); $('#s3-artifact-name').textContent = artifact?.name || artifact?.filename || 'Image export'; notice('#s3-error',''); compactStudioHelp($('#s3-dialog')); $('#s3-dialog').showModal(); }
  if(button.dataset.action === 'open-import') showImport();
  if(button.dataset.action === 'refresh') refresh();
  if(button.dataset.action === 'refresh-inspection') refreshInspection();
  if(button.dataset.action === 'add-service') addService();
  if(button.dataset.action === 'remove-service') { button.closest('.rule-row').remove(); updateDisclosureSummaries(); }
  if(button.dataset.action === 'migration-preview') previewBootMigration();
  if(button.dataset.action === 'oci-preview') previewOci();
  if(button.dataset.action === 'oci-add-shape') addOciShape();
  if(button.dataset.action === 'oci-remove-shape') { button.closest('.oci-shape-row').remove(); markOciChanged(); }
  if(button.dataset.action === 'oci-load-schema') changeOciSchema();
  if(button.dataset.action === 'oci-reset-schema' || button.dataset.action === 'oci-refresh-catalog') changeOciSchema(true);
  if(button.dataset.action === 'oci-use-target') { $('#target-oci').checked = true; updateExport(); }
});
document.addEventListener('change',event => { if(event.target.id === 'image-select') { state.selected = event.target.value; state.editorRevision++; renderImages(true); } if(event.target.name === 'target' || event.target.id === 'output-format') updateExport(); });
document.addEventListener('input', event => {
  if (event.target.closest('#recipe-form')) state.editorRevision++;
  if (event.target.closest('#migration-controls')) invalidateMigrationPlan();
  if (event.target.closest('#panel-oci') && event.target.id !== 'oci-enabled') markOciChanged();
});
document.addEventListener('change', event => {
  if (event.target.closest('#recipe-form')) state.editorRevision++;
  const input = event.target;
  if (input.id === 'oci-enabled') updateOciVisibility();
  if (input.id === 'boot-migration-enabled') toggleBootMigration();
  if (['oci-allow-network','allow-network','migration-allow-network','platform-allow-network'].includes(input.id)) {
    for (const id of ['allow-network','oci-allow-network','migration-allow-network','platform-allow-network']) if ($(`#${id}`)) $(`#${id}`).checked = input.checked;
    if ($('#oci-enabled')?.checked) markOciChanged();
    if ($('#boot-migration-enabled')?.checked) invalidateMigrationPlan();
  }
  if (input.dataset.ociDefault === 'Compute.Firmware' || input.dataset.ociAllowed === 'Compute.Firmware' || input.id === 'oci-firmware-confirm') { state.migrationAutoFirmware = null; state.ociFirmwareEdited = input.id === 'oci-firmware-confirm' ? input.checked : true; if ($('#oci-firmware-confirm')) $('#oci-firmware-confirm').checked = state.ociFirmwareEdited; }
  if (input.dataset.ociDefault) { const allowed = $$('[data-oci-allowed]').find(node => node.dataset.ociAllowed === input.dataset.ociDefault && node.value === input.value); if (allowed) allowed.checked = true; }
  if (input.closest('#panel-oci') && input.id !== 'oci-enabled') markOciChanged();
});
document.addEventListener('invalid',event => { if (!event.target.closest('#recipe-form')) revealEditorField(event.target); },true);
document.addEventListener('keydown',event => { if(event.target.matches?.('.editor-tab') && ['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) { event.preventDefault(); const tabs = $$('.editor-tab'), current = tabs.indexOf(event.target); const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length-1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; setTab(tabs[index].dataset.tab); tabs[index].focus(); } });
window.addEventListener('hashchange',() => setView(location.hash.slice(1)));
function renderBootMigration() {
  return `<details class="editor-disclosure boot-migration" id="boot-migration-section" data-disclosure="boot-migration"><summary id="boot-migration-title">BIOS → UEFI conversion <span class="disclosure-meta">${sourceArchitecture()==='aarch64'?'Unavailable for ARM64':'Optional'}</span></summary><div class="details-content">
    <label class="check-field migration-enable"><input type="checkbox" id="boot-migration-enabled"><span>Convert this image to UEFI during the build<small>${sourceArchitecture()==='aarch64'?'ARM64 requires an existing ARM64 UEFI bootloader. BIOS conversion is unavailable.':'Changes the working copy only. Selecting OCI firmware alone does not convert boot files.'}</small></span></label>
    <div id="migration-architecture-error" class="notice error" role="alert" hidden></div>
    <div id="migration-controls" hidden><div class="form-grid"><label class="field">EFI System Partition size (MiB)<input type="number" id="migration-esp-size" min="512" max="2048" step="1" value="512"><span class="field-help">The plan shows whether an ESP can be created or reused and how much the virtual disk must grow.</span></label><div class="migration-options"><label class="check-field"><input type="checkbox" id="migration-install-packages"><span>Install or refresh bootloader packages<small>Allow required installation or reinstallation from the guest repositories.</small></span></label><label class="check-field"><input type="checkbox" id="migration-allow-network"><span>Allow networking during customization<small>Required for package installation; shared with the other customization settings.</small></span></label></div></div>
      <div class="notice info migration-firmware-note" id="migration-firmware-note">OCI firmware is set to UEFI_64. You can change it in OCI compatibility.</div>
      <div class="migration-plan-heading"><div><h4>Migration plan</h4><p class="field-help">Preview uses the source layout. Storage changes can alter the final ESP location and output size; the build checks the updated layout again.</p></div><button type="button" class="button primary" id="migration-plan-button" data-action="migration-preview">${icon('check')}Preview migration</button></div>
      <div id="migration-error" class="notice error" role="alert" hidden></div><div id="migration-plan" class="oci-plan" aria-live="polite"><p class="muted">Check the migration plan before building.</p></div>
      <p class="validation-note migration-validation">A firmware or cloud boot test is required after export.</p>
    </div></div></details>`;
}
function getBootMigrationConfig() {
  if (!$('#boot-migration-enabled')?.checked) return null;
  if(sourceArchitecture()==='aarch64')throw editorError('ARM64 requires existing ARM64 UEFI. Clear BIOS-to-UEFI conversion; CPU architecture is preserved.','#boot-migration-enabled');
  const esp_size_mib = Number($('#migration-esp-size').value);
  if (!Number.isInteger(esp_size_mib) || esp_size_mib < 512 || esp_size_mib > 2048) throw editorError('EFI System Partition size must be a whole number from 512 to 2048 MiB.','#migration-esp-size');
  const install_packages = $('#migration-install-packages').checked;
  if (install_packages && !$('#allow-network').checked) throw editorError('Enable networking during customization to install or refresh UEFI bootloader packages.','#migration-allow-network');
  return {enabled:true,esp_size_mib,install_packages};
}
function invalidateMigrationPlan() {
  if ($('#migration-plan')) $('#migration-plan').innerHTML = '<p class="muted">Settings changed. Check the migration plan again.</p>';
  if ($('#oci-enabled')?.checked && $('#oci-plan')) $('#oci-plan').innerHTML = '<p class="muted">Boot migration settings changed. Preview the OCI compatibility plan again.</p>';
}
function applyMigrationFirmware() {
  const firmware = $$('[data-oci-default]').find(node => node.dataset.ociDefault === 'Compute.Firmware');
  if (!firmware) return;
  const uefi = JSON.stringify('UEFI_64');
  if (![...firmware.options].some(option => option.value === uefi)) {
    $('#migration-firmware-note').textContent = 'The current OCI schema does not offer UEFI_64. Load a schema with UEFI support before creating an OCI configuration for this migration.';
    return;
  }
  state.migrationAutoFirmware = {setting:readOciCapabilities(false)['Compute.Firmware'],wasEdited:state.ociFirmwareEdited};
  firmware.value = uefi;
  $$('[data-oci-allowed]').filter(node => node.dataset.ociAllowed === 'Compute.Firmware').forEach(node => node.checked = node.value === uefi);
  state.ociFirmwareEdited = true;
  if ($('#oci-firmware-confirm')) $('#oci-firmware-confirm').checked = true;
  $('#migration-firmware-note').textContent = 'OCI firmware is set to UEFI_64. You can change it in OCI compatibility.';
}
function toggleBootMigration() {
  const enabled = $('#boot-migration-enabled').checked;
  $('#migration-controls').hidden = !enabled;
  if (enabled&&sourceArchitecture()!=='aarch64') applyMigrationFirmware();
  else if (state.migrationAutoFirmware) {
    const prior = state.migrationAutoFirmware;
    const firmware = $$('[data-oci-default]').find(node => node.dataset.ociDefault === 'Compute.Firmware');
    if (firmware && prior.setting) {
      const value = JSON.stringify(prior.setting.default_value);
      if ([...firmware.options].some(option => option.value === value)) firmware.value = value;
      $$('[data-oci-allowed]').filter(node => node.dataset.ociAllowed === 'Compute.Firmware').forEach(node => node.checked = (prior.setting.values || [prior.setting.default_value]).some(item => JSON.stringify(item) === node.value));
      state.ociFirmwareEdited = prior.wasEdited;
      if ($('#oci-firmware-confirm')) $('#oci-firmware-confirm').checked = state.ociFirmwareEdited;
    }
    state.migrationAutoFirmware = null;
  }
  invalidateMigrationPlan();
  updateArchitectureHints();
}

function renderMigrationPlan(plan) {
  const source = state.images.find(image => image.id === state.selected)?.inspection || {};
  const layout = {...(plan.layout?.action === 'already_uefi' ? {disk_size_before:source.virtual_size,disk_size_after:source.virtual_size,partition_table:source.boot?.partition_table} : {}),...(plan.layout || {})};
  const ready = Boolean(plan.ready_to_migrate) && !(plan.blockers || []).length;
  const action = {append:'Create a new EFI System Partition',reuse:'Reuse the existing EFI System Partition',already_uefi:'UEFI is already present',blocked:'Migration is unavailable'}[layout.action] || 'Review the migration layout';
  const lines = values => (values || []).map(value => `<li>${esc(typeof value === 'string' ? value : JSON.stringify(value))}</li>`).join('');
  const packages = Array.isArray(plan.requires_packages) ? plan.requires_packages : [];
  const details = [['Partition table',layout.partition_table || 'Not established'],['EFI System Partition',layout.esp_device || (layout.action === 'already_uefi' ? 'No ESP changes required' : 'Determined during migration')],['ESP size',Number.isFinite(layout.esp_size_mib) ? `${layout.esp_size_mib} MiB` : layout.action === 'already_uefi' ? 'Unchanged' : 'Not established'],['Preserve BIOS boot structures',typeof layout.preserve_bios === 'boolean' ? layout.preserve_bios ? 'Yes' : 'No' : 'Not established']];
  if (layout.start_sector !== null && layout.start_sector !== undefined) details.push(['ESP start sector',String(layout.start_sector)]);
  if (layout.end_sector !== null && layout.end_sector !== undefined) details.push(['ESP end sector',String(layout.end_sector)]);
  $('#migration-plan').innerHTML = `<div class="oci-plan-status ${ready ? 'clear' : 'blocked'}">${icon(ready ? 'check' : 'info')}<strong>${ready ? layout.action === 'already_uefi' ? 'UEFI is already present' : 'Migration plan is ready' : 'Resolve the migration blockers'}</strong></div>${plan.blockers?.length ? `<div class="oci-plan-section"><h4>Blockers</h4><ul class="oci-blockers">${lines(plan.blockers)}</ul></div>` : !ready ? '<div class="notice warning">The planner could not establish a supported migration. Refresh inspection and review the source requirements.</div>' : ''}<div class="migration-capacity"><div><span>Current virtual disk</span><strong>${bytes(layout.disk_size_before)}</strong></div><div><span>Additional capacity</span><strong>${bytes(plan.growth_bytes)}</strong></div><div><span>Planned virtual disk</span><strong>${bytes(layout.disk_size_after)}</strong></div></div><details class="editor-disclosure migration-layout"><summary>${esc(action)}</summary><div class="details-content"><dl class="detail-list">${details.map(([label,value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl></div></details>${plan.changes?.length ? `<details class="editor-disclosure"><summary>Planned changes <span class="disclosure-meta">${plan.changes.length}</span></summary><div class="details-content"><ul>${lines(plan.changes)}</ul></div></details>` : ''}${packages.length ? `<div class="oci-plan-section"><h4>Required packages</h4><p class="migration-package-list">${packages.map(esc).join(', ')}</p></div>` : ''}${plan.warnings?.length ? `<div class="oci-plan-section"><h4>Checks and limitations</h4><ul class="oci-warnings">${lines(plan.warnings)}</ul></div>` : ''}`;
}
async function previewBootMigration(config = null, beforeBuild = false, allowNetwork = undefined) {
  const imageId = state.selected, revision = state.editorRevision;
  const button = $('#migration-plan-button'); if (button) button.disabled = true; notice('#migration-error','');
  try {
    config = config || getBootMigrationConfig();
    if (!config) throw new Error('Enable BIOS-to-UEFI migration to preview the proposed changes.');
    const plan = await api(`/images/${encodeURIComponent(imageId)}/uefi/plan`,{method:'POST',body:JSON.stringify({boot_migration:config,allow_network:allowNetwork ?? $('#allow-network').checked})});
    if (state.selected !== imageId || state.editorRevision !== revision) throw new Error('The source or settings changed. Preview migration again for the current choices.');
    renderMigrationPlan(plan);
    if (beforeBuild && (!plan.ready_to_migrate || plan.blockers?.length)) {
      setTab('boot'); revealEditorField($('#migration-plan-button')); $('#migration-plan').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',block:'center'});
      throw new Error('UEFI migration is not ready. Resolve the blockers in Boot & kernel before building.');
    }
    return plan;
  } catch (error) { if (state.selected === imageId) notice('#migration-error',errorText(error)); revealEditorField(error.field); if (beforeBuild) throw error; return null; }
  finally { if (button?.isConnected) button.disabled = ['queued','running'].includes(state.images.find(image => image.id === state.selected)?.inspection_status); }
}

function renderOciPanel() {
  return `<section class="editor-panel" role="tabpanel" aria-labelledby="tab-oci" id="panel-oci" hidden>
    <div class="oci-panel-heading"><h3>Image capabilities</h3><span class="badge" id="oci-catalog-count">${state.ociCatalog?.capabilities?.length || 0} capabilities</span></div>
    <label class="check-field oci-enable"><input type="checkbox" id="oci-enabled"><span>Apply OCI settings<small>Changing an OCI setting enables this option. Settings apply when the export target is Oracle Cloud.</small></span></label>
    <div id="oci-target-notice" class="notice info" hidden>OCI settings are saved in this form, but the current export target is not Oracle Cloud. <button type="button" class="button ghost small" data-action="oci-use-target">Use OCI export${icon('arrow')}</button></div>
    <div id="oci-catalog-error" class="notice error" role="alert"${state.ociCatalog ? ' hidden' : ''}>${esc(state.ociCatalogError || 'The OCI capability catalog is not available yet. Refresh the catalog to configure this image.')} <button type="button" class="button ghost small" data-action="oci-refresh-catalog">Refresh catalog</button></div>
    <div id="oci-settings" hidden><div id="oci-firmware-alert">${['dual','unknown'].includes(studioImage()?.inspection?.boot?.mode) ? `<div class="notice warning">${studioImage().inspection.boot.mode === 'dual' ? 'Both firmware modes are present. Confirm your firmware choice under Compute.' : 'Firmware support is unknown. Refresh inspection before choosing OCI firmware.'}</div>` : !studioImage()?.inspection?.boot ? '<div class="notice warning">Refresh inspection to detect firmware support.</div>' : ''}</div>
    <div id="oci-accelerated-note" class="notice warning" hidden></div>
    <div id="oci-platform-preserve-conflict" class="notice error" role="alert" hidden>Preserve &amp; validate requires OCI guest preparation off. <button type="button" class="button ghost small" data-studio-action="platform-validate-oci">Use validate-only</button></div>
    <div id="oci-capabilities"></div>
    <details class="editor-disclosure oci-section" data-disclosure="oci-preparation"><summary>Guest preparation <span class="disclosure-meta" id="oci-preparation-summary">Enabled</span></summary><div class="details-content">
      <label class="check-field"><input type="checkbox" id="oci-prepare" checked><span>Prepare this guest for the selected capabilities<small>Apply supported driver, initramfs, network, cloud-init, and console changes to the working image.</small></span></label>
      <div class="oci-preparation-grid">
        <label class="check-field"><input type="checkbox" id="oci-configure-network" checked><span>Configure guest networking<small>Prepare DHCP and OCI-compatible guest network configuration.</small></span></label>
        <label class="check-field"><input type="checkbox" id="oci-configure-cloud-init" checked><span>Configure cloud-init<small>Prepare the OCI data source and first-boot provisioning.</small></span></label>
        <label class="check-field"><input type="checkbox" id="oci-configure-serial" checked><span>Configure the serial console<small>Enable boot diagnostics through the OCI instance console.</small></span></label>
        <label class="check-field"><input type="checkbox" id="oci-install-packages"><span>Install missing preparation packages<small>Allow the engine to install required guest packages. Repository access must be enabled below.</small></span></label>
      </div>
      <label class="check-field"><input type="checkbox" id="oci-allow-network"><span>Allow networking during customization<small>Shared with Boot & kernel. Uses the guest’s configured repositories when installing packages.</small></span></label>
      <label class="check-field"><input type="checkbox" id="oci-ipv6-ack"><span>I have validated this guest’s IPv6 configuration<small>Required when advertising IPv6 support. Final validation must include a launch in the destination OCI network.</small></span></label>
    </div></details>
    <details class="editor-disclosure oci-details" data-disclosure="oci-import"><summary>Import settings, tags & shapes <span class="disclosure-meta">Optional</span></summary><div class="details-content">
      <p class="panel-intro">Included in the configuration download; no cloud resources are created.</p>
      <div class="form-grid">
        <label class="field">Display name<input id="oci-display-name" placeholder="custom-linux-image"></label>
        <label class="field">Import launch mode<select id="oci-launch-mode"><option value="NATIVE">Native</option><option value="PARAVIRTUALIZED" selected>Paravirtualized</option><option value="EMULATED">Emulated</option><option value="CUSTOM">Custom</option><option value="ACCELERATEDPV">Accelerated PV</option></select>${helpHint('ACCELERATEDPV is an OCI API launch mode for supported Acceleron shapes and compatible images. Image capability choices are checked against the regional schema separately.','Import launch mode')}</label>
        <label class="field">Operating system<input id="oci-operating-system" placeholder="Oracle Linux"></label>
        <label class="field">Operating system version<input id="oci-os-version" placeholder="9"></label>
        <label class="field">Compartment OCID<input id="oci-compartment" placeholder="ocid1.compartment.oc1…" autocomplete="off"></label>
        <label class="field">Object Storage namespace<input id="oci-namespace" placeholder="your-namespace" autocomplete="off"></label>
        <label class="field">Bucket name<input id="oci-bucket" placeholder="custom-images" autocomplete="off"></label>
        <label class="field">Object name<input id="oci-object-name" placeholder="images/custom-image.qcow2" autocomplete="off"></label>
      </div>
      <label class="field">Object Storage URI <span class="optional">alternative to namespace, bucket, and object</span><input id="oci-object-uri" placeholder="https://objectstorage.region.oraclecloud.com/…" autocomplete="off"><span class="field-help">Presigned URLs become part of the downloaded configuration. Enter one only if you intend to include it.</span></label>
      <div class="form-grid"><label class="field">Freeform tags <span class="optional">JSON object</span><textarea id="oci-freeform-tags" rows="4" spellcheck="false" placeholder='{"environment": "development"}'></textarea></label><label class="field">Defined tags <span class="optional">JSON object</span><textarea id="oci-defined-tags" rows="4" spellcheck="false" placeholder='{"Operations": {"CostCenter": "42"}}'></textarea></label></div>
      <h3 class="subheading">Compatible shapes <span class="disclosure-meta" id="oci-source-architecture"></span></h3><p class="field-help">Use exact OCI shape names for this architecture; CPU and memory limits are optional.</p>
      <div id="oci-shapes"></div><button type="button" class="button secondary small" data-action="oci-add-shape">${icon('plus')}Add compatible shape</button>
    </div></details>
    <details class="editor-disclosure oci-details" data-disclosure="oci-schema"><summary>Custom capability schema <span class="disclosure-meta">Advanced</span></summary><div class="details-content">
      <p class="panel-intro">Paste and load a regional OCI global image capability schema. Additional capabilities may require manual guest preparation.</p>
      <label class="field">Global schema version<input id="oci-schema-version" placeholder="Schema version from OCI"></label>
      <label class="field">Global capability schema <span class="optional">JSON object</span><textarea id="oci-schema-json" class="code-editor" rows="8" spellcheck="false" placeholder="Paste OCI global image capability schema JSON"></textarea></label>
      <div class="oci-inline-actions"><button type="button" class="button secondary small" data-action="oci-load-schema">${icon('code')}Load schema</button><button type="button" class="button ghost small" data-action="oci-reset-schema">Use bundled catalog</button><span class="field-help" id="oci-schema-status">Bundled catalog</span></div>
    </div></details>
    <div class="oci-plan-heading"><div><h3>Compatibility check</h3></div><button type="button" id="oci-plan-button" class="button primary" data-action="oci-preview">${icon('check')}Check compatibility</button></div>
    <div id="oci-form-error" class="notice error" role="alert" hidden></div><div id="oci-plan" class="oci-plan" aria-live="polite"></div>
    <details class="editor-disclosure" data-disclosure="oci-references"><summary>Catalog references</summary><div class="oci-sources details-content" id="oci-sources"></div></details></div>
  </section>`;
}
function ociIsSecureBoot(capability) { return /secure[._-]?boot/i.test(capability.key); }
function ociCapabilityType(capability) { return capability.descriptor_type?.toLowerCase() || (typeof capability.default_value === 'boolean' ? 'boolean' : Number.isInteger(capability.default_value) ? 'enuminteger' : 'enumstring'); }
function renderOciCapabilities(previous = {}) {
  const container = $('#oci-capabilities'); if (!container) return;
  const catalog = state.ociCatalog;
  if (!catalog?.capabilities?.length) { container.innerHTML = ''; return; }
  $('#oci-catalog-count').textContent = `${catalog.capabilities.length} capabilities`;
  const groups = new Map();
  catalog.capabilities.forEach((capability,index) => { const group = capability.group || 'Image capabilities'; if (!groups.has(group)) groups.set(group,[]); groups.get(group).push({...capability,index}); });
  const opened = new Set($$('[data-oci-group][open]',container).map(node => node.dataset.ociGroup));
  container.innerHTML = [...groups].map(([group,capabilities]) => `<details class="editor-disclosure oci-section" data-oci-group="${esc(group)}" data-disclosure="oci-group-${esc(group)}"${opened.has(group) ? ' open' : ''}><summary><span>${esc(group)} <span class="disclosure-meta">${capabilities.length} settings</span></span><span class="oci-group-summary"></span></summary><div class="details-content oci-capability-grid">${capabilities.map(capability => {
    const key = capability.key, type = ociCapabilityType(capability), secure = ociIsSecureBoot(capability), label = capability.label || key;
    const options = capability.values || [];
    const saved = previous[key];
    const recommended = key === 'Compute.Firmware' && !state.ociFirmwareEdited ? detectedOciFirmware() : null;
    const initial = recommended && options.includes(recommended) ? recommended : capability.default_value;
    const value = secure ? false : saved && !recommended && (type === 'boolean' || options.includes(saved.default_value)) ? saved.default_value : initial;
    const allowed = recommended && options.includes(recommended) ? [recommended] : saved?.values?.filter(item => options.includes(item)) || [value];
    const id = `oci-capability-${capability.index}`;
    let control;
    if (type === 'boolean') control = `<label class="check-field oci-boolean"><input type="checkbox" id="${id}" data-oci-default="${esc(key)}" aria-label="${esc(label)}"${value ? ' checked' : ''}${secure ? ' disabled' : ''}><span>${secure ? 'Unavailable for OCI custom images' : 'Enabled'}<small>${secure ? 'Secure Boot remains disabled. Selecting a capability cannot make an unsupported custom-image feature available.' : 'Allow this capability on the imported image.'}</small></span></label>`;
    else if (options.length) control = `<label class="field">Preferred value<select id="${id}" data-oci-default="${esc(key)}" aria-label="Preferred ${esc(label)}">${options.map(option => `<option value="${esc(JSON.stringify(option))}"${option === value ? ' selected' : ''}>${esc(ociValueLabel(option))}</option>`).join('')}</select></label><details class="oci-allowed-options" data-disclosure="oci-allowed-${esc(key)}"><summary>Allowed values <span class="disclosure-meta" data-allowed-summary></span></summary><fieldset class="oci-allowed" aria-label="Allowed values for ${esc(label)}"><legend>Allowed values</legend>${options.map(option => `<label><input type="checkbox" data-oci-allowed="${esc(key)}" value="${esc(JSON.stringify(option))}"${allowed.includes(option) ? ' checked' : ''}><span>${esc(ociValueLabel(option))}</span></label>`).join('')}</fieldset></details>`;
    else control = `<label class="field">Preferred value<input id="${id}" data-oci-default="${esc(key)}" type="${type.includes('integer') ? 'number' : 'text'}"${type.includes('integer') ? ' step="1"' : ''} value="${esc(value)}"></label>`;
    return `<article class="oci-capability" data-oci-capability="${esc(key)}"><div class="oci-capability-title"><h4>${esc(label)}</h4>${helpHint([capability.description,Array.isArray(capability.guest_action)?capability.guest_action.join(' '):capability.guest_action,`Schema key: ${key}`].filter(Boolean).join(' '),label)}</div>${control}${key === 'Compute.Firmware' ? ociFirmwareHint() : ''}</article>`;
  }).join('')}</div></details>`).join('');
  updateDisclosureSummaries();
  $('#oci-sources').innerHTML = `<span>Catalog checked ${esc(catalog.checked_on || 'at build time')}</span>${(catalog.sources || []).filter(source => /^https:\/\//.test(source.url || '')).map(source => `<a href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.title || 'OCI documentation')}</a>`).join('')}`;
}
function readOciCapabilities(validate = true) {
  const capabilities = {};
  for (const capability of state.ociCatalog?.capabilities || []) {
    const node = $$('[data-oci-default]').find(element => element.dataset.ociDefault === capability.key);
    if (!node) continue;
    const type = ociCapabilityType(capability);
    const value = ociIsSecureBoot(capability) ? false : type === 'boolean' ? node.checked : capability.values?.length ? JSON.parse(node.value) : type.includes('integer') ? Number(node.value) : node.value;
    const values = capability.values?.length ? $$('[data-oci-allowed]').filter(element => element.dataset.ociAllowed === capability.key && element.checked).map(element => JSON.parse(element.value)) : null;
    if (validate && values && (!values.length || !values.includes(value))) throw editorError(`${capability.label || capability.key}: choose at least one allowed value and include the preferred value.`,$$('[data-oci-allowed]').find(input => input.dataset.ociAllowed === capability.key) || node);
    if (validate && type.includes('integer') && !Number.isInteger(value)) throw editorError(`${capability.label || capability.key} must be an integer.`,node);
    capabilities[capability.key] = {default_value:value,values};
  }
  return capabilities;
}
function parseOciJson(selector, label, fallback = {}) {
  const content = $(selector).value.trim(); if (!content) return fallback;
  let parsed; try { parsed = JSON.parse(content); } catch { throw editorError(`${label} must be valid JSON.`,selector); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw editorError(`${label} must be a JSON object.`,selector);
  return parsed;
}
function getOciConfig() {
  if (!state.ociCatalog?.capabilities?.length) throw new Error('Load the OCI capability catalog before building with OCI settings.');
  if(platformPreserveConflict())throw editorError('Turn off OCI guest preparation to preserve the existing hardware configuration.','#oci-prepare');
  const acceleratedIssue=ociAcceleratedSchemaError(); if(acceleratedIssue)throw editorError(acceleratedIssue,'#oci-schema-json');
  const boot = state.images.find(image => image.id === state.selected)?.inspection?.boot;
  if (boot?.mode === 'dual' && !state.ociFirmwareEdited && state.ociCatalog.capabilities.some(capability => capability.key === 'Compute.Firmware')) throw editorError('Confirm the OCI firmware choice for this dual-mode image.','#oci-firmware-confirm');
  const global_schema = parseOciJson('#oci-schema-json','Global capability schema',null);
  if (JSON.stringify(global_schema) !== JSON.stringify(state.ociLoadedSchema || null)) throw editorError('Load the edited global capability schema before previewing or building.','#oci-schema-json');
  const import_options = {launch_mode:$('#oci-launch-mode').value,freeform_tags:parseOciJson('#oci-freeform-tags','Freeform tags'),defined_tags:parseOciJson('#oci-defined-tags','Defined tags'),shape_compatibility:[]};
  const fields = {compartment_id:'oci-compartment',namespace:'oci-namespace',bucket:'oci-bucket',object_name:'oci-object-name',object_uri:'oci-object-uri',display_name:'oci-display-name',operating_system:'oci-operating-system',operating_system_version:'oci-os-version'};
  for (const [key,id] of Object.entries(fields)) { const value = $(`#${id}`).value.trim(); if (value) import_options[key] = value; }
  for (const row of $$('.oci-shape-row')) {
    const shape = $('[data-shape-field="shape"]',row).value.trim();
    if (!shape) { if ($$('input',row).some(input => input.value.trim())) throw editorError('Enter a shape name for every shape compatibility entry.',$('[data-shape-field="shape"]',row)); continue; }
    const entry = {shape};
    for (const key of ['min_ocpus','max_ocpus','min_memory_gbs','max_memory_gbs']) { const input = $(`[data-shape-field="${key}"]`,row); if (input.value.trim()) { entry[key] = Number(input.value); if (!Number.isInteger(entry[key]) || entry[key] <= 0) throw editorError('Shape CPU and memory limits must be positive integers.',input); } }
    if (entry.min_ocpus && entry.max_ocpus && entry.min_ocpus > entry.max_ocpus) throw editorError(`${shape}: minimum OCPUs must not exceed the maximum.`,$('[data-shape-field="min_ocpus"]',row));
    if (entry.min_memory_gbs && entry.max_memory_gbs && entry.min_memory_gbs > entry.max_memory_gbs) throw editorError(`${shape}: minimum memory must not exceed the maximum.`,$('[data-shape-field="min_memory_gbs"]',row));
    import_options.shape_compatibility.push(entry);
  }
  if (import_options.object_uri && ['namespace','bucket','object_name'].some(key => import_options[key])) throw editorError('Choose either an Object Storage URI or namespace, bucket, and object name for OCI import.','#oci-object-uri');
  const guest = {prepare:$('#oci-prepare').checked,install_packages:$('#oci-install-packages').checked,configure_network:$('#oci-configure-network').checked,configure_cloud_init:$('#oci-configure-cloud-init').checked,configure_serial_console:$('#oci-configure-serial').checked,acknowledge_ipv6_validation:$('#oci-ipv6-ack').checked};
  if (guest.install_packages && !$('#allow-network').checked) throw editorError('Enable networking during customization to install OCI preparation packages.','#oci-allow-network');
  return {capabilities:readOciCapabilities(),guest,import_options,global_schema_version:$('#oci-schema-version').value.trim() || null,global_schema};
}
function markOciChanged() { if ($('#oci-enabled')) $('#oci-enabled').checked = true; updateDisclosureSummaries(); if ($('#oci-plan')) $('#oci-plan').innerHTML = '<p class="muted">Settings changed. Check compatibility again.</p>'; }
function addOciShape(focus=true) {
  const row = document.createElement('div'); row.className = 'oci-shape-row';
  row.innerHTML = `<div class="oci-shape-heading"><label class="field">OCI shape<input data-shape-field="shape" placeholder="${sourceArchitecture()==='aarch64'?'VM.Standard.A1.Flex':sourceArchitecture()==='x86_64'?'VM.Standard.E5.Flex':'Exact OCI shape name'}"></label><button type="button" class="icon-button" data-action="oci-remove-shape" aria-label="Remove shape">${icon('close')}</button></div><div class="oci-shape-limits">${[['min_ocpus','Minimum OCPUs'],['max_ocpus','Maximum OCPUs'],['min_memory_gbs','Minimum memory (GiB)'],['max_memory_gbs','Maximum memory (GiB)']].map(([key,label]) => `<label class="field">${label}<input type="number" data-shape-field="${key}" min="1" step="1" placeholder="OCI default"></label>`).join('')}</div>`;
  $('#oci-shapes').append(row); markOciChanged(); if(focus)$('input',row).focus();
}
function renderOciPlan(plan) {
  const items = value => (value || []).map(item => `<li>${esc(typeof item === 'string' ? item : JSON.stringify(item))}</li>`).join('');
  const blocked = Boolean(plan.blockers?.length);
  $('#oci-plan').innerHTML = `<div class="oci-plan-status ${blocked ? 'blocked' : 'clear'}">${icon(blocked ? 'info' : 'check')}<strong>${blocked ? 'Resolve these blockers before building' : 'Compatibility plan is ready'}</strong></div>${blocked ? `<div class="oci-plan-section"><h4>Blockers</h4><ul class="oci-blockers">${items(plan.blockers)}</ul></div>` : ''}${plan.changes?.length ? `<details class="editor-disclosure"><summary>Planned changes <span class="disclosure-meta">${plan.changes.length}</span></summary><div class="details-content"><ul>${items(plan.changes)}</ul></div></details>` : ''}${plan.warnings?.length ? `<div class="oci-plan-section"><h4>Checks and limitations</h4><ul class="oci-warnings">${items(plan.warnings)}</ul></div>` : ''}<p class="validation-note">OCI import and a test launch are still required.</p>`;
}
async function previewOci(config = null, beforeBuild = false, migrationOverride = undefined, networkOverride = undefined, platformOverride = undefined, mountPolicyOverride = undefined) {
  const imageId = state.selected, revision = state.editorRevision;
  const button = $('#oci-plan-button'); if (button) button.disabled = true; notice('#oci-form-error','');
  try {
    if (!config) { $('#oci-enabled').checked = true; updateOciVisibility(); config = getOciConfig(); }
    const migration = migrationOverride === undefined ? getBootMigrationConfig() : migrationOverride;
    const platform = platformOverride === undefined ? getPlatformMigrationConfig() : platformOverride;
    const plan = await api(`/images/${encodeURIComponent(imageId)}/oci/plan`,{method:'POST',body:JSON.stringify({oci:config,mount_policy:mountPolicyOverride ?? getMountPolicy(),allow_network:networkOverride ?? $('#allow-network').checked,...(migration ? {boot_migration:migration} : {}),...(platform ? {platform_migration:platform} : {})})});
    if (state.selected !== imageId || state.editorRevision !== revision) throw new Error('The source or settings changed. Preview the OCI settings again for the current choices.');
    renderOciPlan(plan);
    if (beforeBuild && plan.blockers?.length) { setTab('oci'); $('#oci-plan').scrollIntoView({behavior:'smooth',block:'center'}); throw new Error('The OCI compatibility plan has blockers. Resolve them in the OCI compatibility step before building.'); }
    return plan;
  } catch (error) { if (state.selected === imageId) notice('#oci-form-error',errorText(error)); revealEditorField(error.field); if (beforeBuild) throw error; return null; }
  finally { if (button?.isConnected) button.disabled = ['queued','running'].includes(state.images.find(image => image.id === state.selected)?.inspection_status); }
}
async function loadOciCatalog(schema = null, commit = true) {
  const catalog = await api('/oci/catalog',schema ? {method:'POST',body:JSON.stringify({schema})} : {});
  if (!Array.isArray(catalog.capabilities) || !catalog.capabilities.length) throw new Error('The OCI catalog did not contain any capabilities.');
  if (commit) { state.ociCatalog = catalog; if (!schema) state.ociBaseCatalog = catalog; state.ociCatalogError = null; }
  return catalog;
}
async function changeOciSchema(reset = false) {
  const imageId = state.selected, revision = state.editorRevision;
  notice('#oci-form-error','');
  try {
    const previous = readOciCapabilities(false);
    const schema = reset ? null : parseOciJson('#oci-schema-json','Global capability schema',null);
    if (!reset && !schema) throw new Error('Paste a global capability schema before loading it.');
    const catalog = await loadOciCatalog(schema,false);
    if (state.selected !== imageId || state.editorRevision !== revision) throw new Error('The source or settings changed while loading the schema. Load it again for the current image.');
    const acceleratedIssue=ociAcceleratedSchemaError(catalog,previous); if(acceleratedIssue)throw editorError(acceleratedIssue,'#oci-schema-json');
    state.ociCatalog = catalog; if (!schema) state.ociBaseCatalog = catalog; state.ociCatalogError = null; state.ociLoadedSchema = schema; state.editorRevision++;
    if (reset) { $('#oci-schema-json').value = ''; $('#oci-schema-version').value = ''; }
    $('#oci-schema-status').textContent = schema ? 'Current OCI schema loaded' : 'Bundled catalog';
    $('#oci-catalog-error').hidden = true; renderOciCapabilities(previous); compactStudioHelp($('#panel-oci'));  if ($('#boot-migration-enabled')?.checked && !state.ociFirmwareEdited) applyMigrationFirmware(); markOciChanged();
    toast(schema ? 'OCI schema loaded. Review the capability choices and preview the plan.' : 'Bundled OCI catalog restored.');
  } catch (error) { if (state.selected === imageId) notice('#oci-form-error',errorText(error)); }
}

async function start() { setView(location.hash.slice(1)); $('#image-workspace').innerHTML = '<div class="loading-surface"><div class="spinner" aria-hidden="true"></div>Connecting to your image workspace…</div>'; try { updateHealth(await api('/health')); try { await loadOciCatalog(); } catch(error) { state.ociCatalogError = errorText(error); } await loadDestinationCatalog(); await refresh(); } catch(error) { notice('#global-error',errorText(error)); renderEmpty(); } setInterval(() => { if(!document.hidden && !state.authPending && !state.busy) refresh(); },4000); }
start();
