'use strict';

// The editor keeps every field mounted. Navigation changes visibility, so
// returning to an earlier step never resets the customization draft.
const wizardState = {sessions:{},busy:false,navigating:false};
const wizardStepCatalog = [
  {id:'source',label:'Source',description:'Choose a local, S3 or existing image.'},
  {id:'overview',label:'Inspect',description:'Review the source and detected boot mode.'},
  {id:'storage',label:'Storage',description:'Preview and resize disk space.'},
  {id:'startup',label:'Startup',description:'Services and scheduled jobs.'},
  {id:'access',label:'Access',description:'SSH login and authorized public keys.'},
  {id:'mounts',label:'Mounts',description:'Persistent filesystem mounts.'},
  {id:'boot',label:'Boot & kernel',navLabel:'Boot',description:'Firmware, kernels and drivers.'},
  {id:'export',label:'Destination',description:'Output format and target hardware.'},
  {id:'oci',label:'OCI compatibility',navLabel:'OCI',description:'Guest readiness and image capabilities.'},
  {id:'review',label:'Review',description:'Confirm the changes before building.'},
  {id:'result',label:'Build & export',navLabel:'Build',description:'Follow progress, then download or upload.'}
];

function wizardSession(imageId = state.selected) {
  const key = imageId || '__empty__';
  return wizardState.sessions[key] ||= {step:'source',visited:['source'],jobId:null,uploadId:null};
}
function wizardCurrentStep(imageId = state.selected) { return wizardSession(imageId).step; }
function wizardSteps() {
  const target = $('input[name="target"]:checked')?.value || 'oci';
  return wizardStepCatalog.filter(step => step.id !== 'oci' || target === 'oci');
}
function wizardImage() { return state.images.find(image => image.id === state.selected); }
function wizardInspectionPending() { return ['queued','running'].includes(wizardImage()?.inspection_status); }
function wizardBuildPending() {
  const session = wizardSession();
  if (!session.jobId) return false;
  const job = state.jobs.find(item => item.id === session.jobId);
  return !job || !['succeeded','failed'].includes(job.status);
}
function wizardChrome() {
  return '<div id="wizard-chrome"><div class="wizard-context"><h2 id="wizard-heading" tabindex="-1" aria-describedby="wizard-description"></h2><span id="wizard-step-count"></span><p id="wizard-description" class="sr-only"></p><progress class="wizard-progress sr-only" id="wizard-progress" max="100" value="0" aria-label="Wizard progress"></progress></div><nav aria-label="Image build steps"><ol class="wizard-stepper"></ol></nav></div>';
}
function wizardFooter() {
  return `<div id="wizard-error" class="notice error" role="alert" hidden></div><div class="wizard-footer"><div class="wizard-footer-copy"><strong id="build-summary">Image export</strong><span id="wizard-footer-help" hidden></span></div><div class="wizard-footer-actions"><button type="button" id="wizard-back" class="button secondary" data-wizard-action="back"><span class="wizard-back-arrow">${icon('arrow')}</span>Back</button><button type="button" id="wizard-next" class="button primary" data-wizard-action="next">Next${icon('arrow')}</button><button type="submit" id="build-button" class="button primary" hidden>${icon('stack')}Build image</button></div></div>`;
}
function wizardSource() {
  const image = wizardImage();
  if (!state.images.length) return `<div class="wizard-source-card"><span class="large-icon">${icon('upload')}</span><div><h3>Import a source</h3><p>Local file · S3 · HTTPS</p><button type="button" class="button primary" data-action="open-import">${icon('plus')}Import image</button></div></div>`;
  return `<div class="wizard-source-card wizard-source-current"><span class="large-icon">${icon('image')}</span><div><label class="field">Source image<select id="image-select">${state.images.map(item => `<option value="${esc(item.id)}"${item.id === state.selected ? ' selected' : ''}>${esc(item.name)} · ${esc(item.status)}</option>`).join('')}</select></label>${image?.status === 'ready' ? '' : `<p>${image?.status === 'failed' ? 'Choose another image or import a new source.' : 'Inspection is in progress.'}</p>`}</div></div><div class="wizard-source-import"><p>Local file · S3 · HTTPS</p><button type="button" class="button secondary" data-action="open-import">${icon('plus')}Import image</button></div>`;
}
function wizardPendingInspection(image) {
  if (!image) return '<p class="muted">Import an image in the Source step to begin inspection.</p>';
  const job = state.jobs.find(item => item.image_id === image.id && item.kind === 'import');
  return `<h3>Inspecting ${esc(image.name)}</h3>${image.status === 'failed' ? `<div class="notice error">${esc(image.error || 'Import failed. Return to Source and import a new image.')}</div>` : `<div class="loading-surface"><div class="spinner" aria-hidden="true"></div>Importing and inspecting…</div>`}${job ? `<details><summary>Import activity</summary><pre class="job-log">${esc((job.logs || []).join('\n') || 'Waiting for the image engine…')}</pre></details>` : ''}`;
}
function renderWizardEmpty(image = null) {
  if (image && state.selected !== image.id) state.selected = image.id;
  const session = wizardSession();
  if (!['source','overview'].includes(session.step)) session.step = image ? 'overview' : 'source';
  $('#image-workspace').innerHTML = `<div class="wizard-shell">${wizardChrome()}<div class="editor-body"><section id="panel-source" class="editor-panel">${wizardSource()}</section><section id="panel-overview" class="editor-panel" hidden>${wizardPendingInspection(image)}</section></div>${wizardFooter()}</div>`;
  wizardUpdate();
}
function wizardReady() {
  const form = $('#recipe-form');
  if (!form) return;
  form.classList.add('wizard-shell');
  $('.editor-tabs',form)?.remove();
  const body = $('.editor-body',form);
  if (!$('#wizard-chrome',form)) body.insertAdjacentHTML('beforebegin',wizardChrome());
  if (!$('#panel-source',form)) body.insertAdjacentHTML('afterbegin',`<section class="editor-panel" id="panel-source" hidden>${wizardSource()}</section>`);
  if (!$('#panel-review',form)) body.insertAdjacentHTML('beforeend','<section class="editor-panel" id="panel-review" hidden></section><section class="editor-panel" id="panel-result" hidden></section>');
  const oldFooter = $('.build-bar',form);
  if (oldFooter) oldFooter.outerHTML = wizardFooter();
  else if (!$('#wizard-next',form)) form.insertAdjacentHTML('beforeend',wizardFooter());
  $$('.editor-panel',form).forEach(panel => { panel.setAttribute('role','region'); panel.removeAttribute('aria-labelledby'); panel.setAttribute('aria-label',wizardStepCatalog.find(step => panel.id === `panel-${step.id}`)?.label || 'Customization'); });
  wizardUpdate();
}
function wizardShowStep(id, {focus=false} = {}) {
  if (!wizardStepCatalog.some(step => step.id === id)) return;
  const session = wizardSession();
  session.step = id;
  if (!session.visited.includes(id)) session.visited.push(id);
  wizardUpdate();
  if (focus && state.view === 'images') {
    $('#wizard-heading')?.focus({preventScroll:true});
    $('#wizard-chrome')?.scrollIntoView({block:'start',behavior:'instant'});
  }
}
function wizardUpdate() {
  const stepper = $('.wizard-stepper');
  if (!stepper) return;
  const steps = wizardSteps(), session = wizardSession(), image = wizardImage();
  if (!steps.some(step => step.id === session.step)) session.step = 'export';
  if (!$('#recipe-form') && !['source','overview'].includes(session.step)) session.step = image ? 'overview' : 'source';
  const index = Math.max(0,steps.findIndex(step => step.id === session.step));
  const busy = wizardState.busy || wizardState.navigating || Boolean(studioState.plans[state.selected]?.storageFitPending);
  const navigation = steps.map((step,i) => {
    const visited = session.visited.includes(step.id), current = i === index;
    const unavailable = (!image && i > 0) || (image?.status !== 'ready' && i > 1) || (step.id === 'result' && !session.jobId);
    const disabled = busy || unavailable || (!visited && i > index + 1);
    return `<li><button type="button" class="wizard-step-button${current ? ' current' : ''}${visited && i < index ? ' completed' : ''}" data-wizard-step="${step.id}"${current ? ' aria-current="step"' : ''}${disabled ? ' disabled' : ''} aria-label="Step ${i + 1}: ${esc(step.label)}" title="${esc(step.label+': '+step.description)}"><span class="wizard-step-number" aria-hidden="true">${visited && i < index ? icon('check') : i + 1}</span><span class="wizard-step-label">${esc(step.navLabel || step.label)}</span></button></li>`;
  }).join('');
  if (stepper.dataset.signature !== navigation) {
    const focusedStep = document.activeElement?.dataset?.wizardStep;
    stepper.innerHTML = navigation;
    stepper.dataset.signature = navigation;
    if (focusedStep) $$('[data-wizard-step]',stepper).find(button => button.dataset.wizardStep === focusedStep && !button.disabled)?.focus({preventScroll:true});
  }
  const active = $('[aria-current="step"]',stepper);
  if (active) {
    const bounds = stepper.getBoundingClientRect(), item = active.getBoundingClientRect();
    if (item.left < bounds.left || item.right > bounds.right) stepper.scrollLeft += item.left - bounds.left - 10;
  }
  $('#wizard-step-count').textContent = `${index + 1} / ${steps.length}`;
  $('#wizard-step-count').setAttribute('aria-label',`Step ${index + 1} of ${steps.length}`);
  $('#wizard-heading').textContent = steps[index].label;
  $('#wizard-description').textContent = steps[index].description;
  $('#wizard-progress').value = Math.round(index / Math.max(1,steps.length - 1) * 100);
  $$('.editor-panel').forEach(panel => panel.hidden = panel.id !== `panel-${session.step}`);
  const back = $('#wizard-back'), next = $('#wizard-next'), build = $('#build-button');
  back.disabled = index === 0 || busy;
  next.hidden = ['review','result'].includes(session.step);
  next.disabled = busy || (session.step === 'source' && !image) || (session.step === 'overview' && (image?.status !== 'ready' || wizardInspectionPending()));
  next.innerHTML = `Next: ${esc(steps[index + 1]?.label || 'Review')}${icon('arrow')}`;
  build.hidden = session.step !== 'review';
  build.disabled = busy || wizardInspectionPending() || wizardBuildPending();
  const target = $('input[name="target"]:checked')?.value || 'oci';
  $('#build-summary').textContent = `${profiles[target].label} · ${($('input[name="target"]:checked')?.value === 'generic' ? $('#output-format').value : profiles[target].format).toUpperCase()}`;
  $('#wizard-footer-help').textContent = wizardBuildPending() ? 'Build in progress' : '';
  const selector = $('#image-select'); if (selector) selector.disabled = busy;
  if (session.step === 'review') wizardRenderReview();
  if (session.step === 'result') wizardRenderResult();
  updateDisclosureSummaries();
  compactStudioHelp($('#recipe-form')||document);
  wizardOpenCompletedExport();
}
function wizardOpenCompletedExport() {
  if (state.view !== 'images' || !state.selected) return false;
  const session = wizardSession();
  if (session.step !== 'result' || !session.jobId || session.completedJobId === session.jobId) return false;
  const job = state.jobs.find(item => item.id === session.jobId && item.image_id === state.selected && item.kind === 'build');
  const artifact = job?.status === 'succeeded' && state.artifacts.find(item => item.id === job.result?.artifact_id && item.image_id === state.selected);
  if (!artifact) return false;
  session.completedJobId = session.jobId;
  return openExportArtifact(artifact.id, {details:false});
}
function wizardSetBusy(value) { wizardState.busy = Boolean(value); wizardUpdate(); }
function wizardError(message, node) {
  notice('#wizard-error',message);
  if (node) {
    const panel = node.closest('.editor-panel');
    if (panel?.hidden) wizardShowStep(panel.id.replace('panel-',''),{focus:false});
    revealEditorField(node); node.reportValidity?.();
  }
}
function wizardCheckFields(panel) {
  for (const node of $$('input,select,textarea',panel)) {
    if (node.disabled || node.closest('[hidden]') || !node.willValidate) continue;
    if (!node.checkValidity()) {
      const error = new Error(node.validationMessage || 'Review the highlighted field.');
      error.field = node;
      throw error;
    }
  }
}
async function wizardValidateStep(id, remote = false) {
  const image = wizardImage();
  if (id === 'source') { if (!image) throw new Error('Import or choose a source image to continue.'); return; }
  if (id === 'overview') {
    if (image?.status !== 'ready' || wizardInspectionPending()) throw new Error('Wait for successful image inspection before continuing.');
    return;
  }
  const panel = $(`#panel-${id}`);
  if (!panel || ['review','result'].includes(id)) return;
  if (id === 'oci' && !$('#oci-enabled').checked) return;
  // Check native constraints even when reviewing a previously visited panel.
  const hidden = panel.hidden; panel.hidden = false;
  try { wizardCheckFields(panel); } finally { panel.hidden = hidden; }
  if (id === 'storage') {
    const size = getDiskSizeGiB();
    if (size && size > (state.health?.limits?.max_virtual_gib || 2048)) throw new Error('The requested disk capacity exceeds the server limit.');
    const resize = getStorageResizeConfig();
    if (resize && remote) await previewStorage(resize,true);
  }
  if (id === 'export') { const platform=getPlatformMigrationConfig(); if(remote&&platform)await previewPlatform(platform,true); }
  if (id === 'access') getSshAccessConfig();
  if (id === 'startup') {
    for (const row of $$('.rule-row')) {
      const name = $('.service-name',row).value.trim();
      if (name && !/^[A-Za-z0-9_][A-Za-z0-9_@.:-]*\.(service|timer|socket|target)$/.test(name)) throw editorError('Use a valid systemd unit name, such as sshd.service.',$('.service-name',row));
    }
    const path = $('#custom-file-path').value.trim(), content = $('#custom-file-content').value;
    if (Boolean(path) !== Boolean(content)) throw editorError('Enter both a path and contents for the custom startup file, or leave both empty.',path?'#custom-file-content':'#custom-file-path');
    if (path && (path.includes('..') || !/^\/etc\/(cron\.d\/[A-Za-z0-9_-]+|systemd\/system\/[A-Za-z0-9_@.-]+\.service)$/.test(path))) throw editorError('Use a custom .service file under /etc/systemd/system/ or a file under /etc/cron.d/.','#custom-file-path');
    if (path && $$('[data-file]').some(node => node.dataset.file === path && node.value !== node.defaultValue)) throw editorError('This startup file is already edited above. Keep one edit for that path.','#custom-file-path');
  }
  if (id === 'boot') {
    const install = $('#packages-install').value.trim().split(/[\s,]+/).filter(Boolean);
    const remove = $('#packages-remove').value.trim().split(/[\s,]+/).filter(Boolean);
    if ([...install,...remove].some(name => !/^[A-Za-z0-9][A-Za-z0-9.+_:~=-]{0,159}$/.test(name))) throw editorError('Use package names or versions, without paths, wildcards, or command options.','#packages-install');
    if (install.some(name => remove.includes(name))) throw editorError('A package cannot be installed and removed in the same build.','#packages-install');
    const grub = $('[data-file="/etc/default/grub"]');
    if (grub.value !== grub.defaultValue && !$('#regenerate-grub').checked) throw editorError('Enable GRUB regeneration to apply your changed GRUB defaults.','#regenerate-grub');
    const migration = getBootMigrationConfig();
    if (remote && migration) await previewBootMigration(migration,true,requiredDownloadsEnabled());
  }
  if (id === 'mounts') {
    validateMountPolicy();
    const fstab = $('[data-file="/etc/fstab"]');
    if (fstab.value !== fstab.defaultValue) {
      for (const [index,line] of fstab.value.split('\n').entries()) {
        const fields = line.trim().split(/\s+/).filter(Boolean);
        const comment = fields.findIndex(value => value.startsWith('#'));
        if (comment >= 0) fields.splice(comment);
        if (!fields.length) continue;
        if (fields.length < 4 || fields.length > 6) throw new Error(`fstab line ${index + 1} needs 4–6 fields. Escape spaces as \\040.`);
        if (!fields[1].startsWith('/') && !(fields[2] === 'swap' && ['none','swap','-'].includes(fields[1]))) throw new Error(`fstab line ${index + 1} needs an absolute mountpoint, or a swap entry.`);
        if (fields.slice(4).some(value => !/^\d+$/.test(value))) throw new Error(`fstab line ${index + 1} needs nonnegative dump and fsck values.`);
      }
    }
  }
  if (id === 'oci' && $('#oci-enabled').checked) {
    const config = getOciConfig();
    if (remote) await previewOci(config,true,getBootMigrationConfig(),requiredDownloadsEnabled());
  }
}
async function wizardValidateAll() {
  for (const step of wizardSteps().filter(item => !['review','result'].includes(item.id))) {
    try { await wizardValidateStep(step.id); }
    catch (error) { wizardShowStep(step.id,{focus:true}); throw error; }
  }
  getRecipe();
}
async function wizardGo(id) {
  if (wizardState.busy || wizardState.navigating || studioState.plans[state.selected]?.storageFitPending) return;
  const imageId = state.selected, steps = wizardSteps(), session = wizardSession();
  const oldIndex = steps.findIndex(step => step.id === session.step), nextIndex = steps.findIndex(step => step.id === id);
  if (nextIndex < 0 || nextIndex === oldIndex) return;
  if (nextIndex < oldIndex) { notice('#wizard-error',''); wizardShowStep(id,{focus:true}); return; }
  wizardState.navigating = true; wizardUpdate(); notice('#wizard-error','');
  try {
    if (id === 'result') { if (!session.jobId) throw new Error('Review your settings and start a build first.'); }
    else {
      for (const step of steps.slice(oldIndex,nextIndex)) {
        await wizardValidateStep(step.id,true);
        if (state.selected !== imageId) throw new Error('The selected source changed. Continue with the current image.');
      }
      if (id === 'review') await wizardValidateAll();
    }
    if (state.selected !== imageId) return;
    wizardShowStep(id,{focus:true});
  } catch (error) { if (state.selected === imageId) wizardError(errorText(error),error.field); }
  finally { wizardState.navigating = false; wizardUpdate(); }
}
async function wizardNext() {
  const steps = wizardSteps(), index = steps.findIndex(step => step.id === wizardCurrentStep());
  if (steps[index + 1]) await wizardGo(steps[index + 1].id);
}
function wizardBack() {
  if (wizardState.busy || wizardState.navigating) return;
  const steps = wizardSteps(), index = steps.findIndex(step => step.id === wizardCurrentStep());
  if (index > 0) { notice('#wizard-error',''); wizardShowStep(steps[index - 1].id,{focus:true}); }
}
async function wizardBeforeBuild() {
  if (wizardCurrentStep() !== 'review') { await wizardNext(); return false; }
  try { await wizardValidateAll(); return true; }
  catch (error) { wizardError(errorText(error),error.field); return false; }
}
function wizardRenderReview() {
  const panel = $('#panel-review'); if (!panel) return;
  let recipe;
  try { recipe = getRecipe(); }
  catch (error) { delete panel.dataset.signature; panel.innerHTML = `<div class="notice error">${esc(errorText(error))}</div><p class="muted">Use Back or the completed steps to correct these settings.</p>`; return; }
  const cachedStorage = studioSession().storage;
  const sizing = recipe.storage_resize && cachedStorage?.signature === JSON.stringify({storage_resize:recipe.storage_resize,disk_size_gib:recipe.disk_size_gib,mount_policy:recipe.mount_policy}) && cachedStorage.snapshot === studioInspectionKey() ? cachedStorage.plan : null;
  const plannedCapacity = sizing?.ready ? sizing.layout?.disk_size_after : recipe.disk_size_gib ? recipe.disk_size_gib*GiB : null;
  const signature = JSON.stringify([state.selected,recipe,wizardImage()?.inspection?.boot,sizing]);
  if (panel.dataset.signature === signature) return;
  panel.dataset.signature = signature;
  const unchangedOpen = $('[data-disclosure="review-unchanged"]',panel)?.open ?? state.editorDrafts[state.selected]?.disclosures?.['review-unchanged'];
  const cards = [], unchanged = [];
  const add = (title, step, lines, changed=true) => (changed ? cards : unchanged).push(`<article class="wizard-review-card"><div class="wizard-review-heading"><h3>${esc(title)}</h3><button type="button" class="button ghost small" data-wizard-step="${step}">Edit</button></div><ul>${lines.map(line => `<li>${esc(line)}</li>`).join('')}</ul></article>`);
  add('Source','source',[wizardImage()?.name || 'Selected source',`Architecture: ${architectureName(wizardImage()?.inspection?.os?.arch)}`,`Detected boot: ${bootModeLabel(wizardImage()?.inspection?.boot)}`]);
  add('Storage','storage',[
    plannedCapacity ? `Disk: ${bytes(plannedCapacity)}` : recipe.storage_resize ? 'Size the disk automatically' : 'Keep current disk capacity',
    ...(recipe.storage_resize?.sizes.length ? recipe.storage_resize.sizes.map(item=>`${storageFilesystems().find(fs=>fs.device===item.device)?.mountpoint || item.device}: ${bytes(item.size_mib*MiB)}`) : sizing?.ready && sizing.root_fill ? sizing.filesystems.filter(fs=>fs.selected_size!==fs.size).map(fs=>`${fs.mountpoint || fs.device}: ${bytes(fs.selected_size)} · automatic`) : sizing?.ready ? ['Keep filesystem capacities'] : recipe.storage_resize ? ['Automatic filesystem sizing'] : []),
    ...(sizing?.ready && sizing.projected_boot_updates?.length ? ['Use filesystem UUIDs for GRUB searches'] : [])
  ],Boolean(recipe.disk_size_gib || recipe.storage_resize));
  const startup = recipe.services.map(item => `${item.action} ${item.name}`);
  startup.push(...recipe.files.filter(file => /\/cron|\/systemd\//.test(file.path)).map(file => `Edit ${file.path}`));
  add('Startup','startup',startup.length ? startup : ['Unchanged'],Boolean(startup.length));
  add('SSH access','access',sshAccessReview(recipe.ssh_access),Boolean(recipe.ssh_access));
  add('Mounts','mounts',[{auto:'Use filesystem UUIDs for local mounts',labels:'Prefer unique existing labels; use verified UUIDs where unavailable',preserve:'Keep current mount references'}[recipe.mount_policy],...(recipe.files.some(file=>file.path==='/etc/fstab')?['Apply manual fstab edits before the mount policy']:[])],recipe.mount_policy!=='preserve'||recipe.files.some(file=>file.path==='/etc/fstab'));
  const boot = [recipe.boot_migration ? `Migrate BIOS to UEFI; requested ESP ${recipe.boot_migration.esp_size_mib} MiB` : 'Keep existing firmware arrangement'];
  if (recipe.kernel_default) boot.push(`Default kernel: ${recipe.kernel_default}`);
  if (recipe.kernel_args) boot.push(`Kernel arguments: ${recipe.kernel_args}`);
  if (recipe.packages_install.length) boot.push(`Install: ${recipe.packages_install.join(', ')}`);
  if (recipe.packages_remove.length) boot.push(`Remove: ${recipe.packages_remove.join(', ')}`);
  if (recipe.rebuild_initramfs) boot.push('Rebuild initramfs');
  if (recipe.regenerate_grub) boot.push('Regenerate GRUB configuration');
  boot.push(...recipe.files.filter(file => /\/modules-load\.d\/|\/modprobe\.d\//.test(file.path)).map(file => `Edit ${file.path}`));
  add('Boot and kernel','boot',boot,Boolean(recipe.boot_migration || recipe.kernel_default || recipe.kernel_args || recipe.packages_install.length || recipe.packages_remove.length || recipe.rebuild_initramfs || recipe.regenerate_grub || recipe.allow_network || recipe.files.some(file => /\/modules-load\.d\/|\/modprobe\.d\//.test(file.path))));
  add('Destination','export',[profiles[recipe.target].label,`Output: ${recipe.output_format.toUpperCase()}`,recipe.sparsify ? 'Reclaim unused space' : 'Keep unused blocks',...(recipe.output_format === 'qcow2' ? [recipe.compress ? 'Compress QCOW2 output' : 'Uncompressed QCOW2 output'] : [])]);
  if(recipe.platform_migration) { const platform=recipe.platform_migration;add('Hardware compatibility','export',[platform.strategy==='preserve'?'Preserve & validate · hardware settings unchanged':'Reconfigure hardware settings',platform.source==='unknown'?`Destination: ${platform.target==='vm'?'Virtual machine':'Bare metal'}; previous platform unspecified`:`${platform.source==='vm'?'Virtual machine':'Bare metal'} → ${platform.target==='vm'?'Virtual machine':'Bare metal'}`,`Boot: ${platform.boot_attachment}; network: ${platform.network_attachment==='accelerated'?'Accelerated PV':platform.network_attachment}`,...(platform.nic_driver?[platform.nic_driver==='auto'?'NIC drivers: automatic available bundle':`NIC driver: ${platform.nic_driver}`]:[]),...(platform.target==='bare_metal'?['Experimental · OCI bare-metal BYOI is unsupported']:[])]); }
  if (recipe.target === 'oci') {
    const firmware = recipe.oci?.capabilities?.['Compute.Firmware'];
    add('OCI compatibility','oci',recipe.oci ? [`Apply ${Object.keys(recipe.oci.capabilities).length} capability settings`,...(firmware ? [`Preferred firmware: ${firmware.default_value}; allowed: ${(firmware.values || [firmware.default_value]).join(', ')}`] : []),recipe.oci.guest.prepare ? 'Prepare the guest for selected capabilities' : 'Validate existing guest preparation'] : ['Disabled'],Boolean(recipe.oci));
  }
  panel.innerHTML = `<div class="wizard-review-grid">${cards.join('')}</div>${unchanged.length ? `<details class="editor-disclosure" data-disclosure="review-unchanged"${unchangedOpen?' open':''}><summary>Unchanged settings <span class="disclosure-meta">${unchanged.length} sections</span></summary><div class="details-content wizard-review-grid">${unchanged.join('')}</div></details>` : ''}${recipe.files.length ? `<details class="wizard-file-review"><summary>Review ${recipe.files.length} changed configuration file${recipe.files.length === 1 ? '' : 's'}</summary>${recipe.files.map(file => `<h4><code>${esc(file.path)}</code></h4><pre class="wizard-file-content">${esc(file.content)}</pre>`).join('')}</details>` : ''}<p class="validation-note">Build checks the plans again and creates a new image.</p>`;
}
function wizardRenderResult() {
  const panel = $('#panel-result'); if (!panel) return;
  const session = wizardSession(), job = state.jobs.find(item => item.id === session.jobId);
  const artifact = job?.result?.artifact_id ? state.artifacts.find(item => item.id === job.result.artifact_id) : null;
  const upload = state.jobs.find(item => item.id === session.uploadId);
  const signature = JSON.stringify([state.selected,session.jobId,job,artifact,session.uploadId,upload]);
  if (panel.dataset.signature === signature) return;
  panel.dataset.signature = signature;
  const logOpen = $('.wizard-job-details',panel)?.open, exportOpen = $('.wizard-export-details',panel)?.open;
  const logScroll = $('.job-log',panel)?.scrollTop || 0;
  const status = job?.status || 'queued';
  const title = status === 'succeeded' ? 'Your image is ready' : status === 'failed' ? 'The build needs attention' : status === 'running' ? 'Building your image' : 'Build queued';
  panel.innerHTML = `<div class="wizard-result"><div class="wizard-result-heading"><span class="large-icon">${icon(status === 'succeeded' ? 'check' : status === 'failed' ? 'info' : 'activity')}</span><div><h3>${title}</h3><p>${esc(wizardImage()?.name || 'Source image')}</p></div>${badge(status)}</div>${status === 'failed' ? `<div class="notice error" role="alert">${esc(job?.error || 'The build failed. Review the log and update your settings before trying again.')}</div>` : status === 'succeeded' ? '' : '<div class="wizard-result-progress" role="status"><progress aria-label="Image build in progress"></progress><p>Processing in the background. You can return to this step anytime.</p></div>'}${artifact ? `<div class="wizard-result-actions"><a class="button primary" href="/api/artifacts/${encodeURIComponent(artifact.id)}/download" download>${icon('download')}Download image</a><button type="button" class="button secondary" data-s3="${esc(artifact.id)}" data-wizard-s3="${esc(state.selected)}">${icon('upload')}Upload to S3</button>${artifact.oci_config ? `<a class="button secondary" href="/api/artifacts/${encodeURIComponent(artifact.id)}/oci-bundle" download>OCI configuration</a>` : ''}</div><details class="editor-disclosure wizard-export-details"><summary>Export details <span class="disclosure-meta">${esc(artifact.format?.toUpperCase())} · ${bytes(artifact.size)}</span></summary><div class="details-content"><dl class="detail-list"><div><dt>Output format</dt><dd>${esc(artifact.format?.toUpperCase())}</dd></div><div><dt>File size</dt><dd>${bytes(artifact.size)}</dd></div><div><dt>SHA-256</dt><dd><code>${esc(artifact.sha256)}</code></dd></div></dl><a class="button secondary small" href="/api/artifacts/${encodeURIComponent(artifact.id)}/manifest" download>Download manifest</a></div></details>` : status === 'succeeded' ? '<p class="muted">Loading export details…</p>' : ''}${upload ? `<div class="wizard-upload-status" role="status"><h4>S3 upload ${esc(upload.status)}</h4>${upload.error ? `<p class="notice error">${esc(upload.error)}</p>` : `<p>${upload.status === 'succeeded' ? 'Upload completed successfully.' : 'Transferring to S3…'}</p>`}</div>` : ''}<details class="wizard-job-details"><summary>Build log</summary><pre class="job-log">${esc((job?.logs || []).join('\n') || 'Waiting for the image engine…')}</pre></details><div class="wizard-result-actions"><button type="button" class="button secondary" data-wizard-action="review">${status === 'failed' ? 'Review & retry' : 'Back to review'}</button><button type="button" class="button ghost" data-view="jobs">All activity</button></div></div>`;
  $('.wizard-result',panel).dataset.status = status;
  $('.wizard-job-details',panel).open = Boolean(logOpen);
  if ($('.wizard-export-details',panel)) $('.wizard-export-details',panel).open = Boolean(exportOpen);
  $('.job-log',panel).scrollTop = logScroll;
}
function wizardBuildQueued(imageId,jobId) {
  const session = wizardSession(imageId); session.jobId = jobId; session.completedJobId = null; session.uploadId = null; session.step = 'result';
  if (!session.visited.includes('result')) session.visited.push('result');
  if (state.selected === imageId) { setView('images'); wizardShowStep('result',{focus:true}); }
}
function wizardUploadQueued(imageId,jobId) {
  wizardSession(imageId).uploadId = jobId;
  if (state.selected === imageId) { setView('images'); wizardShowStep('result',{focus:true}); }
}
function wizardImported(imageId,jobId) {
  const session = wizardSession(imageId); session.step = 'overview'; session.visited = ['source','overview']; session.importJobId = jobId;
}

document.addEventListener('click',event => {
  const button = event.target.closest('button'); if (!button || button.disabled) return;
  if (button.dataset.wizardStep) { event.preventDefault(); wizardGo(button.dataset.wizardStep); }
  if (button.dataset.wizardAction === 'next') wizardNext();
  if (button.dataset.wizardAction === 'back') wizardBack();
  if (button.dataset.wizardAction === 'review') wizardShowStep('review',{focus:true});
});
window.addEventListener('resize',() => {
  if (document.getElementById('wizard-chrome')) wizardUpdate();
});
