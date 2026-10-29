'use strict';

const destinationState={catalog:null,error:null,requestId:0,scheduledRequest:0};
async function loadDestinationCatalog() {
  const authGeneration=state.authGeneration,requestId=destinationState.catalogRequest=(destinationState.catalogRequest||0)+1;
  const current=()=>authGeneration===state.authGeneration&&requestId===destinationState.catalogRequest;
  try{const result=await api('/destinations/catalog');if(!Array.isArray(result.profiles))throw new Error('Destination profiles are unavailable.');if(current()){destinationState.catalog=result;destinationState.error=null;}}
  catch(error){if(current())destinationState.error=errorText(error);}
}
function destinationProfiles() {
  const arch=sourceArchitecture();
  return (destinationState.catalog?.profiles||[]).filter(profile=>!['aarch64','x86_64'].includes(arch)||profile.architecture===arch);
}
function automaticDestinationProvider() { return ($('input[name="target"]:checked')?.value||'oci')==='oci'?'oci':'generic'; }
function automaticDestinationLabel() {
  const arch=sourceArchitecture();
  return `Automatic · ${automaticDestinationProvider()==='oci'?'OCI':'general'} ${arch==='aarch64'?'ARM64 ':arch==='x86_64'?'x86_64 ':''}VM`;
}
function renderDestinationProfile() {
  const profiles=destinationProfiles(),arch=sourceArchitecture();
  return `<label class="field destination-profile-field">Destination profile<select id="destination-profile"><option value="auto" selected>${esc(automaticDestinationLabel())}</option>${[['vm','Virtual machines'],['bare_metal','Bare metal']].map(([kind,label])=>`<optgroup label="${label}">${profiles.filter(profile=>profile.target===kind).map(profile=>`<option value="${esc(profile.id)}">${esc(profile.label)}${!arch?` · ${esc(profile.architecture)}`:''}</option>`).join('')}</optgroup>`).join('')}<option value="custom">Custom settings</option></select>${helpHint('Profiles choose destination attachments from the catalog, using the inspected CPU architecture. They do not infer where the source last ran or prove it will boot. Custom settings keep explicit hardware overrides.','Destination profiles')}</label><p class="destination-profile-status" id="destination-profile-loading" role="status" hidden>Applying destination defaults…</p><div class="destination-profile-actions"><button type="button" class="button secondary small" id="destination-profile-apply" data-destination-action="apply" hidden>Reapply profile</button></div><div id="destination-profile-summary" class="destination-profile-summary" hidden></div><div id="destination-downloads" class="destination-downloads" hidden><label class="check-field"><input type="checkbox" id="destination-allow-downloads"><span>Allow required downloads</span></label><span id="destination-downloads-help"></span></div><div id="destination-profile-error" class="notice error" role="alert" hidden></div><div id="destination-profile-warnings" hidden></div>${destinationState.error?`<div class="notice warning">Destination catalog unavailable. Use Custom settings or retry.<button type="button" class="button ghost small" data-destination-action="reload">Retry</button></div>`:''}`;
}
function selectedDestinationProfileId() {
  const value=$('#destination-profile')?.value;
  return value==='auto'?`${automaticDestinationProvider()}:${sourceArchitecture()}:vm`:value==='custom'?null:value;
}
function destinationSelection() {
  return {profile_id:selectedDestinationProfileId(),source:$('#platform-source').value,strategy:$('#platform-strategy').value,nic_driver:$('#platform-nic').value||null};
}
function applyDestinationNicDefault() {
  const profile=destinationState.catalog?.profiles.find(item=>item.id===selectedDestinationProfileId()),input=$('#platform-nic');
  if(input&&!input.value&&profile?.nic_driver&&[...input.options].some(option=>option.value===profile.nic_driver))input.value=profile.nic_driver;
}
function destinationOciIssue(defaults) {
  if(!defaults)return '';
  const missing=Object.entries(defaults.capabilities||{}).filter(([key,setting])=>{
    const node=$$('[data-oci-default]').find(input=>input.dataset.ociDefault===key);
    if(!node)return true;
    if(typeof setting.default_value==='boolean')return node.type!=='checkbox'||(node.disabled&&node.checked!==setting.default_value);
    return !node.options||![...node.options].some(option=>option.value===JSON.stringify(setting.default_value));
  });
  return missing.length?`This OCI schema cannot represent ${missing.map(([key,setting])=>`${setting.default_value} for ${key}`).join(', ')}. Load a compatible regional schema or use Custom settings. Existing OCI choices were kept.`:'';
}
function applyDestinationOci(defaults,strategy) {
  if(!defaults)return;
  for(const [key,setting] of Object.entries(defaults.capabilities||{})) {
    const node=$$('[data-oci-default]').find(input=>input.dataset.ociDefault===key);if(node.type==='checkbox')node.checked=setting.default_value;else node.value=JSON.stringify(setting.default_value);
    $$('[data-oci-allowed]').filter(input=>input.dataset.ociAllowed===key).forEach(input=>input.checked=(setting.values||[setting.default_value]).includes(JSON.parse(input.value)));
    if(key==='Compute.Firmware'){state.ociFirmwareEdited=true;if($('#oci-firmware-confirm'))$('#oci-firmware-confirm').checked=true;}
  }
  $('#oci-launch-mode').value=defaults.import_options.launch_mode;
  for(const [field,key] of [['oci-operating-system','operating_system'],['oci-os-version','operating_system_version']])$(`#${field}`).value=defaults.import_options[key]||'';
  $('#oci-shapes').innerHTML='';
  // Explicit profile selection replaces the advertised shape list with that destination.
  for(const shape of defaults.import_options.shape_compatibility||[]){addOciShape(false);const row=$$('.oci-shape-row').at(-1);$('[data-shape-field="shape"]',row).value=shape.shape;}
  studioSession().destinationOciPrepare={profileId:selectedDestinationProfileId(),prepare:true};
  $('#oci-enabled').checked=true;$('#oci-prepare').checked=strategy!=='preserve';markOciChanged();
}
function renderDestinationIssues(issues) {
  notice('#destination-profile-error',issues.join(' '));
  if(issues.length>1)$('#destination-profile-error').innerHTML=`<strong>Review these destination requirements</strong><ul class="destination-issue-list">${issues.map(issue=>`<li>${esc(issue)}</li>`).join('')}</ul>`;
}
function setDestinationLoading(loading) {
  $('#destination-profile-loading').hidden=!loading;
  $('#destination-profile-summary').setAttribute('aria-busy',String(loading));
}
function renderDestinationResult(result) {
  const profile=result?.profile,summary=$('#destination-profile-summary');if(!summary)return;
  summary.hidden=!profile;
  if(profile){const attachment={paravirtualized:'PV',accelerated:'Accelerated PV',vfio:'Physical NIC',iscsi:'Firmware iSCSI'};summary.innerHTML=`<span><strong>${esc(architectureName(profile.architecture))}</strong></span><span>${profile.target==='bare_metal'?'Bare metal':'Virtual machine'}</span><span>${esc(attachment[profile.boot_attachment]||profile.boot_attachment)} boot</span><span>${esc(attachment[profile.network_attachment]||profile.network_attachment)} network</span>`;}
  const blockers=[...(result?.blockers||[]),...(result?.schema_error?[result.schema_error]:[])];renderDestinationIssues(blockers);$('#destination-profile-apply').hidden=!result?.schema_error;
  const warnings=$('#destination-profile-warnings'),notesOpen=$('details',warnings)?.open??state.editorDrafts[state.selected]?.disclosures?.['destination-notes'];warnings.hidden=!result?.warnings?.length;warnings.innerHTML=result?.warnings?.length?`<details class="editor-disclosure" data-disclosure="destination-notes"${notesOpen?' open':''}><summary>Profile notes <span class="disclosure-meta">${result.warnings.length}</span></summary><div class="details-content"><ul>${result.warnings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div></details>`:'';
  updateDestinationDownloads(result);
}
function updateDestinationDownloads(result=studioSession().destination) {
  const container=$('#destination-downloads');if(!container)return;
  const required=result?.required_packages||[];
  container.hidden=!$('#platform-enabled').checked||$('#platform-strategy').value==='preserve'||$('#destination-profile').value==='custom'||!required.length;
  $('#destination-allow-downloads').checked=$('#allow-network').checked&&$('#platform-install-packages').checked&&(result?.profile?.provider!=='oci'||$('#oci-install-packages').checked);
  const help=$('#destination-downloads-help'),signature=JSON.stringify(required);
  if(help.dataset.packages!==signature){help.dataset.packages=signature;help.innerHTML=required.length?helpHint(`Required packages: ${required.join(', ')}. Allows guest network access and installation from guest repositories for hardware and OCI preparation.`,'Required downloads'):'';}
}
function setDestinationDownloads(allowed) {
  for(const id of ['allow-network','oci-allow-network','migration-allow-network','platform-allow-network','platform-install-packages','oci-install-packages'])$(`#${id}`).checked=allowed;
  invalidateStudioPlans('platform');if($('#boot-migration-enabled').checked)invalidateMigrationPlan();updatePlatformStudio();updateDisclosureSummaries();updateDestinationDownloads();
}
function destinationConfigurationIssue() {
  if(!$('#platform-enabled')?.checked||$('#destination-profile')?.value==='custom')return '';
  const session=studioSession();if(session.destinationPending)return 'Wait for the destination defaults to finish loading.';
  if(!destinationState.catalog?.profiles?.some(profile=>profile.id===selectedDestinationProfileId()))return 'The destination profile is unavailable for this catalog. Retry the catalog or use Custom settings.';
  const result=session.destination;
  if(!result||result.selection!==JSON.stringify(destinationSelection())||result.snapshot!==studioInspectionKey())return 'Apply the destination profile before checking compatibility.';
  const issue=[...(result.blockers||[]),...(result.schema_error?[result.schema_error]:[])];return issue.join(' ')||(result.ready!==true?'Destination defaults could not be resolved. Reapply the profile or use Custom settings.':'');
}
async function resolveDestinationProfile({apply=true,syncOci=true}={}) {
  if(!$('#platform-enabled')?.checked)return;
  if($('#destination-profile').value==='custom'){useCustomDestination();return;}
  const imageId=state.selected,revision=state.editorRevision,selection=destinationSelection(),snapshot=studioInspectionKey(),session=studioSession(),requestId=++destinationState.requestId;
  session.destinationPending=requestId;notice('#destination-profile-error','');setDestinationLoading(true);
  try{
    const result=await api(`/images/${encodeURIComponent(imageId)}/destination/resolve`,{method:'POST',body:JSON.stringify(selection)});
    if(state.selected!==imageId||state.editorRevision!==revision||studioInspectionKey()!==snapshot||session.destinationPending!==requestId)return;
    if(!result||typeof result.ready!=='boolean'||!Array.isArray(result.blockers))throw new Error('The destination resolver returned an invalid response. Retry or use Custom settings.');
    const config=result.platform_migration;
    if(config&&apply){
      for(const [key,id] of Object.entries({source:'platform-source',target:'platform-target',boot_attachment:'platform-boot',network_attachment:'platform-network',nic_driver:'platform-nic'}))$(`#${id}`).value=config[key]||'';
      if(result.profile?.provider==='oci'){$('#target-oci').checked=true;updateExport();}
      result.schema_error=destinationOciIssue(result.oci_defaults);
      if(!result.schema_error&&syncOci)applyDestinationOci(result.oci_defaults,selection.strategy);
      else if(!result.schema_error&&result.oci_defaults&&session.destinationOciPrepare?.profileId===selection.profile_id)$('#oci-prepare').checked=selection.strategy!=='preserve'&&session.destinationOciPrepare.prepare;
      if(selection.strategy==='preserve')preservePlatformConfiguration();
      state.editorRevision++;invalidateStudioPlans('platform');
    }
    result.selection=JSON.stringify(destinationSelection());result.snapshot=snapshot;session.destination=result;renderDestinationResult(result);updatePlatformStudio();
  }catch(error){if(state.selected===imageId&&state.editorRevision===revision&&studioInspectionKey()===snapshot){notice('#destination-profile-error',errorText(error));$('#destination-profile-apply').hidden=false;}}
  finally{if(session.destinationPending===requestId){delete session.destinationPending;if(state.selected===imageId){setDestinationLoading(false);syncDestinationEditor();wizardUpdate();}}}
}
function syncDestinationEditor() {
  if(!$('#destination-profile'))return;
  $('#destination-profile option[value="auto"]').textContent=automaticDestinationLabel();
  const result=studioSession().destination;if(result?.selection===JSON.stringify(destinationSelection())&&result.snapshot===studioInspectionKey())renderDestinationResult(result);
  else if($('#platform-enabled').checked&&$('#destination-profile').value!=='custom'){$('#destination-profile-apply').hidden=false;if(!$('#destination-profile-error').textContent)notice('#destination-profile-error','Reapply the profile to check its defaults against this inspection.');}
  $('#platform-advanced').open=$('#destination-profile').value==='custom'||$('#platform-advanced').open;
}
function useCustomDestination() {
  if(!$('#destination-profile'))return;
  $('#destination-profile').value='custom';delete studioSession().destination;delete studioSession().destinationPending;renderDestinationResult(null);setDestinationLoading(false);$('#platform-advanced').open=true;
}
function scheduleDestinationResolution(options) {
  const imageId=state.selected,requestId=++destinationState.scheduledRequest;
  // Native events can run microtasks between listeners; capture the revision after the event finishes.
  setTimeout(()=>{if(requestId===destinationState.scheduledRequest&&imageId===state.selected)resolveDestinationProfile(options);},0);
}
document.addEventListener('change',event=>{
  const input=event.target;
  if(input.id==='destination-allow-downloads')setDestinationDownloads(input.checked);
  if(['allow-network','oci-allow-network','migration-allow-network','platform-allow-network','platform-install-packages','oci-install-packages','platform-strategy','platform-enabled'].includes(input.id))queueMicrotask(()=>updateDestinationDownloads());
  if(input.name==='target'){
    $('#destination-profile option[value="auto"]').textContent=automaticDestinationLabel();
    if($('#destination-profile').value==='auto'&&$('#platform-enabled').checked)scheduleDestinationResolution({syncOci:studioSession().destinationOciPrepare?.profileId!==selectedDestinationProfileId()});
  }
  if(input.id==='oci-prepare'&&studioSession().destinationOciPrepare?.profileId===selectedDestinationProfileId())studioSession().destinationOciPrepare.prepare=input.checked;
  if(input.id==='destination-profile'){applyDestinationNicDefault();scheduleDestinationResolution();syncDestinationEditor();}
  if(input.id==='platform-enabled'&&input.checked){applyDestinationNicDefault();scheduleDestinationResolution();}
  if(['platform-strategy','platform-source','platform-nic'].includes(input.id)&&$('#destination-profile')?.value!=='custom')scheduleDestinationResolution({syncOci:false});
  if(['platform-target','platform-boot','platform-network'].includes(input.id)){useCustomDestination();syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
});
document.addEventListener('click',async event=>{
  if(event.target.closest('[data-destination-action="apply"]')){resolveDestinationProfile();return;}
  if(!event.target.closest('[data-destination-action="reload"]'))return;
  const imageId=state.selected;await loadDestinationCatalog();if(imageId===state.selected)renderImages(true);
});
