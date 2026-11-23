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
  return (destinationState.catalog?.profiles||[]).filter(profile=>
    !profile.group_id && (!['aarch64','x86_64'].includes(arch) || profile.architecture===arch));
}
function restoreDestinationProfile(select, id) {
  const profiles = destinationState.catalog?.profiles || [];
  const shared = profiles.find(profile => profile.variants?.includes(id) && [...select.options].some(option => option.value === profile.id));
  if (shared) {
    select.value = shared.id;
    updateDestinationVariants(id);
    return;
  }
  if (![...select.options].some(option=>option.value===id)) {
    const member=destinationState.catalog?.profiles.find(profile=>profile.id===id && profile.group_id && profile.architecture===sourceArchitecture());
    if (!member) return;
    const option=new Option(member.label, member.id);
    option.hidden=true;
    select.add(option);
  }
  select.value=id;
  updateDestinationVariants();
}
function automaticDestinationProvider() { return ($('input[name="target"]:checked')?.value||'oci')==='oci'?'oci':'generic'; }
function automaticDestinationLabel() {
  const arch=sourceArchitecture();
  return `Automatic · ${automaticDestinationProvider()==='oci'?'OCI':'general'} ${arch==='aarch64'?'ARM64 ':arch==='x86_64'?'x86_64 ':''}VM`;
}
function renderDestinationProfile() {
  const profiles=destinationProfiles(),arch=sourceArchitecture();
  const groups=[['vm','Virtual machines'],['bare_metal','Bare metal']].map(([target,label])=>{
    const options=profiles.filter(profile=>profile.target===target).map(profile=>
      `<option value="${esc(profile.id)}">${esc(profile.label)}${profile.variants ? ' · Generic' : ''}${!arch?` · ${esc(profile.architecture)}`:''}</option>`);
    return `<optgroup label="${label}">${options.join('')}</optgroup>`;
  });
  return `<label class="field destination-profile-field">Destination profile<select id="destination-profile"><option value="auto" selected>${esc(automaticDestinationLabel())}</option>${groups.join('')}<option value="custom">Custom settings</option></select>${helpHint('Shapes on the same row use the same hardware preparation. For a shared row, choose listed OCI shapes or generic hardware settings. Edit individual shapes under OCI compatibility.','Destination profiles')}</label>
    <label id="destination-variant-field" class="field" hidden>Apply settings<select id="destination-variant"></select></label>
    <p class="destination-profile-status" id="destination-profile-loading" role="status" hidden>Applying destination defaults…</p>
    <div class="destination-profile-actions"><button type="button" class="button secondary small" id="destination-profile-apply" data-destination-action="apply" hidden>Reapply profile</button></div>
    <div id="destination-profile-summary" class="destination-profile-summary" hidden></div><div id="destination-resolved-shapes"></div>
    <div id="destination-profile-error" class="notice error" role="alert" hidden></div><div id="destination-profile-warnings" hidden></div>
    ${destinationState.error?`<div class="notice warning">Destination catalog unavailable. Use Custom settings or retry.<button type="button" class="button ghost small" data-destination-action="reload">Retry</button></div>`:''}`;
}
function updateDestinationVariants(savedId) {
  const profiles = destinationState.catalog?.profiles || [];
  const row = profiles.find(profile => profile.id === $('#destination-profile')?.value);
  const select = $('#destination-variant');
  const choices = (row?.variants || []).map(id => profiles.find(profile => profile.id === id));
  select.replaceChildren();
  $('#destination-variant-field').hidden = !choices.length;
  for (const profile of choices) {
    const label = profile.provider === 'generic' ? 'Generic hardware only' :
      profile.shapes.length ? 'OCI defaults and listed shapes' : 'OCI defaults without shapes';
    select.add(new Option(label, profile.id));
  }
  const preferred = savedId || choices.find(profile => profile.provider === automaticDestinationProvider())?.id;
  if (preferred) select.value = preferred;
}
function selectedDestinationProfileId() {
  const value=$('#destination-profile')?.value;
  return value==='auto'?`${automaticDestinationProvider()}:${sourceArchitecture()}:vm`:value==='custom'?null:($('#destination-variant')?.value || value);
}
function destinationSelection() {
  return {profile_id:selectedDestinationProfileId(),source:$('#platform-source').value,strategy:$('#platform-strategy').value,nic_driver:$('#platform-nic').value||null};
}
function applyDestinationNicDefault() {
  const profile=destinationState.catalog?.profiles.find(item=>item.id===selectedDestinationProfileId()),input=$('#platform-nic');
  if(input&&!input.value&&profile?.nic_driver&&[...input.options].some(option=>option.value===profile.nic_driver))input.value=profile.nic_driver;
}
function destinationOciForRegion(defaults) {
  if (!defaults?.capabilities[ociPvVersionKey]) return defaults;
  const capability = state.ociCatalog?.capabilities.find(item => item.key === ociPvVersionKey);
  const names = defaults.import_options.shape_compatibility.map(row => row.shape);
  const setting = ociPvVersionDefaults(capability, names);
  const capabilities = {...defaults.capabilities};
  if (setting) capabilities[ociPvVersionKey] = setting;
  else delete capabilities[ociPvVersionKey];
  return {...defaults, capabilities};
}
function destinationOciIssue(defaults) {
  if(!defaults)return '';
  const versionIssue = ociPvVersionSchemaError(defaults.import_options.shape_compatibility.map(row => row.shape));
  if (versionIssue) return versionIssue;
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
  studioSession().ociPvVersionEdited = false;
  for(const [key,setting] of Object.entries(defaults.capabilities||{})) {
    setOciCapability(key, setting);
    if(key==='Compute.Firmware'){state.ociFirmwareEdited=true;if($('#oci-firmware-confirm'))$('#oci-firmware-confirm').checked=true;}
  }
  $('#oci-launch-mode').value=defaults.import_options.launch_mode;
  $('#oci-shape-mode').value=defaults.import_options.shape_compatibility_mode||'auto';
  for(const [field,key] of [['oci-operating-system','operating_system'],['oci-os-version','operating_system_version']])$(`#${field}`).value=defaults.import_options[key]||'';
  $('#oci-shapes').innerHTML='';
  // Apply every shape named in the selected row.
  for(const shape of defaults.import_options.shape_compatibility||[]){addOciShape(false);const row=$$('.oci-shape-row').at(-1);$('[data-shape-field="shape"]',row).value=shape.shape;}
  const prepare=typeof defaults.guest?.prepare==='boolean'?defaults.guest.prepare:strategy!=='preserve';
  studioSession().destinationOciPrepare={profileId:selectedDestinationProfileId(),prepare,manual:false};
  $('#oci-enabled').checked=true;$('#oci-prepare').checked=prepare;markOciChanged();
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
  if(profile){const attachment={paravirtualized:'PV',accelerated:'Accelerated PV',vfio:'Physical NIC',iscsi:'Firmware iSCSI'};summary.innerHTML=`<span><strong>${esc(architectureName(profile.architecture))}</strong></span><span>${profile.target==='bare_metal'?'Bare metal':'Virtual machine'}</span><span>${esc(attachment[profile.boot_attachment]||profile.boot_attachment)} boot</span><span>${esc(attachment[profile.network_attachment]||profile.network_attachment)} network</span>${$('#platform-strategy')?.value==='auto'&&result.platform_migration?`<span>Hardware: <strong>${result.platform_migration.strategy==='preserve'?'preserve':'prepare'}</strong></span>`:''}`;}
  const blockers=[...(result?.blockers||[]),...(result?.schema_error?[result.schema_error]:[])];renderDestinationIssues(blockers);$('#destination-profile-apply').hidden=!result?.schema_error;
  const warnings=$('#destination-profile-warnings'),notesOpen=$('details',warnings)?.open??state.editorDrafts[state.selected]?.disclosures?.['destination-notes'];warnings.hidden=!result?.warnings?.length;warnings.innerHTML=result?.warnings?.length?`<details class="editor-disclosure" data-disclosure="destination-notes"${notesOpen?' open':''}><summary>Profile notes <span class="disclosure-meta">${result.warnings.length}</span></summary><div class="details-content"><ul>${result.warnings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div></details>`:'';
}
function applyDestinationPackageRequirements(result,strategy) {
  // A selected profile authorizes only its inspected preparation prerequisites.
  // Do not infer permission from an old checkbox or an unrelated cached plan.
  const required=strategy!=='preserve'&&Array.isArray(result?.required_packages)&&result.required_packages.length>0;
  if($('#platform-install-packages'))$('#platform-install-packages').checked=required;
  if(result?.profile?.provider==='oci'&&$('#oci-install-packages'))$('#oci-install-packages').checked=required&&Boolean($('#oci-prepare')?.checked);
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
      const regionalDefaults = destinationOciForRegion(result.oci_defaults);
      result.schema_error=destinationOciIssue(regionalDefaults);
      if(!result.schema_error&&syncOci)applyDestinationOci(regionalDefaults,config.strategy);
      else if(!result.schema_error&&result.oci_defaults&&session.destinationOciPrepare?.profileId===selection.profile_id) {
        const managed=session.destinationOciPrepare;
        if(!managed.manual)managed.prepare=typeof result.oci_defaults.guest?.prepare==='boolean'?result.oci_defaults.guest.prepare:config.strategy!=='preserve';
        $('#oci-prepare').checked=selection.strategy==='preserve'?false:managed.prepare;
      }
      if(selection.strategy==='preserve')preservePlatformConfiguration();
      applyDestinationPackageRequirements(result,config.strategy);
      state.editorRevision++;invalidateStudioPlans('platform');
    }
    result.selection=JSON.stringify(destinationSelection());result.snapshot=snapshot;session.destination=result;renderDestinationResult(result);updatePlatformStudio();if(syncOci&&!result.schema_error)rememberOciShapeResolution(result.shape_compatibility_resolution);
  }catch(error){if(state.selected===imageId&&state.editorRevision===revision&&studioInspectionKey()===snapshot){notice('#destination-profile-error',errorText(error));$('#destination-profile-apply').hidden=false;}}
  finally{if(session.destinationPending===requestId){delete session.destinationPending;if(state.selected===imageId){setDestinationLoading(false);syncDestinationEditor();wizardUpdate();}}}
}
function syncDestinationEditor() {
  if(!$('#destination-profile'))return;
  $('#destination-profile option[value="auto"]').textContent=automaticDestinationLabel();
  const result=studioSession().destination;if(result?.selection===JSON.stringify(destinationSelection())&&result.snapshot===studioInspectionKey())renderDestinationResult(result);
  else if($('#platform-enabled').checked&&$('#destination-profile').value!=='custom'){$('#destination-profile-apply').hidden=false;if(!$('#destination-profile-error').textContent)notice('#destination-profile-error','Reapply the profile to check its defaults against this inspection.');}
  $('#platform-strategy option[value=auto]').disabled=$('#destination-profile').value==='custom';
  $('#platform-advanced').open=$('#destination-profile').value==='custom'||$('#platform-advanced').open;
}
function useCustomDestination() {
  if(!$('#destination-profile'))return;
  if($('#platform-strategy').value==='auto')$('#platform-strategy').value=studioSession().destination?.platform_migration?.strategy||'reconfigure';
  $('#destination-profile').value='custom';updateDestinationVariants();delete studioSession().destination;delete studioSession().destinationPending;renderDestinationResult(null);setDestinationLoading(false);$('#platform-advanced').open=true;
}
function scheduleDestinationResolution(options) {
  const imageId=state.selected,requestId=++destinationState.scheduledRequest;
  // Native events can run microtasks between listeners; capture the revision after the event finishes.
  setTimeout(()=>{if(requestId===destinationState.scheduledRequest&&imageId===state.selected)resolveDestinationProfile(options);},0);
}
document.addEventListener('change',event=>{
  const input=event.target;
  if(input.name==='target'){
    $('#destination-profile option[value="auto"]').textContent=automaticDestinationLabel();
    const shared = Boolean($('#destination-variant')?.options.length);
    if (shared) {
      const remembered = studioSession().destinationOciPrepare?.profileId;
      const restoreOci = automaticDestinationProvider() === 'oci' && [...$('#destination-variant').options].some(option => option.value === remembered);
      updateDestinationVariants(restoreOci ? remembered : undefined);
    }
    if((shared||$('#destination-profile').value==='auto')&&$('#platform-enabled').checked)scheduleDestinationResolution({syncOci:studioSession().destinationOciPrepare?.profileId!==selectedDestinationProfileId()});
  }
  if(input.id==='oci-prepare'&&studioSession().destinationOciPrepare?.profileId===selectedDestinationProfileId()){studioSession().destinationOciPrepare.prepare=input.checked;studioSession().destinationOciPrepare.manual=true;}
  if(input.id==='destination-profile')updateDestinationVariants();
  if(input.id==='destination-profile'||input.id==='destination-variant'){applyDestinationNicDefault();scheduleDestinationResolution();syncDestinationEditor();}
  if(input.id==='platform-enabled'&&input.checked){applyDestinationNicDefault();scheduleDestinationResolution();}
  if(['platform-strategy','platform-source','platform-nic'].includes(input.id)&&$('#destination-profile')?.value!=='custom')scheduleDestinationResolution({syncOci:false});
  if(['platform-target','platform-boot','platform-network'].includes(input.id)){useCustomDestination();syncOciPlatformChoices();updatePlatformStudio();invalidateStudioPlans('platform');}
});
document.addEventListener('click',async event=>{
  if(event.target.closest('[data-destination-action="apply"]')){resolveDestinationProfile();return;}
  if(!event.target.closest('[data-destination-action="reload"]'))return;
  const imageId=state.selected;await loadDestinationCatalog();if(imageId===state.selected)renderImages(true);
});
