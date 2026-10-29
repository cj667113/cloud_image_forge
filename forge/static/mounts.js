'use strict';

const mountPreviewState={requestId:0,scheduled:0,pending:null};
function renderMountPolicy() {
  return `<div class="mount-policy"><label class="field mount-policy-choice" for="mount-policy"><span>Mount references ${helpHint('UUIDs are preserved across copies and supported rebuilds. Prefer labels uses only existing, unique filesystem labels and falls back to verified UUIDs. No labels or UUIDs are created. Network, bind and virtual mounts keep their sources.','Mount references')}</span><select id="mount-policy"><option value="auto">UUIDs · automatic</option><option value="labels">Prefer labels</option><option value="preserve">Keep current</option></select></label><span class="mount-policy-summary" id="mount-policy-summary">Recommended</span></div><div id="mount-plan-error" class="notice error" role="alert" hidden></div><div id="mount-plan" class="studio-plan"></div>`;
}
function getMountPolicy() { return $('#mount-policy')?.value||($('#mount-policy-auto')?.checked===false?'preserve':'auto'); }
function mountPreviewSignature() {
  const image=studioImage();
  return JSON.stringify([image?.id,image?.inspected_at||image?.updated_at,state.authGeneration,getMountPolicy(),$('[data-file="/etc/fstab"]')?.value]);
}
function mountTextEdited() {
  const field=$('[data-file="/etc/fstab"]');
  return Boolean(field&&field.value!==(studioImage()?.inspection?.files?.['/etc/fstab']||''));
}
function mountPreviewMemo() { return studioSession().mountPolicies?.[getMountPolicy()]; }
function updateMountPolicy() {
  const summary=$('#mount-policy-summary');
  if(summary)summary.textContent={auto:'Recommended',labels:'UUID fallback',preserve:'No automatic changes'}[getMountPolicy()];
  renderMountPreview();
  if(getMountPolicy()==='labels'&&!mountTextEdited()&&!currentMountPreview()&&mountPreviewMemo()?.signature!==mountPreviewSignature())scheduleMountPreview();
}
function scheduleMountPreview() {
  const scheduled=++mountPreviewState.scheduled;
  setTimeout(()=>{if(scheduled===mountPreviewState.scheduled)requestMountPreview();},0);
}
async function requestMountPreview(force=false) {
  if(!$('#mount-plan')||getMountPolicy()==='preserve'||mountTextEdited())return;
  const signature=mountPreviewSignature(),policy=getMountPolicy(),imageId=state.selected,session=studioSession();
  if(mountPreviewState.pending===signature||(!force&&session.mountPolicies?.[policy]?.signature===signature))return;
  const requestId=++mountPreviewState.requestId;
  mountPreviewState.pending=signature;renderMountPreview();
  try {
    const plan=await api(`/images/${encodeURIComponent(imageId)}/mounts/plan`,{method:'POST',body:JSON.stringify({mount_policy:policy})});
    if(requestId!==mountPreviewState.requestId||signature!==mountPreviewSignature())return;
    session.mountPolicies??={};session.mountPolicies[policy]={signature,plan};
  }catch(error){
    if(requestId===mountPreviewState.requestId&&signature===mountPreviewSignature()){
      session.mountPolicies??={};session.mountPolicies[policy]={signature,error:errorText(error)};
    }
  }finally{
    if(requestId===mountPreviewState.requestId){mountPreviewState.pending=null;if(signature===mountPreviewSignature())renderMountPreview();}
  }
}
function mountChangeList(changes=[]) {
  return `<ul class="mount-change-list">${changes.map(change=>`<li><div><strong>${esc(change.mountpoint||'Mount')}</strong><span>${esc(change.from||'')} → <code>${esc(change.to||'')}</code></span></div>${change.fallback_reason?helpHint(change.fallback_reason,'UUID fallback'):change.reason?helpHint(change.reason,'Mount change reason'):''}</li>`).join('')}</ul>`;
}
function currentMountPreview() {
  if(mountTextEdited())return null;
  const memo=mountPreviewMemo();
  if(memo?.signature===mountPreviewSignature())return memo.plan||null;
  if(getMountPolicy()!=='auto')return null;
  const inspection=studioImage()?.inspection,standalone=inspection?.mount_reconciliation,platform=inspection?.platform?.fstab;
  return standalone||(typeof platform?.ready==='boolean'?platform:null);
}
function renderMountPreview() {
  const panel=$('#mount-plan');if(!panel)return;
  const plan=currentMountPreview(),policy=getMountPolicy(),edited=mountTextEdited(),memo=mountPreviewMemo(),signature=mountPreviewSignature(),pending=mountPreviewState.pending===signature,error=memo?.signature===signature?memo.error:null;
  const rendering=JSON.stringify([signature,plan,edited,pending,error]);if(panel.dataset.signature===rendering)return;panel.dataset.signature=rendering;
  if(policy==='preserve'){panel.innerHTML='<p class="storage-note">Mount references stay unchanged unless edited below.</p>';notice('#mount-plan-error','');return;}
  notice('#mount-plan-error',error||(plan?.errors||[]).join(' '));
  if(!plan){
    panel.innerHTML=edited?'<p class="storage-note">Manual fstab edits are verified against the disk during build.</p>':pending?'<p class="storage-note" role="status">Checking mount references…</p>':error?'<button type="button" class="button secondary small" data-mount-action="retry">Retry preview</button>':policy==='labels'?'<p class="storage-note" role="status">Preparing label preview…</p>':'<p class="storage-note">References are verified during build. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh inspection</button> to preview them.</p>';
    return;
  }
  const changes=plan.changes||[],fallbacks=(plan.entries||[]).filter(entry=>entry.fallback_reason),labelCount=(plan.entries||[]).filter(entry=>entry.reference_kind==='label').length;
  const notes=(plan.warnings||[]).filter(note=>!fallbacks.some(entry=>note===`${entry.mountpoint}: ${entry.fallback_reason}`));
  panel.innerHTML=`<div class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${!plan.ready?'Resolve mount references':changes.length?`${changes.length} mount ${changes.length===1?'update':'updates'} planned`:'Mount references are consistent'}</strong></div>${policy==='labels'?`<div class="mount-reference-counts"><span>${labelCount} ${labelCount===1?'label':'labels'}</span>${fallbacks.length?`<span>${fallbacks.length} UUID ${fallbacks.length===1?'fallback':'fallbacks'} ${helpHint('Some filesystems have no usable unique label. Their verified UUIDs are used instead. Open Reference choices for details.','UUID fallback')}</span>`:''}</div>`:''}${changes.length?`<details class="editor-disclosure"><summary>Planned mount changes <span class="disclosure-meta">${changes.length}</span></summary><div class="details-content">${mountChangeList(changes)}</div></details>`:''}${policy==='labels'&&fallbacks.length?`<details class="editor-disclosure"><summary>Reference choices <span class="disclosure-meta">${fallbacks.length}</span></summary><div class="details-content"><ul class="mount-reference-fallbacks">${fallbacks.map(entry=>`<li><strong>${esc(entry.mountpoint||'Mount')}</strong><span>${esc(entry.fallback_reason)}</span></li>`).join('')}</ul></div></details>`:''}${plan.boot_update_required||plan.boot_reference_check_required?`<p class="storage-note">Boot references will be rechecked.${helpHint('Critical mount repairs also require verified bootloader and initramfs references before export.','Root boot references')}</p>`:''}${!plan.ready&&/refresh/i.test((plan.errors||[]).join(' '))?'<button type="button" class="button secondary small" data-action="refresh-inspection">Refresh inspection</button>':''}${notes.length?`<details class="editor-disclosure"><summary>Mount notes <span class="disclosure-meta">${notes.length}</span></summary><div class="details-content"><ul>${notes.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div></details>`:''}`;
}
function validateMountPolicy() {
  if(getMountPolicy()==='preserve'||mountTextEdited())return;
  const plan=currentMountPreview(),memo=mountPreviewMemo();
  if(getMountPolicy()==='labels'&&!plan)throw editorError(memo?.error||'Wait for the mount reference preview, then try again.','#mount-policy');
  if(plan&&!plan.ready)throw editorError((plan.errors||[]).join(' ')||'Review fstab or keep the current references.','#mount-policy');
}
function renderMountIdentifiers(partitions) {
  const inventory=studioImage()?.inspection?.mount_reconciliation?.filesystems||[];
  return `<div class="table-wrap"><table><thead><tr><th>Device</th><th>Mount</th><th>Label</th><th>UUID</th></tr></thead><tbody>${partitions.map(part=>`<tr><td><code>${esc(part.device)}</code></td><td>${esc(part.mountpoint||'—')}</td><td><code>${esc(inventory.find(fs=>fs.device===part.device)?.label||part.label||'—')}</code></td><td><code>${esc(part.uuid||'—')}</code></td></tr>`).join('')}</tbody></table></div>`;
}
document.addEventListener('change',event=>{if(['mount-policy','mount-policy-auto'].includes(event.target.id)){updateMountPolicy();invalidateStudioPlans('platform');invalidateStudioPlans('storage');}});
document.addEventListener('input',event=>{if(event.target.dataset.file==='/etc/fstab')updateMountPolicy();});
document.addEventListener('click',event=>{if(event.target.closest('[data-mount-action="retry"]'))requestMountPreview(true);});
