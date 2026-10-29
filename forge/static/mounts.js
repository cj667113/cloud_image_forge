'use strict';

function renderMountPolicy() {
  return `<div class="mount-policy"><label class="check-field"><input type="checkbox" id="mount-policy-auto" checked><span>Use filesystem UUIDs for local mounts</span>${helpHint('Resolve local mount identifiers against inspected filesystems. Network, bind and virtual mounts keep their existing sources. No filesystem UUIDs are regenerated; ambiguous devices require review.','Automatic mount identifiers')}</label><span class="mount-policy-summary" id="mount-policy-summary">Automatic</span></div><div id="mount-plan-error" class="notice error" role="alert" hidden></div><div id="mount-plan" class="studio-plan"></div>`;
}
function getMountPolicy() { return $('#mount-policy-auto')?.checked ? 'auto' : 'preserve'; }
function updateMountPolicy() {
  const summary=$('#mount-policy-summary');if(summary)summary.textContent=getMountPolicy()==='auto'?'Automatic':'Keep current identifiers';
  renderMountPreview();
}
function mountChangeList(changes=[]) {
  return `<ul class="mount-change-list">${changes.map(change=>`<li><div><strong>${esc(change.mountpoint||'Mount')}</strong><span>${esc(change.from||'')} → <code>${esc(change.to||'')}</code></span></div>${change.reason?helpHint(change.reason,'Mount change reason'):''}</li>`).join('')}</ul>`;
}
function currentMountPreview() {
  const image=studioImage(),field=$('[data-file="/etc/fstab"]');
  if(!field||field.value!==(image?.inspection?.files?.['/etc/fstab']||''))return null;
  const standalone=image?.inspection?.mount_reconciliation,platform=image?.inspection?.platform?.fstab;
  return standalone||(typeof platform?.ready==='boolean'?platform:null);
}
function renderMountPreview() {
  const panel=$('#mount-plan');if(!panel)return;
  const plan=currentMountPreview(),policy=getMountPolicy(),edited=$('[data-file="/etc/fstab"]')?.value!==($('[data-file="/etc/fstab"]')?.defaultValue||'');
  const signature=JSON.stringify([policy,plan,edited]);if(panel.dataset.signature===signature)return;panel.dataset.signature=signature;
  if(policy==='preserve'){panel.innerHTML='<p class="storage-note">Mount identifiers stay unchanged unless edited below.</p>';notice('#mount-plan-error','');return;}
  if(!plan){panel.innerHTML=edited?'<p class="storage-note">Manual fstab edits will be checked against the disk during build.</p>':'<p class="storage-note">Mount identifiers are checked during build. <button type="button" class="button ghost small" data-action="refresh-inspection">Refresh inspection</button> to preview them.</p>';notice('#mount-plan-error','');return;}
  notice('#mount-plan-error',(plan.errors||[]).join(' '));
  const changes=plan.changes||[];
  panel.innerHTML=`<div class="plan-status ${plan.ready?'ready':'blocked'}">${icon(plan.ready?'check':'info')}<strong>${!plan.ready?'Resolve mount identifiers':changes.length?`${changes.length} mount ${changes.length===1?'update':'updates'} planned`:'Local mount identifiers are consistent'}</strong></div>${changes.length?`<details class="editor-disclosure"><summary>Planned mount changes <span class="disclosure-meta">${changes.length}</span></summary><div class="details-content">${mountChangeList(changes)}</div></details>`:''}${plan.boot_update_required||plan.boot_reference_check_required?`<p class="storage-note">Boot references will be rechecked.${helpHint('Changing a root filesystem reference can also require bootloader or initramfs updates. The build verifies the resulting references before export.','Root boot references')}</p>`:''}${plan.warnings?.length?`<details class="editor-disclosure"><summary>Mount notes <span class="disclosure-meta">${plan.warnings.length}</span></summary><div class="details-content"><ul>${plan.warnings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div></details>`:''}`;
}
function validateMountPolicy() {
  const plan=currentMountPreview();
  if(getMountPolicy()==='auto'&&plan&&!plan.ready)throw editorError((plan.errors||[]).join(' ')||'The mount identifiers could not be resolved. Review fstab or select Keep current identifiers.','#mount-policy-auto');
}
document.addEventListener('change',event=>{if(event.target.id==='mount-policy-auto'){updateMountPolicy();invalidateStudioPlans('platform');invalidateStudioPlans('storage');}});
document.addEventListener('input',event=>{if(event.target.dataset.file==='/etc/fstab')renderMountPreview();});
