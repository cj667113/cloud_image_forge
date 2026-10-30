'use strict';

const exportsView = {rows:new Map(),open:new Set(),warnings:new Set()};
function exportWarnings(artifact) {
  return [...new Set((artifact.warnings||[]).map(value=>typeof value==='string'?value.trim():JSON.stringify(value)).filter(Boolean))];
}
function exportDate(value) {
  if(!value)return null;const date=new Date(value);if(!Number.isFinite(date.getTime()))return null;
  return {short:date.toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}),full:date.toLocaleString(),iso:date.toISOString()};
}
function exportModel(artifact) {
  const source=state.images.find(image=>image.id===artifact.image_id);
  return {id:artifact.id,name:artifact.name||artifact.filename||'Image export',target:artifact.target,format:artifact.format,size:artifact.size,virtual_size:artifact.virtual_size,sha256:artifact.sha256,created_at:artifact.created_at,image_id:artifact.image_id,source:source?.name||null,oci_config:Boolean(artifact.oci_config),warnings:exportWarnings(artifact),error:artifact.error||null};
}
function exportEntryMarkup(item) {
  const key=encodeURIComponent(item.id),date=exportDate(item.created_at),provider=profiles[item.target]?.label||item.target||'Generic',format={gcp:'TAR.GZ',vhd:'VHD',qcow2:'QCOW2',raw:'RAW',oci:'OCI'}[item.format]||(item.format||'Image').toUpperCase();
  const isOpen=exportsView.open.has(item.id),warningsOpen=exportsView.warnings.has(item.id);
  return `<div class="export-row-main"><div class="export-identity"><div class="export-name-line"><h2 id="export-title-${key}" class="export-name" tabindex="-1" data-export-focus="name">${esc(item.name)}</h2><span class="export-format" title="${esc(item.format==='oci'?'OCI archive (.oci)':format+' format')}">${esc(format)}</span></div>${item.source&&item.source!==item.name?`<p class="export-source-name">From ${esc(item.source)}</p>`:''}<div class="export-meta"><span>${esc(provider)}</span><span aria-label="File size: ${esc(bytes(item.size))}">${bytes(item.size)}</span>${date?`<time datetime="${date.iso}" title="${esc(date.full)}">${esc(date.short)}</time>`:''}${item.warnings.length?`<button type="button" class="export-warning-count" data-export-warnings="${esc(item.id)}" data-export-focus="warnings" aria-expanded="${isOpen&&warningsOpen}" aria-controls="export-warnings-${key}" aria-label="View ${item.warnings.length} distinct warnings for ${esc(item.name)}">${icon('info')}${item.warnings.length} ${item.warnings.length===1?'warning':'warnings'}</button>`:''}<button type="button" class="export-toggle" data-export-toggle="${esc(item.id)}" data-export-focus="details" aria-expanded="${isOpen}" aria-controls="export-details-${key}" aria-label="Details for ${esc(item.name)}">Details<span class="export-chevron">${icon('arrow')}</span></button></div></div><div class="export-row-actions"><a class="button primary small export-download" href="/api/artifacts/${key}/download" download data-export-focus="download" aria-label="Download ${esc(item.name)}">${icon('download')}Download</a><button type="button" class="button secondary small export-upload" data-s3="${esc(item.id)}" data-export-focus="upload" aria-label="Upload ${esc(item.name)} to S3" title="Upload to S3">${icon('upload')}Upload<span class="export-upload-suffix"> to S3</span></button></div></div>${item.error?`<div class="notice error export-error" role="alert">${esc(item.error)}</div>`:''}<section class="export-detail-panel" id="export-details-${key}" aria-labelledby="export-title-${key}"${isOpen?'':' hidden'}><div class="export-detail-heading"><h3>Export details</h3><div class="export-secondary-actions">${item.oci_config?`<a class="button secondary small" href="/api/artifacts/${key}/oci-bundle" download data-export-focus="oci">${icon('code')}OCI configuration</a>`:''}<a class="button ghost small" href="/api/artifacts/${key}/manifest" download data-export-focus="manifest">Manifest${icon('download')}</a></div></div><dl class="export-properties">${item.source||item.image_id?`<div class="export-source"><dt>Source image</dt><dd>${esc(item.source||item.image_id)}</dd></div>`:''}${date?`<div><dt>Created</dt><dd><time datetime="${date.iso}">${esc(date.full)}</time></dd></div>`:''}${Number.isFinite(item.virtual_size)?`<div><dt>Disk capacity</dt><dd>${bytes(item.virtual_size)}</dd></div>`:''}${Number.isFinite(item.size)?`<div><dt>File length</dt><dd>${item.size.toLocaleString()} bytes</dd></div>`:''}<div class="export-checksum"><dt>SHA-256</dt><dd><code>${esc(item.sha256||'Not available')}</code></dd></div></dl>${item.warnings.length?`<details class="export-warnings" id="export-warnings-${key}" data-export-warning-details="${esc(item.id)}"${warningsOpen?' open':''}><summary data-export-focus="warning-summary">${icon('info')}Warnings <span>${item.warnings.length}</span></summary><ul>${item.warnings.map(warning=>`<li>${esc(warning)}</li>`).join('')}</ul></details>`:''}</section>`;
}
function exportEntry(id) { return exportsView.rows.get(id)?.element; }
function updateExportDisclosure(id,open) {
  const row=exportEntry(id);if(!row)return;
  if(open)exportsView.open.add(id);else exportsView.open.delete(id);
  $('[data-export-toggle]',row).setAttribute('aria-expanded',String(open));$('.export-detail-panel',row).hidden=!open;
  const warnings=$('[data-export-warnings]',row),details=$('.export-warnings',row);if(warnings)warnings.setAttribute('aria-expanded',String(open&&Boolean(details?.open)));
}
function renderExports() {
  const host=$('#artifacts-content');if(!host)return;
  // Native details toggle events are queued; snapshot before any row replacement.
  $$('[data-export-warning-details]',host).forEach(details=>{if(details.open)exportsView.warnings.add(details.dataset.exportWarningDetails);else exportsView.warnings.delete(details.dataset.exportWarningDetails);});
  if(!state.artifacts.length){
    if(!$('.exports-empty',host))host.innerHTML=`<div class="exports-empty"><span class="large-icon">${icon('download')}</span><h2>No exports yet</h2><p>Build an image in the studio to create an export.</p><button type="button" class="button secondary" data-view="images">Open image studio</button></div>`;
    exportsView.rows.clear();return;
  }
  let list=$('.export-library',host);if(!list){host.innerHTML='<div class="export-library" role="list" aria-label="Exported images"></div>';list=$('.export-library',host);exportsView.rows.clear();}
  const active=document.activeElement,activeRow=active?.closest('[data-export-id]'),focus=activeRow?{id:activeRow.dataset.exportId,key:active.dataset.exportFocus}:null;
  const ids=new Set();
  state.artifacts.forEach((artifact,index)=>{
    const item=exportModel(artifact),signature=JSON.stringify(item);ids.add(item.id);let entry=exportsView.rows.get(item.id);
    if(!entry){const element=document.createElement('article');element.className='export-entry';element.dataset.exportId=item.id;element.setAttribute('role','listitem');element.setAttribute('aria-labelledby',`export-title-${encodeURIComponent(item.id)}`);entry={element,signature:null};exportsView.rows.set(item.id,entry);}
    if(entry.signature!==signature){entry.element.innerHTML=exportEntryMarkup(item);entry.signature=signature;}
    if(list.children[index]!==entry.element)list.insertBefore(entry.element,list.children[index]||null);
  });
  for(const [id,entry]of exportsView.rows)if(!ids.has(id)){entry.element.remove();exportsView.rows.delete(id);exportsView.open.delete(id);exportsView.warnings.delete(id);}
  if(focus?.key&&document.activeElement!==active){const row=exportEntry(focus.id);if(row)$$('[data-export-focus]',row).find(node=>node.dataset.exportFocus===focus.key)?.focus({preventScroll:true});}
}
function openExportArtifact(id, {details=true} = {}) {
  setView('artifacts');renderExports();const row=exportEntry(id);if(!row)return false;
  updateExportDisclosure(id,details);$('.export-name',row).focus({preventScroll:true});row.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});return true;
}
document.addEventListener('click',event=>{
  const button=event.target.closest('button');if(!button||button.disabled)return;
  if(button.dataset.exportToggle){const id=button.dataset.exportToggle;updateExportDisclosure(id,!exportsView.open.has(id));}
  if(button.dataset.exportWarnings){const id=button.dataset.exportWarnings,row=exportEntry(id);if(!row)return;updateExportDisclosure(id,true);exportsView.warnings.add(id);const details=$('.export-warnings',row);details.open=true;button.setAttribute('aria-expanded','true');$('summary',details).focus({preventScroll:true});details.scrollIntoView({block:'nearest',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});}
});
document.addEventListener('toggle',event=>{
  const id=event.target.dataset?.exportWarningDetails;if(!id||!event.target.isConnected)return;
  if(event.target.open)exportsView.warnings.add(id);else exportsView.warnings.delete(id);
  const row=exportEntry(id),button=row&&$('[data-export-warnings]',row);if(button)button.setAttribute('aria-expanded',String(exportsView.open.has(id)&&event.target.open));
},true);
