'use strict';

// Public keys stay in the per-image draft. Nothing is sent until Build image.
const sshAccessState = {nextId:0,fingerprints:new Map()};
const sshKeyTypes = ['ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'];
function renderSshAccess(inspection) {
  const inventory=inspection.ssh_access,users=inventory?.users||[];
  return `<div class="access-policy"><div class="access-policy-heading"><span class="access-icon">${icon('lock')}</span><div><h3>SSH sign-in</h3><span id="ssh-policy-status" class="access-policy-status">Keep current policy</span></div></div><div class="access-policy-control"><label class="check-field"><input type="checkbox" id="ssh-disable-password"><span>Disable password login</span>${helpHint('Disables password and keyboard-interactive authentication in the exported image. Existing public keys are kept. This does not verify a live SSH login.','SSH password login')}</label><p id="ssh-password-caution" class="access-caution" hidden>Make sure you have a working public key.</p></div></div><div id="ssh-worker-notice" class="notice warning" hidden></div><div class="access-section-heading"><div><div class="access-section-title"><h3>User access</h3><span id="ssh-user-count" class="access-user-count">No changes</span></div><p>Append public keys. Existing keys stay in place.</p></div><button type="button" class="button secondary" id="ssh-add-user" data-ssh-action="add">${icon('plus')}Add user</button></div>${!inventory?'<div class="access-inventory-note">Enter an existing username, or <button type="button" class="button ghost small" data-action="refresh-inspection">refresh inspection</button> to list accounts.</div>':''}${inventory&&inventory.sshd_present===false?'<div class="notice warning">OpenSSH server was not found. Install it in Boot &amp; kernel to use Access changes.</div>':''}<datalist id="ssh-known-users">${users.map(user=>`<option value="${esc(user.username)}">${esc(user.home)} · ${esc(user.shell)}</option>`).join('')}</datalist><div id="ssh-user-rows"></div><div id="ssh-empty" class="access-empty"><span class="access-empty-icon">${icon('code')}</span><div><strong>No user changes</strong><p>Add a public key for an existing account, or create a user.</p></div></div>${inventory?.warnings?.length||inventory?.errors?.length?`<details class="editor-disclosure access-inspection-notes" data-disclosure="ssh-inspection"><summary>Inspection notes <span class="disclosure-meta">${(inventory.warnings?.length||0)+(inventory.errors?.length||0)}</span></summary><div class="details-content"><ul>${[...(inventory.errors||[]),...(inventory.warnings||[])].map(note=>`<li>${esc(note)}</li>`).join('')}</ul></div></details>`:''}`;
}
function captureSshAccessDraft() {
  return $$('.ssh-user-row').map(row=>({username:$('[data-ssh-username]',row).value,create:$('[data-ssh-create]',row).checked,keys:$('[data-ssh-keys]',row).value,fingerprintsOpen:$('.ssh-fingerprints',row).open}));
}
function restoreSshAccessDraft(rows=[]) {
  for(const row of rows)addSshUser(row,false);
}
function addSshUser(draft={},focus=true) {
  if($$('.ssh-user-row').length>=16)return;
  const id=`ssh-user-${++sshAccessState.nextId}`,row=document.createElement('article');
  row.className='ssh-user-row';row.dataset.sshRow=id;
  row.setAttribute('aria-labelledby',`${id}-title`);
  row.innerHTML=`<div class="ssh-user-heading"><div class="ssh-user-title"><h4 id="${id}-title" data-ssh-user-title>User access</h4><span class="ssh-account-badge" data-ssh-user-mode>Existing user</span></div><button type="button" class="icon-button" data-ssh-action="remove" aria-label="Remove user keys">${icon('close')}</button></div><div class="ssh-account-options"><label class="field" for="${id}-name">Username<input id="${id}-name" data-ssh-username list="ssh-known-users" placeholder="Choose or enter a username" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="32"></label><div class="ssh-create-option"><label class="check-field"><input type="checkbox" data-ssh-create><span>Create this user</span>${helpHint('Creates a local account with a home directory and no usable password. No administrator or sudo privileges are granted. Choose an unused username and provide at least one public key.','New user account')}</label><span class="ssh-user-info muted"></span></div></div><label class="field ssh-key-field" for="${id}-keys"><span class="ssh-key-label">Public keys<span>One key per line</span></span><textarea id="${id}-keys" data-ssh-keys rows="3" spellcheck="false" autocapitalize="none" autocomplete="off" placeholder="Paste an OpenSSH public key, or choose a .pub file below"></textarea></label><div class="ssh-key-toolbar"><label class="button secondary small ssh-key-upload" for="${id}-file">${icon('upload')}Choose .pub files<input id="${id}-file" type="file" data-ssh-file accept=".pub,text/plain" multiple aria-label="Upload public key files"></label><span class="ssh-key-count muted" role="status">No keys added</span></div><div class="ssh-row-error notice error" role="alert" hidden></div><details class="ssh-fingerprints" data-disclosure="${id}-fingerprints" hidden><summary>Key fingerprints</summary><ul></ul></details>`;
  $('[data-ssh-username]',row).value=draft.username||'';$('[data-ssh-create]',row).checked=Boolean(draft.create);$('[data-ssh-keys]',row).value=draft.keys||'';
  // Rows have their own structured draft; generated IDs are not reused across images.
  $('#ssh-user-rows').append(row);updateSshUser(row);syncSshAccess();
  $('.ssh-fingerprints',row).open=Boolean(draft.fingerprintsOpen);
  if(focus){state.editorRevision++;revealEditorField($('[data-ssh-username]',row));}
}
function parseSshPublicKeys(text) {
  if(/-----BEGIN [^-]*PRIVATE KEY-----|PuTTY-User-Key-File:/i.test(text))throw new Error('This is a private key. Use the public .pub key instead.');
  const lines=text.split(/\r?\n/).map(line=>line.trim()).filter(Boolean),keys=[],seen=new Set();
  if(lines.length>32)throw new Error('Use at most 32 public keys per user.');
  for(const [index,line] of lines.entries()) {
    if(line.length>16384)throw new Error(`Public key ${index+1} exceeds 16,384 characters.`);
    const parts=line.split(/\s+/),type=parts[0],encoded=parts[1];
    if(!sshKeyTypes.includes(type))throw new Error(`Key ${index+1}: use an OpenSSH Ed25519, RSA or ECDSA public key, without authorized_keys options.`);
    if(!encoded||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))throw new Error(`Key ${index+1}: the public-key data is missing or invalid.`);
    let wire;try{wire=Uint8Array.from(atob(encoded),char=>char.charCodeAt(0));}catch{throw new Error(`Key ${index+1}: the public-key data is not valid base64.`);}
    let offset=0;
    const field=()=>{if(offset+4>wire.length)throw new Error('truncated');const length=new DataView(wire.buffer,wire.byteOffset+offset,4).getUint32(0);offset+=4;if(length>wire.length-offset)throw new Error('truncated');const value=wire.slice(offset,offset+length);offset+=length;return value;};
    try {
      const decode=value=>new TextDecoder().decode(value);
      if(decode(field())!==type)throw new Error('type');
      if(type==='ssh-ed25519'){if(field().length!==32)throw new Error('length');}
      else if(type==='ssh-rsa'){const exponent=field(),modulus=field();let start=0;while(start<modulus.length&&modulus[start]===0)start++;const bits=start<modulus.length?(modulus.length-start-1)*8+32-Math.clz32(modulus[start]):0;if(!exponent.length||bits<2048)throw new Error('RSA keys must be at least 2048 bits');}
      else {const curve=type.slice('ecdsa-sha2-'.length),pointSize={nistp256:65,nistp384:97,nistp521:133}[curve];if(decode(field())!==curve)throw new Error('curve');const point=field();if(point.length!==pointSize||point[0]!==4)throw new Error('curve point');}
      if(offset!==wire.length)throw new Error('trailing data');
    }catch(error){throw new Error(error.message.startsWith('RSA')?`Key ${index+1}: ${error.message}.`:`Key ${index+1}: invalid ${type} public-key structure.`);}
    const identity=btoa(String.fromCharCode(...wire));
    if(identity!==encoded||wire.length>8192)throw new Error(`Key ${index+1}: use the original, complete OpenSSH public-key data.`);
    if(!seen.has(identity)){seen.add(identity);keys.push({line:[type,encoded,...parts.slice(2)].join(' '),type,identity,wire});}
  }
  return keys;
}
function sshWorkerRestriction() {
  const arch=sourceArchitecture(),engine=state.health?.engine||{},worker=normalizeArchitecture(engine.worker_arch),allowed=(engine.guest_execution_architectures||[worker]).map(normalizeArchitecture);
  return ['aarch64','x86_64'].includes(arch)&&worker&&!allowed.includes(arch)?`SSH access changes require an ${architectureName(arch)} worker. This worker is ${architectureName(worker)}; your draft is kept.`:'';
}
function getSshAccessConfig() {
  const disable_password_auth=Boolean($('#ssh-disable-password')?.checked),rows=$$('.ssh-user-row');
  if(!disable_password_auth&&!rows.length)return null;
  const users=[],names=new Set();
  for(const row of rows){
    const name=$('[data-ssh-username]',row),keyField=$('[data-ssh-keys]',row),username=name.value.trim();
    if(row.dataset.readingKeys)throw editorError('Wait for the public-key files to finish reading.',keyField);
    if(!/^[a-z_][a-z0-9_-]{0,31}$/.test(username))throw editorError('Enter a username of up to 32 lowercase letters, digits, underscores or hyphens, starting with a letter or underscore.',name);
    if(names.has(username))throw editorError(`Combine the keys for ${username} in one user entry.`,name);names.add(username);
    const create=$('[data-ssh-create]',row).checked;
    if(create&&(username==='root'||studioImage()?.inspection?.ssh_access?.users?.some(user=>user.username===username)))throw editorError(`${username} already exists. Turn off “Create this user” to add keys to the existing account.`,$('[data-ssh-create]',row));
    let keys;try{keys=parseSshPublicKeys(keyField.value);}catch(error){throw editorError(error.message,keyField);}
    if(!keys.length)throw editorError(`Add at least one public key for ${username}, or remove the user entry.`,keyField);
    users.push({username,create,authorized_keys:keys.map(key=>key.line)});
  }
  const restriction=sshWorkerRestriction();if(restriction)throw editorError(restriction,rows.length?$('[data-ssh-username]',rows[0]):$('#ssh-disable-password'));
  return {disable_password_auth,users};
}
function syncSshAccess() {
  if(!$('#ssh-user-rows'))return;
  const count=$$('.ssh-user-row').length,changed=count||$('#ssh-disable-password').checked;
  $('#ssh-user-count').textContent=count?`${count} ${count===1?'user':'users'}`:'No changes';$('#ssh-empty').hidden=Boolean(count);$('#ssh-add-user').disabled=count>=16;
  const disabled=$('#ssh-disable-password').checked;
  $('#ssh-password-caution').hidden=!disabled;
  $('#ssh-policy-status').textContent=disabled?'Passwords disabled':'Keep current policy';
  $('.access-policy').classList.toggle('is-changed',disabled);
  notice('#ssh-worker-notice',changed?sshWorkerRestriction():'');
}
function sshFingerprint(key) {
  if(!sshAccessState.fingerprints.has(key.identity)) {
    sshAccessState.fingerprints.set(key.identity,{value:null});
    if(crypto.subtle)crypto.subtle.digest('SHA-256',key.wire).then(digest=>{
      sshAccessState.fingerprints.set(key.identity,{value:'SHA256:'+btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/=+$/,'')});
      $$('.ssh-user-row').forEach(updateSshUser);
      if(wizardCurrentStep()==='review'){delete $('#panel-review')?.dataset.signature;wizardRenderReview();}
    }).catch(()=>sshAccessState.fingerprints.set(key.identity,{value:'Fingerprint unavailable'}));
    else sshAccessState.fingerprints.set(key.identity,{value:'Fingerprint unavailable in this browser'});
  }
  return sshAccessState.fingerprints.get(key.identity).value||'Calculating fingerprint…';
}
function updateSshUser(row) {
  const name=$('[data-ssh-username]',row).value.trim(),create=$('[data-ssh-create]',row).checked,source=studioImage()?.inspection?.ssh_access?.users?.find(user=>user.username===name);
  $('[data-ssh-user-title]',row).textContent=name||'User access';
  $('[data-ssh-user-mode]',row).textContent=create?'New user':'Existing user';
  row.classList.toggle('is-new-user',create);
  $('[data-ssh-action=remove]',row).setAttribute('aria-label',name?`Remove keys for ${name}`:'Remove user keys');
  $('.ssh-user-info',row).textContent=create?'No password · no administrator access':source?source.home:'Use an account already in the image';
  $('[data-ssh-username]',row).setAttribute('aria-label',create?'New username':'Existing username');
  $('[data-ssh-username]',row).setAttribute('list',create?'':'ssh-known-users');
  const field=$('[data-ssh-keys]',row),details=$('.ssh-fingerprints',row),error=$('.ssh-row-error',row);let keys=[];
  try{keys=parseSshPublicKeys(field.value);error.hidden=true;error.textContent='';}catch(issue){error.hidden=false;error.textContent=issue.message;}
  $('.ssh-key-count',row).textContent=keys.length?`${keys.length} public ${keys.length===1?'key':'keys'}`:'No keys added';
  details.hidden=!keys.length;$('ul',details).innerHTML=keys.map(key=>`<li><span>${esc(key.type.replace('ecdsa-sha2-',''))}</span><code>${esc(sshFingerprint(key))}</code></li>`).join('');
}
function sshAccessReview(config) {
  if(!config)return ['Unchanged'];
  const lines=[config.disable_password_auth?'Disable SSH password and keyboard-interactive login':'Keep existing SSH password policy'];
  for(const user of config.users){const keys=parseSshPublicKeys(user.authorized_keys.join('\n'));lines.push(`${user.create?'Create':'Update'} ${user.username} · ${keys.length} public ${keys.length===1?'key':'keys'}`);for(const key of keys)lines.push(sshFingerprint(key));}
  return lines;
}
async function uploadSshKeys(input) {
  const row=input.closest('.ssh-user-row'),field=$('[data-ssh-keys]',row),imageId=state.selected,before=field.value,error=$('.ssh-row-error',row),files=[...input.files];input.value='';
  const requestId=String(++sshAccessState.nextId);
  try {
    if(!files.length)return;
    if(files.length>32||files.reduce((sum,file)=>sum+file.size,0)>524288)throw new Error('Choose at most 32 public-key files, up to 512 KiB in total.');
    row.dataset.readingKeys=requestId;$('.ssh-key-count',row).textContent='Reading public keys…';
    const content=(await Promise.all(files.map(file=>file.text()))).join('\n');
    if(!row.isConnected||state.selected!==imageId||row.dataset.readingKeys!==requestId)return;
    if(field.value!==before)throw new Error('Keys changed while reading the files. Choose the files again to add them.');
    const imported=parseSshPublicKeys(content);if(!imported.length)throw new Error('The selected file contains no public keys.');
    const keys=parseSshPublicKeys([before,content].filter(Boolean).join('\n'));
    field.value=keys.map(key=>key.line).join('\n');field.dispatchEvent(new Event('input',{bubbles:true}));
  }catch(issue){if(row.isConnected&&state.selected===imageId&&(!row.dataset.readingKeys||row.dataset.readingKeys===requestId)){error.textContent=issue.message;error.hidden=false;}}
  finally{if(row.dataset.readingKeys===requestId){delete row.dataset.readingKeys;if(row.isConnected){let keys=[];try{keys=parseSshPublicKeys(field.value);}catch{}$('.ssh-key-count',row).textContent=keys.length?`${keys.length} public ${keys.length===1?'key':'keys'}`:'No keys added';}}}
}
document.addEventListener('click',event=>{
  const button=event.target.closest('[data-ssh-action]');if(!button||button.disabled)return;
  if(button.dataset.sshAction==='add')addSshUser();
  if(button.dataset.sshAction==='remove'){button.closest('.ssh-user-row').remove();state.editorRevision++;syncSshAccess();$('#ssh-add-user').focus();}
});
document.addEventListener('input',event=>{const row=event.target.closest('.ssh-user-row');if(row&&!event.target.matches('[data-ssh-file]'))updateSshUser(row);if(event.target.closest('#panel-access'))syncSshAccess();});
document.addEventListener('change',event=>{if(event.target.matches('[data-ssh-file]'))uploadSshKeys(event.target);else if(event.target.closest('#panel-access')){const row=event.target.closest('.ssh-user-row');if(row)updateSshUser(row);syncSshAccess();}});
