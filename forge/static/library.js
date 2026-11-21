'use strict';

function libraryName(kind, item) {
  return item?.name || item?.filename || (kind === 'image' ? 'Imported image' : 'Image export');
}

function libraryActions(kind, item) {
  if (!item) return '';
  const noun = kind === 'image' ? 'import' : 'export';
  return `<div class="library-actions">${['rename','delete'].map(action => {
    const label = action === 'rename' ? 'Rename' : 'Delete';
    return `<button type="button" class="library-action" data-library-action="${action}" data-library-kind="${kind}" data-library-id="${esc(item.id)}" data-export-focus="${action}" aria-label="${label} ${noun} ${esc(libraryName(kind, item))}">${label}</button>`;
  }).join('')}</div>`;
}

function openLibraryDialog(button) {
  const {libraryAction:action, libraryKind:kind, libraryId:id} = button.dataset;
  const item = (kind === 'image' ? state.images : state.artifacts).find(record => record.id === id);
  if (!item) return;
  const displayName = libraryName(kind, item);
  const dialog = $('#library-dialog'), field = $('#library-name');
  const renaming = action === 'rename', noun = kind === 'image' ? 'import' : 'export';
  Object.assign(dialog.dataset, {kind, id, action});
  $('#library-title').textContent = `${renaming ? 'Rename' : 'Delete'} ${noun}`;
  const description = $('#library-description');
  description.hidden = renaming;
  description.textContent = renaming ? '' : kind === 'image'
    ? `Permanently delete “${displayName}” from this workspace? Previously built exports stay available.`
    : `Permanently delete “${displayName}” and its export files from this workspace? Copies already downloaded or uploaded stay available.`;
  if (renaming) dialog.removeAttribute('aria-describedby');
  else dialog.setAttribute('aria-describedby', 'library-description');
  $('#library-name-field').hidden = !renaming;
  field.disabled = !renaming;
  field.value = displayName;
  field.setCustomValidity('');
  notice('#library-error', '');
  $('#library-confirm').textContent = renaming ? 'Save name' : `Delete ${noun}`;
  dialog.showModal();
  if (renaming) {
    field.focus();
    const tail = kind === 'artifact' && /(?:\.tar\.gz|\.(?:qcow2|vhd|oci|raw))$/i.exec(field.value);
    field.setSelectionRange(0, tail ? tail.index : field.value.length);
  } else {
    $('#library-cancel').focus();
  }
}

function restoreLibraryFocus() {
  const {kind, id, action} = $('#library-dialog').dataset;
  const trigger = $$('[data-library-action]').find(button => button.dataset.libraryAction === action &&
    button.dataset.libraryKind === kind && button.dataset.libraryId === id && button.getClientRects().length);
  const fallback = kind === 'image' ? $('#image-select') || $('#panel-source [data-action="open-import"]')
    : $('.export-name') || $('.exports-empty button');
  const target = trigger || fallback;
  if (target?.getClientRects().length && !document.querySelector('dialog[open]')) target.focus({preventScroll:true});
}

document.addEventListener('click', event => {
  const button = event.target.closest('[data-library-action]');
  if (button) openLibraryDialog(button);
});
const libraryDialog = document.getElementById('library-dialog');
libraryDialog.addEventListener('close', restoreLibraryFocus);
libraryDialog.addEventListener('cancel', event => {
  if (libraryDialog.getAttribute('aria-busy') === 'true') event.preventDefault();
});
document.getElementById('library-cancel').addEventListener('click', () => libraryDialog.close());
document.getElementById('library-name').addEventListener('input', event => event.target.setCustomValidity(''));
document.getElementById('library-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (libraryDialog.getAttribute('aria-busy') === 'true') return;
  const {kind, id, action} = libraryDialog.dataset;
  const collection = kind === 'image' ? 'images' : 'artifacts';
  const renaming = action === 'rename';
  const field = $('#library-name'), name = field.value.trim();
  if (renaming && !name) {
    field.setCustomValidity('Enter a name.');
    field.reportValidity();
    return;
  }
  notice('#library-error', '');
  libraryDialog.setAttribute('aria-busy', 'true');
  $('#library-confirm').disabled = $('#library-cancel').disabled = true;
  field.readOnly = true;
  try {
    const updated = await api(`/${collection}/${encodeURIComponent(id)}`,
      renaming ? {method:'PATCH', body:JSON.stringify({name})} : {method:'DELETE'});
    const records = renaming ? state[collection].map(record => record.id === id ? updated : record)
      : state[collection].filter(record => record.id !== id);
    // Paint the confirmed change now. A poll that started before the write
    // must not put the old name or deleted entry back into the workspace.
    state.listValidators = {...state.listValidators};
    delete state.listValidators['/' + collection];
    updateWorkspaceInventory(kind === 'image' ? records : state.images, state.jobs,
                             kind === 'artifact' ? records : state.artifacts);
    libraryDialog.close();
    toast(`${kind === 'image' ? 'Import' : 'Export'} ${renaming ? 'renamed' : 'deleted'}.`);
    void refresh({supersede:true});
  } catch (error) {
    notice('#library-error', errorText(error));
    if (error.status === 404) void refresh({supersede:true});
  } finally {
    libraryDialog.removeAttribute('aria-busy');
    $('#library-confirm').disabled = $('#library-cancel').disabled = false;
    field.readOnly = false;
    if (libraryDialog.open && !document.getElementById('auth-dialog').open) {
      (renaming ? field : $('#library-cancel')).focus();
    }
  }
});
