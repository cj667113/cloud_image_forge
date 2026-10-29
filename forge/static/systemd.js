'use strict';

// This is a source-file graph, never an inferred boot-time measurement.
const systemdExplorer = {sessions:{},model:null,searchResults:[],returnFocus:null,skipDialogRestore:false};
const systemdOrderRelations = new Set(['After','Before']);
const systemdDependencyRelations = new Set(['Requires','Wants','Requisite','BindsTo','Upholds']);
const systemdCycleHelp = 'Configured links form a loop. Offline conditions and which units start together are not evaluated; this is not a runtime boot diagnosis.';
const systemdRelationHelp = {
  After:'Ordering only: start after the named unit when both are started. It does not pull the other unit in.',
  Before:'Ordering only: start before the named unit when both are started. It does not pull the other unit in.',
  Requires:'Pull in the named unit. Start ordering is separate.',
  Wants:'Pull in the named unit without requiring its successful activation. Start ordering is separate.',
  Requisite:'The named unit must already be active; this does not start it.',
  BindsTo:'Link activation and lifetime to the named unit. Start ordering is separate.',
  Upholds:'Keep the named unit running while this unit remains active. Start ordering is separate.',
  PartOf:'Propagate stop and restart operations from the named unit. It is not a startup prerequisite.',
  Conflicts:'The units cannot be active together. It is not a startup prerequisite.',
  OnFailure:'Start the named unit if this unit fails. It is not a startup prerequisite.'
};
function systemdSession() {
  return systemdExplorer.sessions[state.selected] ||= {selected:null,inspected:null,query:'',view:'order',direction:'upstream',open:new Set(),closed:new Set(),all:false,collapsed:false,budget:80,focused:null,evidenceOpen:false,searchOpen:false,searchIndex:-1};
}
function captureSystemdExplorerState(imageId) {
  const session=systemdExplorer.sessions[imageId],details=$('.systemd-unit-evidence');
  if(session&&details&&systemdExplorer.model?.imageId===imageId)session.evidenceOpen=details.open;
}
function renderSystemdExplorer(inspection) {
  const evidence=inspection.systemd,refreshing=['queued','running'].includes(state.images.find(image=>image.id===state.selected)?.inspection_status);
  const refresh=`<button type="button" class="button secondary small" data-action="refresh-inspection"${refreshing?' disabled':''}>${refreshing?'Refreshing…':'Refresh inspection'}</button>`;
  return `<section id="systemd-explorer" class="systemd-explorer" aria-labelledby="systemd-title">
    <div class="systemd-heading"><div><h3 id="systemd-title">Service chain</h3><span class="systemd-scope">Source configuration · no timings</span></div>${helpHint('This tree describes the imported source, not draft service or file changes. It contains configured relationships, not measured boot times. Implicit dependencies, generated units and runtime conditions can change the actual boot. Enabled or masked are unit-file states, not live status.','About this source tree')}</div>
    ${!evidence?`<div class="notice info systemd-missing">Refresh inspection to load the service tree. ${refresh}</div>`:!evidence.available?`<div class="notice warning">Systemd metadata is unavailable. ${refresh}</div>`:''}
    ${evidence?.truncated?'<div class="notice warning systemd-partial">Partial source inventory: inspection limits omitted some units or links.</div>':''}
    <div class="systemd-controls"><div class="systemd-picker"><label class="sr-only" for="systemd-unit-search">Find a service or target</label><input id="systemd-unit-search" data-systemd-search type="search" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="systemd-search-list" placeholder="Find a service or target…" autocomplete="off" spellcheck="false"><div id="systemd-search-list" class="systemd-search-results" role="listbox" aria-label="Matching units" hidden></div></div><div class="systemd-view-switch" role="group" aria-label="Relationship view"><button type="button" data-systemd-view="order">Start order</button><button type="button" data-systemd-view="dependencies">Dependencies</button></div><label class="systemd-direction"><span class="sr-only">Relationship direction</span><select data-systemd-direction></select></label><span data-systemd-view-help></span></div>
    <div class="systemd-tree-toolbar"><span class="systemd-coverage" data-systemd-coverage role="status"></span><div><button type="button" class="button ghost small" data-systemd-action="expand-all">Expand all</button><button type="button" class="button ghost small" data-systemd-action="collapse">Collapse</button></div></div>
    <div class="systemd-tree-scroll"><div class="systemd-tree" data-systemd-tree role="tree" aria-label="Configured systemd relationships"></div></div>
    <div class="systemd-tree-bottom"><span data-systemd-tree-note></span><button type="button" class="button secondary small" data-systemd-action="remaining" hidden>Show remaining</button></div>
    ${evidence?.warnings?.length?`<details class="systemd-notes"><summary>Inspection notes <span>${evidence.warnings.length}</span></summary><ul>${evidence.warnings.map(warning=>`<li>${esc(warning)}</li>`).join('')}</ul></details>`:''}
    <dialog id="systemd-unit-dialog" class="systemd-unit-dialog" aria-labelledby="systemd-dialog-title"></dialog>
  </section>`;
}
function systemdBuildModel(inspection) {
  const evidence = inspection.systemd, units = new Map();
  for (const unit of evidence?.units || []) if (unit?.name) units.set(unit.name,unit);
  if (!evidence?.available) for (const name of inspection.services || []) if (!units.has(name)) units.set(name,{name,type:name.split('.').pop(),load_state:'unknown',unit_file_state:'unknown'});
  const aliases = evidence?.aliases || {};
  const canonical = name => {
    const seen = new Set();
    while (aliases[name] && !seen.has(name)) { seen.add(name); name = aliases[name]; }
    return name;
  };
  const maps = {order:{upstream:new Map(),downstream:new Map()},dependencies:{upstream:new Map(),downstream:new Map()}};
  const add = (map,from,to,edge) => {
    if (!map.has(from)) map.set(from,new Map());
    const links = map.get(from);
    if (!links.has(to)) links.set(to,{name:to,edges:[]});
    links.get(to).edges.push(edge);
  };
  const edges = [];
  for (const original of evidence?.edges || []) {
    if (!original?.source || !original?.target || !original?.relation) continue;
    const edge = {...original,source:canonical(original.source),target:canonical(original.target)};
    edges.push(edge);
    for (const name of [edge.source,edge.target]) if (!units.has(name)) units.set(name,{name,type:name.split('.').pop(),load_state:'missing',unit_file_state:'unknown'});
    if (systemdOrderRelations.has(edge.relation)) {
      const before = edge.relation === 'After' ? edge.target : edge.source, after = edge.relation === 'After' ? edge.source : edge.target;
      add(maps.order.upstream,after,before,edge); add(maps.order.downstream,before,after,edge);
    } else if (systemdDependencyRelations.has(edge.relation)) {
      add(maps.dependencies.upstream,edge.source,edge.target,edge); add(maps.dependencies.downstream,edge.target,edge.source,edge);
    }
  }
  return {imageId:state.selected,evidence,units,aliases,canonical,maps,edges,traces:new Map()};
}
function systemdTrace() {
  const model=systemdExplorer.model,session=systemdSession(),key=JSON.stringify([session.selected,session.view,session.direction]);
  if(model.traces.has(key))return model.traces.get(key);
  const adjacency=model.maps[session.view][session.direction],items=new Map(),order=[];
  if(!session.selected||!model.units.has(session.selected))return {items,order,total:0,services:0,cyclic:new Set()};
  items.set(session.selected,{name:session.selected,parent:null,depth:0,children:[],references:[]});order.push(session.selected);
  // Breadth-first ownership gives shared units their shortest path from the root.
  for(let index=0;index<order.length;index++){
    const name=order[index],item=items.get(name),links=[...(adjacency.get(name)?.values()||[])].sort((a,b)=>a.name.localeCompare(b.name));
    for(const link of links){
      if(!items.has(link.name)){items.set(link.name,{name:link.name,parent:name,depth:item.depth+1,children:[],references:[],edges:link.edges});item.children.push(link.name);order.push(link.name);}
      else item.references.push(link);
    }
  }
  // SCC membership distinguishes real cycles from shared paths in a diamond.
  let nextIndex=0;const indices=new Map(),low=new Map(),stack=[],onStack=new Set(),cyclic=new Set();
  function visit(name){
    indices.set(name,nextIndex);low.set(name,nextIndex++);stack.push(name);onStack.add(name);
    for(const other of adjacency.get(name)?.keys()||[]){if(!items.has(other))continue;if(!indices.has(other)){visit(other);low.set(name,Math.min(low.get(name),low.get(other)));}else if(onStack.has(other))low.set(name,Math.min(low.get(name),indices.get(other)));}
    if(low.get(name)===indices.get(name)){const component=[];let other;do{other=stack.pop();onStack.delete(other);component.push(other);}while(other!==name);if(component.length>1||adjacency.get(name)?.has(name))component.forEach(unit=>cyclic.add(unit));}
  }
  visit(session.selected);
  const trace={items,order,total:order.length,services:order.filter(name=>model.units.get(name)?.type==='service'||name.endsWith('.service')).length,cyclic};model.traces.set(key,trace);return trace;
}
function systemdOpen(item,trace,session=systemdSession()) {
  return item.children.length>0&&!session.closed.has(item.name)&&(session.all||session.open.has(item.name)||(!session.collapsed&&(trace.total<=80||item.depth<4)));
}
function systemdVisibleRows(trace) {
  const session=systemdSession(),rows=[];
  function walk(name,guides,last){
    if(rows.length>=session.budget)return;
    const item=trace.items.get(name);rows.push({item,guides,last});
    if(systemdOpen(item,trace))item.children.forEach((child,index)=>walk(child,[...guides,!last],index===item.children.length-1));
  }
  if(trace.total)walk(session.selected,[],true);
  return rows;
}
function systemdUnitState(unit) { return ['masked','missing','unreadable'].includes(unit.load_state)?unit.load_state:unit.unit_file_state||'unknown'; }
function systemdGuides(row) {
  const depth=row.item.depth,level=Math.min(depth,10);if(!depth)return '';
  const lines=row.guides.slice(1,10).map((continued,index)=>continued?`<span class="systemd-guide" style="--column:${index}"></span>`:'').join('');
  return `${lines}<span class="systemd-elbow${row.last?' last':''}" style="--column:${level-1}"></span>`;
}
function renderSystemdTree(focusName=null) {
  const root=$('#systemd-explorer'),model=systemdExplorer.model,session=systemdSession();if(!root||model?.imageId!==state.selected)return;
  const trace=systemdTrace(),rows=systemdVisibleRows(trace),tree=$('[data-systemd-tree]',root),oldScroll=$('.systemd-tree-scroll',root).scrollTop;
  const focus=rows.some(row=>row.item.name===(focusName||session.focused))?(focusName||session.focused):session.selected;
  $$('[data-systemd-view]',root).forEach(button=>{const active=button.dataset.systemdView===session.view;button.classList.toggle('selected',active);button.setAttribute('aria-pressed',String(active));});
  const ordering=session.view==='order',direction=$('[data-systemd-direction]',root),directionLabels=ordering?['Before selected','After selected']:['Referenced units','Referencing units'];
  direction.innerHTML=`<option value="upstream"${session.direction==='upstream'?' selected':''}>${directionLabels[0]}</option><option value="downstream"${session.direction==='downstream'?' selected':''}>${directionLabels[1]}</option>`;
  const help=$('[data-systemd-view-help]',root);
  if(help.dataset.view!==session.view){help.dataset.view=session.view;help.innerHTML=helpHint(ordering?'Configured After/Before links, normalized around the selected root. Ordering applies only when both units start; it does not pull units in. Shared links point to a unit already placed in the tree.':'Requires, Wants, Requisite, BindsTo and Upholds are shown separately from ordering. Requisite requires an already-active unit; it does not start it. PartOf, Conflicts and OnFailure remain in Unit details.','How to read this tree');}
  $('[data-systemd-coverage]',root).textContent=`${rows.length} / ${trace.total} units · ${trace.services} services`;
  tree.setAttribute('aria-label',`${directionLabels[session.direction==='upstream'?0:1]} ${session.selected||'selected unit'}; ${rows.length} of ${trace.total} configured units`);
  tree.innerHTML=rows.map(row=>{
    const item=row.item,unit=model.units.get(item.name),open=systemdOpen(item,trace,session),isRoot=item.depth===0,warning=['masked','missing','unreadable'].includes(unit.load_state),cycle=trace.cyclic.has(item.name);
    return `<div class="systemd-tree-row${isRoot?' root':''}${cycle?' cycle':''}" role="treeitem" aria-level="${item.depth+1}" aria-posinset="${item.parent?trace.items.get(item.parent).children.indexOf(item.name)+1:1}" aria-setsize="${item.parent?trace.items.get(item.parent).children.length:1}"${item.children.length?` aria-expanded="${open}"`:''} aria-selected="${session.inspected===item.name}" tabindex="${item.name===focus?0:-1}" data-systemd-unit="${esc(item.name)}" style="--level:${Math.min(item.depth,10)}" aria-label="${esc(item.name)}${warning?', '+esc(unit.load_state):''}${cycle?', configured cycle':''}${item.references.length?', '+item.references.length+' extra configured links':''}. Inspect unit.">${systemdGuides(row)}<div class="systemd-row-content">${item.children.length?`<button type="button" tabindex="-1" class="systemd-expand" data-systemd-expand="${esc(item.name)}" aria-label="${open?'Collapse':'Expand'} ${esc(item.name)}" aria-expanded="${open}">${icon('arrow')}</button>`:'<span class="systemd-leaf" aria-hidden="true"></span>'}<span class="systemd-node-name"${isRoot?' id="systemd-selected-name"':''}>${esc(item.name)}</span>${isRoot?'<span class="systemd-root-label">root</span>':''}${item.depth>10?`<span class="systemd-deep-level">level ${item.depth+1}</span>`:''}${warning?`<span class="systemd-node-state">${esc(unit.load_state)}</span>`:''}${cycle?`<span class="systemd-cycle-label" title="${esc(systemdCycleHelp)}">cycle</span>`:''}${item.references.length?`<button type="button" tabindex="-1" class="systemd-reference" data-systemd-references="${esc(item.name)}" aria-label="Inspect ${item.references.length} additional shared or cycle links for ${esc(item.name)}" title="${item.references.length} extra configured links within this tree. Opens source relationships, not external navigation.">↗ ${item.references.length}</button>`:''}</div></div>`;
  }).join('')||'<p class="systemd-empty">No unit files were found.</p>';
  const remaining=$('[data-systemd-action="remaining"]',root);remaining.hidden=rows.length>=trace.total;remaining.textContent=`Show remaining ${trace.total-rows.length} units`;
  $('[data-systemd-action="expand-all"]',root).disabled=rows.length>=trace.total;
  $('[data-systemd-action="collapse"]',root).disabled=rows.length<=1;
  $('[data-systemd-tree-note]',root).textContent=trace.cyclic.size?'Configured cycle detected.':!model.evidence?.available?'Refresh inspection to load configured links.':trace.total===1?'No further configured links.':'';
  $('[data-systemd-tree-note]',root).title=trace.cyclic.size?systemdCycleHelp:'';
  $('.systemd-tree-scroll',root).scrollTop=oldScroll;
  if(focusName)systemdFocusUnit(focusName);
}
function systemdFocusUnit(name,scroll=true) {
  const row=$$('[data-systemd-unit]').find(node=>node.dataset.systemdUnit===name);if(!row)return;
  $$('[data-systemd-unit]').forEach(node=>node.tabIndex=node===row?0:-1);systemdSession().focused=name;row.focus({preventScroll:true});if(scroll)row.scrollIntoView({block:'nearest',behavior:'instant'});
}
function resetSystemdTrace() { const session=systemdSession();session.open.clear();session.closed.clear();session.all=false;session.collapsed=false;session.budget=80;session.focused=session.selected; }
function systemdChooseRoot(name) {
  const model=systemdExplorer.model,session=systemdSession();name=model.canonical(name);if(!model.units.has(name))return;
  session.selected=name;session.inspected=name;session.query='';session.searchOpen=false;session.searchIndex=-1;resetSystemdTrace();$('[data-systemd-search]').value='';renderSystemdSearch();$('.systemd-tree-scroll').scrollTop=0;renderSystemdTree(name);
}
function systemdExpandAll() { const session=systemdSession(),trace=systemdTrace();session.all=true;session.collapsed=false;session.closed.clear();session.budget=trace.total;renderSystemdTree(); }
function systemdToggleUnit(name) {const session=systemdSession(),trace=systemdTrace(),item=trace.items.get(name);if(!item?.children.length)return;if(systemdOpen(item,trace)){session.closed.add(name);session.open.delete(name);}else{session.closed.delete(name);session.open.add(name);session.budget=Math.max(session.budget,trace.total);}renderSystemdTree(name);}
function renderSystemdSearch() {
  const root=$('#systemd-explorer'),model=systemdExplorer.model,session=systemdSession();if(!root||model?.imageId!==state.selected)return;
  const query=session.query.trim().toLowerCase(),aliases=new Map();for(const [alias,name]of Object.entries(model.aliases)){const canonical=model.canonical(name);aliases.set(canonical,[...(aliases.get(canonical)||[]),alias]);}
  let matches=[...model.units.values()].filter(unit=>[unit.name,unit.description,...(unit.aliases||[]),...(aliases.get(unit.name)||[])].filter(Boolean).join(' ').toLowerCase().includes(query)).sort((a,b)=>Number(b.name===session.selected)-Number(a.name===session.selected)||a.name.localeCompare(b.name));
  systemdExplorer.searchResults=matches.slice(0,12);if(session.searchIndex>=systemdExplorer.searchResults.length)session.searchIndex=systemdExplorer.searchResults.length-1;
  const list=$('#systemd-search-list',root),input=$('[data-systemd-search]',root);list.hidden=!session.searchOpen;input.setAttribute('aria-expanded',String(session.searchOpen));
  if(session.searchOpen&&session.searchIndex>=0)input.setAttribute('aria-activedescendant',`systemd-option-${session.searchIndex}`);else input.removeAttribute('aria-activedescendant');
  list.innerHTML=systemdExplorer.searchResults.map((unit,index)=>`<button type="button" role="option" id="systemd-option-${index}" tabindex="-1" aria-selected="${index===session.searchIndex}" data-systemd-pick="${esc(unit.name)}"><strong>${esc(unit.name)}</strong>${unit.description?`<span>${esc(unit.description)}</span>`:''}</button>`).join('')||'<div class="systemd-search-empty">No matching units.</div>';
  if(matches.length>12)list.insertAdjacentHTML('beforeend',`<div class="systemd-search-hint">${matches.length} matches · type to narrow</div>`);
  if(session.searchOpen&&session.searchIndex>=0)$(`#systemd-option-${session.searchIndex}`,list)?.scrollIntoView({block:'nearest',behavior:'instant'});
}
function systemdRelatedRow(edge,unitName,trace) {
  const other=edge.source===unitName?edge.target:edge.source,canLocate=trace.items.has(other);
  return `<div class="systemd-relationship"><div><code>${esc(edge.source)}</code><strong>${esc(edge.relation)}</strong><code>${esc(edge.target)}</code>${helpHint(systemdRelationHelp[edge.relation]||'Configured relationship.',edge.relation+' details')}</div><small>${esc(edge.origin||'unit')}${edge.path?' · '+esc(edge.path):''}</small>${canLocate?`<button type="button" class="button ghost small" data-systemd-locate="${esc(other)}">Locate ${esc(other)}</button>`:`<button type="button" class="button ghost small" data-systemd-inspect="${esc(other)}">Inspect ${esc(other)}</button>`}</div>`;
}
function showSystemdUnit(name,links=false) {
  const model=systemdExplorer.model,session=systemdSession(),dialog=$('#systemd-unit-dialog');name=model.canonical(name);const unit=model.units.get(name);if(!unit||!dialog)return;
  if(!dialog.open)systemdExplorer.returnFocus=session.focused||session.selected;
  session.inspected=name;const trace=systemdTrace(),references=model.edges.filter(edge=>edge.source===name||edge.target===name),startup=references.filter(edge=>systemdOrderRelations.has(edge.relation)||systemdDependencyRelations.has(edge.relation)),other=references.filter(edge=>!systemdOrderRelations.has(edge.relation)&&!systemdDependencyRelations.has(edge.relation));
  const supported=name.length<=160&&/^[A-Za-z0-9_][A-Za-z0-9_@.:-]*\.(service|timer|socket|target)$/.test(name);
  dialog.innerHTML=`<div class="dialog-heading"><div><h3 id="systemd-dialog-title" tabindex="-1">${esc(name)}</h3>${unit.description?`<p>${esc(unit.description)}</p>`:''}</div><button type="button" class="icon-button" data-systemd-action="close-dialog" aria-label="Close unit details">${icon('close')}</button></div><div class="systemd-dialog-body"><div class="systemd-unit-properties"><span>Unit file: <strong>${esc(systemdUnitState(unit))}</strong></span>${unit.service_type?`<span>Type: <strong>${esc(unit.service_type)}</strong></span>`:''}</div>${unit.fragment_path?`<p class="systemd-fragment"><code>${esc(unit.fragment_path)}</code></p>`:''}${unit.warnings?.map(warning=>`<p class="notice warning">${esc(warning)}</p>`).join('')||''}<details class="systemd-unit-evidence"${session.evidenceOpen?' open':''}><summary>Files & properties</summary><dl class="detail-list"><div><dt>Load state</dt><dd>${esc(unit.load_state||'Unknown')}</dd></div>${unit.dropins?.length?`<div><dt>Drop-ins</dt><dd>${unit.dropins.map(path=>`<code>${esc(path)}</code>`).join('<br>')}</dd></div>`:''}${unit.aliases?.length?`<div><dt>Aliases</dt><dd>${unit.aliases.map(esc).join(', ')}</dd></div>`:''}${unit.enabled_by?.length?`<div><dt>Enabled by</dt><dd>${unit.enabled_by.map(esc).join(', ')}</dd></div>`:''}<div><dt>Default dependencies</dt><dd>${typeof unit.default_dependencies==='boolean'?unit.default_dependencies?'Enabled; implicit links are not expanded':'Disabled':'Not inspected'}</dd></div></dl>${unit.conditions?.length?`<ul>${unit.conditions.map(condition=>`<li>${esc(typeof condition==='string'?condition:JSON.stringify(condition))}</li>`).join('')}</ul>`:''}</details><details class="systemd-link-details"${links?' open':''}><summary>Ordering & dependencies <span>${startup.length} links</span></summary>${startup.map(edge=>systemdRelatedRow(edge,name,trace)).join('')||'<p>No configured links.</p>'}</details>${other.length?`<details class="systemd-link-details"><summary>Other relationships <span>${other.length} links</span></summary>${other.map(edge=>systemdRelatedRow(edge,name,trace)).join('')}</details>`:''}</div><div class="dialog-footer">${supported?'<button type="button" class="button secondary" data-systemd-action="configure">Add service action</button>':''}${name!==session.selected?'<button type="button" class="button primary" data-systemd-action="trace">Trace from here</button>':'<button type="button" class="button secondary" data-systemd-action="close-dialog">Close</button>'}</div>`;
  $$('[data-systemd-unit]').forEach(row=>row.setAttribute('aria-selected',String(row.dataset.systemdUnit===name)));
  if(!dialog.open)dialog.showModal();$('#systemd-dialog-title').focus({preventScroll:true});dialog.scrollTop=0;
}
function closeSystemdDialog(restore=true) {const dialog=$('#systemd-unit-dialog');if(!dialog?.open)return;captureSystemdExplorerState(state.selected);systemdExplorer.skipDialogRestore=!restore;dialog.close();}
function systemdLocate(name) {const session=systemdSession(),trace=systemdTrace();if(!trace.items.has(name))return;closeSystemdDialog(false);session.budget=trace.total;let item=trace.items.get(name);while(item.parent){session.open.add(item.parent);session.closed.delete(item.parent);item=trace.items.get(item.parent);}renderSystemdTree(name);}
function handleSystemdClick(event) {
  const button=event.target.closest('button'),row=event.target.closest('[data-systemd-unit]');if(button?.disabled||event.target.closest('.help-anchor'))return;
  const session=systemdSession();
  if(button?.dataset.systemdPick){systemdChooseRoot(button.dataset.systemdPick);return;}
  if(button?.dataset.systemdView){session.view=button.dataset.systemdView;resetSystemdTrace();renderSystemdTree();button.focus({preventScroll:true});return;}
  if(button?.dataset.systemdExpand){systemdToggleUnit(button.dataset.systemdExpand);return;}
  if(button?.dataset.systemdReferences){session.focused=button.dataset.systemdReferences;showSystemdUnit(button.dataset.systemdReferences,true);return;}
  if(button?.dataset.systemdLocate){systemdLocate(button.dataset.systemdLocate);return;}
  if(button?.dataset.systemdInspect){showSystemdUnit(button.dataset.systemdInspect);return;}
  const action=button?.dataset.systemdAction;
  if(action==='expand-all'||action==='remaining'){systemdExpandAll();systemdFocusUnit(session.selected,false);return;}
  if(action==='collapse'){session.all=false;session.collapsed=true;session.open.clear();session.closed.clear();renderSystemdTree(session.selected);return;}
  if(action==='close-dialog'){closeSystemdDialog();return;}
  if(action==='trace'){const name=session.inspected;closeSystemdDialog(false);systemdChooseRoot(name);return;}
  if(action==='configure'){const name=session.inspected;closeSystemdDialog(false);state.editorRevision++;addService();const input=$$('.service-name').at(-1);input.value=name;revealEditorField(input);return;}
  if(row){session.focused=row.dataset.systemdUnit;showSystemdUnit(row.dataset.systemdUnit);}
}
function handleSystemdKeys(event) {
  const session=systemdSession();
  if(event.target.matches('[data-systemd-search]')){
    if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)&&(!['Home','End'].includes(event.key)||session.searchOpen)){event.preventDefault();session.searchOpen=true;renderSystemdSearch();const total=systemdExplorer.searchResults.length;session.searchIndex=event.key==='Home'?0:event.key==='End'?total-1:Math.max(0,Math.min(total-1,session.searchIndex+(event.key==='ArrowDown'?1:-1)));renderSystemdSearch();return;}
    if(event.key==='Enter'){event.preventDefault();event.stopPropagation();if(session.searchOpen&&systemdExplorer.searchResults.length)systemdChooseRoot(systemdExplorer.searchResults[Math.max(0,session.searchIndex)].name);return;}
    if(event.key==='Escape'){event.preventDefault();session.searchOpen=false;renderSystemdSearch();return;}
    if(event.key==='Tab'){session.searchOpen=false;renderSystemdSearch();}return;
  }
  const row=event.target.closest('[data-systemd-unit]');if(!row||event.target!==row)return;
  const name=row.dataset.systemdUnit,trace=systemdTrace(),item=trace.items.get(name),rows=$$('[data-systemd-unit]'),index=rows.indexOf(row);
  if(['ArrowUp','ArrowDown','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?rows.length-1:Math.max(0,Math.min(rows.length-1,index+(event.key==='ArrowDown'?1:-1)));systemdFocusUnit(rows[next].dataset.systemdUnit);}
  if(event.key==='ArrowRight'){event.preventDefault();if(item.children.length){if(!systemdOpen(item,trace))systemdToggleUnit(name);else if($$('[data-systemd-unit]').some(node=>node.dataset.systemdUnit===item.children[0]))systemdFocusUnit(item.children[0]);else systemdLocate(item.children[0]);}}
  if(event.key==='ArrowLeft'){event.preventDefault();if(systemdOpen(item,trace))systemdToggleUnit(name);else if(item.parent)systemdFocusUnit(item.parent);}
  if(event.key==='Enter'||event.key===' '){event.preventDefault();session.focused=name;showSystemdUnit(name);}
}
function mountSystemdExplorer() {
  const root=$('#systemd-explorer');if(!root)return;const inspection=state.images.find(image=>image.id===state.selected)?.inspection||{},model=systemdExplorer.model=systemdBuildModel(inspection),session=systemdSession();
  session.selected=model.canonical(session.selected);if(!model.units.has(session.selected))session.selected=['sshd.service','ssh.service',model.evidence?.default_target].map(model.canonical).find(name=>model.units.has(name))||[...model.units.keys()].find(name=>name.endsWith('.service'))||model.units.keys().next().value||null;
  if(!model.units.has(session.inspected))session.inspected=session.selected;
  session.searchOpen=false;session.searchIndex=-1;$('[data-systemd-search]',root).value=session.query;
  root.addEventListener('input',event=>{event.stopPropagation();if(event.target.matches('[data-systemd-search]')){session.query=event.target.value;session.searchOpen=true;session.searchIndex=-1;renderSystemdSearch();}});
  root.addEventListener('change',event=>{event.stopPropagation();if(event.target.matches('[data-systemd-direction]')){session.direction=event.target.value;resetSystemdTrace();renderSystemdTree();}});
  root.addEventListener('focusin',event=>{if(event.target.matches('[data-systemd-search]')){session.searchOpen=true;renderSystemdSearch();}});
  root.addEventListener('toggle',event=>{if(event.target.matches('.systemd-unit-evidence')&&event.target.isConnected)session.evidenceOpen=event.target.open;},true);
  root.addEventListener('click',handleSystemdClick);root.addEventListener('keydown',handleSystemdKeys);
  const dialog=$('#systemd-unit-dialog',root);
  dialog.addEventListener('close',()=>{
    const skip=systemdExplorer.skipDialogRestore;systemdExplorer.skipDialogRestore=false;
    if(skip||dialog.open||!root.isConnected)return;
    const name=systemdExplorer.returnFocus||session.selected,active=document.activeElement;
    // Native close is queued: do not steal focus after the user moves on.
    if(active?.isConnected&&active!==document.body&&active!==document.documentElement&&!dialog.contains(active)&&active.closest('[data-systemd-unit]')?.dataset.systemdUnit!==name)return;
    systemdFocusUnit(name,false);
  });
  renderSystemdSearch();renderSystemdTree();
}
document.addEventListener('pointerdown',event=>{if(!document.getElementById('systemd-explorer')||event.target.closest('.systemd-picker'))return;const session=systemdSession();if(session.searchOpen){session.searchOpen=false;renderSystemdSearch();}});
