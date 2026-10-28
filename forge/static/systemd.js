'use strict';

// A read-only view of offline unit-file evidence. No activation times are inferred.
const systemdExplorer = {sessions:{},model:null};
const systemdOrderRelations = new Set(['After','Before']);
const systemdRelationHelp = {
  After:'Start after this unit when both units are started. This does not pull the other unit in.',
  Before:'Start before the named unit when both units are started. This does not pull the other unit in.',
  Requires:'Pull in the named unit. Ordering must be declared separately.',
  Wants:'Pull in the named unit without requiring its successful activation. Ordering is separate.',
  Requisite:'The named unit must already be active; this does not start it.',
  BindsTo:'A stronger requirement that also links the units’ lifetimes. Ordering is separate.',
  PartOf:'Propagate stop and restart operations from the named unit; this does not start it.',
  Upholds:'Keep the named unit running while this unit remains active. Ordering is separate.',
  Conflicts:'The units cannot run together. This does not establish start order.',
  OnFailure:'Start the named unit if this unit fails.'
};

function systemdSession() {
  return systemdExplorer.sessions[state.selected] ||= {selected:null,query:'',view:'order',direction:'upstream',limit:24,expanded:new Set(),closed:new Set(),depth:1};
}
function captureSystemdExplorerState(imageId) {
  const session=systemdExplorer.sessions[imageId],details=$('.systemd-unit-evidence');
  if(session&&details&&systemdExplorer.model?.imageId===imageId)session.evidenceOpen=details.open;
}
function renderSystemdExplorer(inspection) {
  const data = inspection.systemd;
  const refreshing = ['queued','running'].includes(state.images.find(image=>image.id===state.selected)?.inspection_status);
  const refreshButton = `<button type="button" class="button secondary small" data-action="refresh-inspection"${refreshing?' disabled':''}>${refreshing?'Refreshing…':'Refresh inspection'}</button>`;
  return `<section id="systemd-explorer" class="systemd-explorer" aria-labelledby="systemd-title">
    <div class="systemd-heading"><div><h3 id="systemd-title">Service explorer</h3><span class="systemd-scope">Source map · no runtime timings</span></div>${helpHint('This offline map describes the imported source. Draft service actions and file edits do not change it. Relationships come from unit files, drop-ins and enablement links, not a measured boot sequence or systemd-analyze blame/critical-chain output. Enabled and masked are unit-file states, not live status. Implicit dependencies, generators and runtime conditions can change the actual boot.','About the source service map')}</div>
    ${!data ? `<div class="notice info systemd-missing">Inspect this image to load its service map. ${refreshButton}</div>` : !data.available ? `<div class="notice warning">Systemd metadata is unavailable for this image. ${refreshButton}</div>` : ''}
    ${data?.truncated ? '<div class="notice warning">The inspection limit was reached. Some units or relationships are missing.</div>' : ''}
    <div class="systemd-layout"><aside class="systemd-browser" aria-label="Find a systemd unit"><label class="field systemd-search-label"><span class="sr-only">Find a service or target</span><input type="search" data-systemd-search placeholder="Find a service or target…" autocomplete="off" spellcheck="false"></label><div class="systemd-list-heading"><span data-systemd-count></span><span>Unit-file state</span></div><div class="systemd-unit-list" data-systemd-list role="list" aria-label="Systemd units"></div><button type="button" class="button ghost small systemd-more" data-systemd-action="more" hidden>Show more</button></aside><div class="systemd-detail" data-systemd-detail></div></div>
    ${data?.warnings?.length ? `<details class="systemd-evidence editor-disclosure" data-disclosure="systemd-limits"><summary>Inspection notes <span class="disclosure-meta">${data.warnings.length}</span></summary><div class="details-content"><ul>${data.warnings.map(warning=>`<li>${esc(warning)}</li>`).join('')}</ul></div></details>` : ''}
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
    } else {
      add(maps.dependencies.upstream,edge.source,edge.target,edge); add(maps.dependencies.downstream,edge.target,edge.source,edge);
    }
  }
  return {imageId:state.selected,evidence,units,aliases,canonical,maps,edges};
}
function mountSystemdExplorer() {
  const root = $('#systemd-explorer'); if (!root) return;
  const inspection = state.images.find(image=>image.id===state.selected)?.inspection || {};
  const model = systemdExplorer.model = systemdBuildModel(inspection), session = systemdSession();
  session.selected = model.canonical(session.selected);
  if (!model.units.has(session.selected)) session.selected = ['sshd.service','ssh.service',model.evidence?.default_target].find(name=>model.units.has(name)) || [...model.units.keys()].find(name=>name.endsWith('.service')) || model.units.keys().next().value || null;
  const search = $('[data-systemd-search]',root); search.value = session.query;
  // Explorer controls are not customization inputs and must not invalidate plans.
  root.addEventListener('input',event=>{ event.stopPropagation(); if (event.target.matches('[data-systemd-search]')) { session.query=event.target.value; session.limit=24; renderSystemdUnits(); } });
  root.addEventListener('change',event=>{ event.stopPropagation(); if (event.target.matches('[data-systemd-direction]')) { session.direction=event.target.value; session.expanded.clear(); session.closed.clear(); session.depth=1; renderSystemdDetail('direction'); } });
  root.addEventListener('toggle',event=>{if(event.target.matches('.systemd-unit-evidence')&&event.target.isConnected)session.evidenceOpen=event.target.open;},true);
  root.addEventListener('click',handleSystemdClick);
  root.addEventListener('keydown',handleSystemdKeys);
  renderSystemdUnits(); renderSystemdDetail();
}
function systemdUnitState(unit) {
  return ['masked','missing','unreadable'].includes(unit.load_state) ? unit.load_state : unit.unit_file_state || 'unknown';
}
function renderSystemdUnits(focusName=null) {
  const model=systemdExplorer.model,session=systemdSession(),root=$('#systemd-explorer'); if (!root || model?.imageId!==state.selected) return;
  const query=session.query.trim().toLowerCase();
  let matches=[...model.units.values()].filter(unit=>[unit.name,unit.description,...(unit.aliases||[]),...Object.keys(model.aliases).filter(alias=>model.canonical(alias)===unit.name)].filter(Boolean).join(' ').toLowerCase().includes(query)).sort((a,b)=>a.name.localeCompare(b.name));
  if (!query && session.selected) matches.sort((a,b)=>Number(b.name===session.selected)-Number(a.name===session.selected));
  const shown=matches.slice(0,session.limit);
  $('[data-systemd-count]',root).textContent=`${matches.length.toLocaleString()} ${query?'matches':'units'}`;
  $('[data-systemd-list]',root).innerHTML=shown.map(unit=>`<div role="listitem"><button type="button" class="systemd-unit${unit.name===session.selected?' selected':''}" data-systemd-select="${esc(unit.name)}" aria-pressed="${unit.name===session.selected}"><span><strong>${esc(unit.name)}</strong>${unit.description?`<span class="systemd-unit-description">${esc(unit.description)}</span>`:''}</span><span class="systemd-state ${esc(systemdUnitState(unit))}">${esc(systemdUnitState(unit))}</span></button></div>`).join('') || '<p class="systemd-empty">No matching units.</p>';
  const more=$('[data-systemd-action="more"]',root);more.hidden=matches.length<=shown.length;more.textContent=`Show ${Math.min(24,matches.length-shown.length)} more`;
  if (focusName) {
    const button=$$('[data-systemd-select]',$('[data-systemd-list]',root)).find(button=>button.dataset.systemdSelect===focusName);
    button?.focus({preventScroll:true});button?.scrollIntoView({block:'nearest',behavior:'instant'});
  }
}
function systemdNeighbors(name) {
  const session=systemdSession(),map=systemdExplorer.model.maps[session.view][session.direction];
  return [...(map.get(name)?.values() || [])].sort((a,b)=>a.name.localeCompare(b.name));
}
function systemdRelationBadges(edges) {
  return [...new Set(edges.map(edge=>edge.relation))].map(relation=>{
    const directions=[...new Set(edges.filter(edge=>edge.relation===relation).map(edge=>`${edge.source} ${edge.relation} ${edge.target}`))].join('. ');
    return helpHint(`${directions}. ${systemdRelationHelp[relation] || ''}`,`${relation}: relationship details`).replace('class="help-toggle"',`class="help-toggle systemd-relation${relation==='Conflicts'?' conflict':''}"`).replace('>?</button>',`>${esc(relation)}</button>`);
  }).join('');
}
function systemdTree(name,ancestors,key,depth,budget) {
  const model=systemdExplorer.model,session=systemdSession(),neighbors=systemdNeighbors(name);
  if (!neighbors.length) return '';
  let html='';
  for (const link of neighbors) {
    if (budget.remaining--<=0) { budget.limited=true; break; }
    const unit=model.units.get(link.name),cycle=ancestors.includes(link.name),path=key+'>'+link.name,children=systemdNeighbors(link.name),expandable=!cycle&&children.length>0&&depth<8;
    const open=expandable&&!session.closed.has(path)&&(depth<session.depth||session.expanded.has(path));
    const descriptions=link.edges.map(edge=>`${edge.source} ${edge.relation} ${edge.target}`).join('; ');
    html+=`<li class="systemd-branch"><div class="systemd-node${cycle?' cycle':''}">${expandable?`<button type="button" class="systemd-expand" data-systemd-expand="${esc(path)}" aria-expanded="${open}" aria-label="${open?'Collapse':'Expand'} links for ${esc(link.name)}">${icon('arrow')}</button>`:'<span class="systemd-node-dot" aria-hidden="true"></span>'}<button type="button" class="systemd-node-name" data-systemd-select="${esc(link.name)}"><strong>${esc(link.name)}</strong><span>${esc(unit?.description || unit?.type || 'Unit')}</span></button><div class="systemd-node-tags" aria-label="${esc(descriptions)}">${systemdRelationBadges(link.edges)}${cycle?'<span class="systemd-state cycle">Cycle</span>':['masked','missing','unreadable'].includes(unit?.load_state)?`<span class="systemd-state ${esc(unit.load_state)}">${esc(unit.load_state)}</span>`:''}${expandable?`<span class="systemd-link-count">${children.length}</span>`:!cycle&&children.length&&depth>=8?'<span class="systemd-state">Depth limit</span>':''}</div></div>${open?systemdTree(link.name,[...ancestors,link.name],path,depth+1,budget):''}</li>`;
  }
  return `<ul class="systemd-tree">${html}</ul>`;
}
function renderSystemdDetail(focus=null) {
  const root=$('[data-systemd-detail]'),model=systemdExplorer.model,session=systemdSession();if(!root||model?.imageId!==state.selected)return;
  const unit=model.units.get(session.selected);
  if (!unit) { root.innerHTML='<div class="systemd-empty">No unit files were found.</div>';return; }
  const evidenceOpen=$('.systemd-unit-evidence',root)?.open ?? session.evidenceOpen;
  const neighbors=systemdNeighbors(unit.name),budget={remaining:100,limited:false},tree=systemdTree(unit.name,[unit.name],unit.name,1,budget);
  const ordering=session.view==='order',direction=ordering?session.direction==='upstream'?'Before selected':'After selected':session.direction==='upstream'?'Referenced units':'Referencing units';
  const scope=ordering?'After and Before express ordering only when both units are started. They do not start a dependency, and they contain no duration.':'Requires, Wants and other relationships are shown in their declared direction. They do not establish start order. Conflicts and PartOf have different meanings; inspect the relationship details.';
  const cycles=(model.evidence?.cycles||[]).filter(cycle=>cycle.units?.includes(unit.name));
  const references=model.edges.filter(edge=>edge.source===unit.name||edge.target===unit.name);
  root.innerHTML=`<div class="systemd-selected-heading"><div><h4 id="systemd-selected-name" tabindex="-1">${esc(unit.name)}</h4>${unit.description?`<p>${esc(unit.description)}</p>`:''}</div><span class="systemd-state ${esc(systemdUnitState(unit))}">${esc(systemdUnitState(unit))}</span></div>
    <div class="systemd-toolbar"><div class="systemd-view-switch" role="group" aria-label="Relationship view"><button type="button" data-systemd-view="order" aria-pressed="${ordering}"${ordering?' class="selected"':''}>Start order</button><button type="button" data-systemd-view="dependencies" aria-pressed="${!ordering}"${!ordering?' class="selected"':''}>Dependencies</button></div><label class="systemd-direction"><span class="sr-only">Relationship direction</span><select data-systemd-direction><option value="upstream"${session.direction==='upstream'?' selected':''}>${ordering?'Before selected':'Referenced units'}</option><option value="downstream"${session.direction==='downstream'?' selected':''}>${ordering?'After selected':'Referencing units'}</option></select></label>${helpHint(scope,'How to read these relationships')}</div>
    ${cycles.length?'<div class="systemd-cycle-notice">A declared cycle includes this unit. Repeated nodes stop the path.</div>':''}
    <div class="systemd-path-heading"><span>${esc(direction)} <strong>${neighbors.length}</strong></span><div><button type="button" class="button ghost small" data-systemd-action="expand-level"${!neighbors.length||session.depth>=4?' disabled':''}>Expand level</button><button type="button" class="button ghost small" data-systemd-action="collapse"${session.depth===1&&!session.expanded.size?' disabled':''}>Collapse</button></div></div>
    <div class="systemd-graph" aria-label="${esc(direction)} ${esc(unit.name)}">${tree || `<p class="systemd-empty">${model.evidence?.available?ordering?'No declared ordering links in this direction.':'No declared relationships in this direction.':'Refresh inspection to load relationships.'}</p>`}</div>${budget.limited?'<p class="systemd-limit">Showing 100 links. Collapse branches or select a unit to narrow the map.</p>':''}
    <div class="systemd-detail-actions">${unit.name.length<=160&&/^[A-Za-z0-9_][A-Za-z0-9_@.:-]*\.(service|timer|socket|target)$/.test(unit.name)?`<button type="button" class="button secondary small" data-systemd-action="configure">${icon('plus')}Add service action</button>`:''}</div>
    <details class="systemd-unit-evidence editor-disclosure"${evidenceOpen?' open':''}><summary>Unit details <span class="disclosure-meta">Files & relationships</span></summary><div class="details-content"><dl class="detail-list"><div><dt>Load state</dt><dd>${esc(unit.load_state||'Unknown')}</dd></div><div><dt>Unit-file state</dt><dd>${esc(unit.unit_file_state||'Unknown')}</dd></div>${unit.service_type?`<div><dt>Service type</dt><dd>${esc(unit.service_type)}</dd></div>`:''}${unit.fragment_path?`<div><dt>Unit file</dt><dd><code>${esc(unit.fragment_path)}</code></dd></div>`:''}${unit.dropins?.length?`<div><dt>Drop-ins</dt><dd>${unit.dropins.map(path=>`<code>${esc(path)}</code>`).join('<br>')}</dd></div>`:''}${unit.aliases?.length?`<div><dt>Aliases</dt><dd>${unit.aliases.map(esc).join(', ')}</dd></div>`:''}${unit.enabled_by?.length?`<div><dt>Enabled by</dt><dd>${unit.enabled_by.map(esc).join(', ')}</dd></div>`:''}<div><dt>Default dependencies</dt><dd>${typeof unit.default_dependencies==='boolean'?unit.default_dependencies?'Enabled; implicit links are not expanded':'Disabled':'Not inspected'}</dd></div></dl>${unit.conditions?.length?`<h5>Conditions</h5><ul>${unit.conditions.map(condition=>`<li>${esc(typeof condition==='string'?condition:JSON.stringify(condition))}</li>`).join('')}</ul>`:''}${unit.warnings?.map(warning=>`<p class="notice warning">${esc(warning)}</p>`).join('')||''}${references.length?`<div class="systemd-edge-inventory">${references.slice(0,200).map(edge=>`<div><span><code>${esc(edge.source)}</code> <strong>${esc(edge.relation)}</strong> <code>${esc(edge.target)}</code></span><small>${esc(edge.origin||'unit')}${edge.path?' · '+esc(edge.path):''}</small></div>`).join('')}</div>${references.length>200?'<p class="systemd-limit">First 200 relationships shown.</p>':''}`:''}</div></details>`;
  if(focus==='heading')$('#systemd-selected-name')?.focus({preventScroll:true});
  else if(focus==='direction')$('[data-systemd-direction]',root)?.focus({preventScroll:true});
  else if(focus?.startsWith('view:'))$$('[data-systemd-view]',root).find(button=>button.dataset.systemdView===focus.slice(5))?.focus({preventScroll:true});
  else if(focus?.startsWith('expand:'))$$('[data-systemd-expand]',root).find(button=>button.dataset.systemdExpand===focus.slice(7))?.focus({preventScroll:true});
  else if(focus){const button=$(`[data-systemd-action="${focus}"]`,root);if(button&&!button.disabled)button.focus({preventScroll:true});else $('#systemd-selected-name')?.focus({preventScroll:true});}
}
function handleSystemdClick(event) {
  const button=event.target.closest('button');if(!button||button.disabled||button.closest('.help-anchor'))return;
  const session=systemdSession();
  if(button.dataset.systemdSelect){event.preventDefault();const inList=Boolean(button.closest('[data-systemd-list]')),mobile=matchMedia('(max-width:720px)').matches;session.selected=systemdExplorer.model.canonical(button.dataset.systemdSelect);session.expanded.clear();session.closed.clear();session.depth=1;renderSystemdUnits(inList&&!mobile?session.selected:null);renderSystemdDetail(inList&&!mobile?null:'heading');if(mobile)$('#systemd-selected-name')?.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});}
  if(button.dataset.systemdView){session.view=button.dataset.systemdView;session.expanded.clear();session.closed.clear();session.depth=1;renderSystemdDetail('view:'+session.view);}
  if(button.dataset.systemdExpand){const key=button.dataset.systemdExpand,open=button.getAttribute('aria-expanded')==='true';if(open){session.closed.add(key);session.expanded.delete(key);}else{session.closed.delete(key);session.expanded.add(key);}renderSystemdDetail('expand:'+key);}
  const action=button.dataset.systemdAction;
  if(action==='more'){session.limit+=24;renderSystemdUnits();const more=$('[data-systemd-action="more"]');if(!more.hidden)more.focus({preventScroll:true});else $$('[data-systemd-select]',$('[data-systemd-list]')).at(-1)?.focus({preventScroll:true});}
  if(action==='expand-level'){session.depth++;session.closed.clear();renderSystemdDetail('expand-level');}
  if(action==='collapse'){session.depth=1;session.expanded.clear();session.closed.clear();renderSystemdDetail('collapse');}
  if(action==='configure'){state.editorRevision++;addService();const input=$$('.service-name').at(-1);input.value=session.selected;revealEditorField(input);}
}
function handleSystemdKeys(event) {
  if(!event.target.matches('[data-systemd-select]')||!event.target.closest('[data-systemd-list]')||!['ArrowUp','ArrowDown','Home','End'].includes(event.key))return;
  const buttons=$$('[data-systemd-select]',$('[data-systemd-list]')),index=buttons.indexOf(event.target);
  const next=event.key==='Home'?0:event.key==='End'?buttons.length-1:Math.max(0,Math.min(buttons.length-1,index+(event.key==='ArrowDown'?1:-1)));
  event.preventDefault();buttons[next]?.focus();
}
