'use strict';

// Activity reads the existing registry. Keyed rows keep disclosure and focus
// state intact while the shared four-second refresh supplies updated jobs.
const activityState = {query:'',status:'all',kind:'all',limit:20,nodes:new Map(),records:new Map(),logPositions:new Map(),visible:false,ready:false};
const activityKinds = {import:'Import',inspect:'Inspection',build:'Build',upload:'S3 upload',s3_upload:'S3 upload'};
const activityStatuses = {running:'Running',queued:'Queued',succeeded:'Completed',failed:'Failed'};

function activityTimestamp(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : null;
}
function activityDuration(job, now=Date.now()) {
  const active = ['running','queued'].includes(job.status);
  const start = activityTimestamp(job.status==='queued' ? job.created_at : job.started_at);
  const end = active ? now : activityTimestamp(job.finished_at);
  if (start===null || end===null) return '—';
  const seconds = Math.max(0,Math.floor((end-start)/1000));
  const duration = seconds<60 ? `${seconds}s` : seconds<3600 ? `${Math.floor(seconds/60)}m ${String(seconds%60).padStart(2,'0')}s` : `${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m`;
  return job.status==='queued' ? `Waiting ${duration}` : active ? `${duration} elapsed` : duration;
}
function activityDate(value, now=Date.now()) {
  const timestamp = activityTimestamp(value);
  if (timestamp===null) return {short:'Time unavailable',full:'Time unavailable',iso:''};
  const date = new Date(timestamp),today = new Date(now);
  const time = date.toLocaleTimeString(undefined,{hour:'numeric',minute:'2-digit'});
  const sameDay = date.toDateString()===today.toDateString();
  const day = date.toLocaleDateString(undefined,{month:'short',day:'numeric',...(date.getFullYear()!==today.getFullYear()?{year:'numeric'}:{})});
  return {short:sameDay ? `Today, ${time}` : `${day}, ${time}`,full:date.toLocaleString(),iso:date.toISOString()};
}
function activityLog(job) {
  return (Array.isArray(job.logs) ? job.logs : []).map(line=>typeof line==='string' ? line : JSON.stringify(line)).join('\n');
}
function activityLatest(job) {
  if (job.status==='queued') return 'Waiting for the image engine';
  const lines = Array.isArray(job.logs) ? job.logs : [],latest = lines.at(-1);
  const line = typeof latest==='string' ? latest : latest ? JSON.stringify(latest) : '';
  return line.replace(/^\d{4}-\d{2}-\d{2}T\S+\s+/, '').slice(0,220) || 'Working on this image';
}
function activityText(node, value) {
  const text = String(value ?? '');
  if (node.textContent!==text) node.textContent=text;
}
function activityRecord(job, images, artifacts) {
  const artifactId=job.result?.artifact_id || job.artifact_id || null,artifact=artifacts.get(artifactId);
  const imageId=job.image_id || job.result?.image_id || artifact?.image_id,image=images.get(imageId);
  const kind=job.kind==='s3_upload' ? 'upload' : job.kind || 'other';
  return {job,kind,title:activityKinds[job.kind] || 'Image operation',source:image?.name || artifact?.name || artifact?.filename || 'Source unavailable',
    imageId:image?.id || null,artifactId,active:['running','queued'].includes(job.status)};
}

function mountActivity() {
  const root=$('#jobs-content');
  if (!root || $('#activity-workspace',root)) return root;
  activityState.nodes.clear();
  root.innerHTML=`<div id="activity-workspace" class="activity-workspace">
    <div class="activity-empty" data-activity-empty hidden><span class="large-icon">${icon('activity')}</span><h2>No activity yet</h2><p>Your image operations will appear here.</p><button type="button" class="button secondary" data-action="open-import">Import image${icon('arrow')}</button></div>
    <section class="activity-current" aria-labelledby="activity-current-title" data-activity-current hidden><div class="activity-section-heading"><h2 id="activity-current-title">In progress</h2><span data-activity-active-count></span></div><div data-activity-active class="activity-active-list"></div></section>
    <section class="activity-history" aria-labelledby="activity-history-title" data-activity-history-section hidden>
      <div class="activity-section-heading"><h2 id="activity-history-title">History</h2><span data-activity-history-count aria-live="polite"></span></div>
      <div class="activity-toolbar"><label class="activity-search"><span class="sr-only">Search activity history</span><input type="search" data-activity-search placeholder="Search activity…" autocomplete="off"></label><label class="activity-filter"><span class="sr-only">History status</span><select data-activity-status><option value="all">All statuses</option><option value="succeeded">Completed</option><option value="failed">Failed</option></select></label><label class="activity-filter"><span class="sr-only">Operation type</span><select data-activity-kind><option value="all">All operations</option><option value="import">Imports</option><option value="inspect">Inspections</option><option value="build">Builds</option><option value="upload">S3 uploads</option></select></label><button type="button" class="button ghost small" data-activity-action="clear" hidden>Clear</button></div>
      <div class="activity-history-list" data-activity-history></div>
      <div class="activity-history-empty" data-activity-no-results hidden><p data-activity-empty-message>No past activity yet.</p><button type="button" class="button secondary small" data-activity-action="reset" hidden>Clear filters</button></div>
      <div class="activity-pagination" data-activity-pagination hidden><span data-activity-page-count></span><button type="button" class="button secondary small" data-activity-action="more">Show more</button></div>
    </section><span class="sr-only" data-activity-announcement role="status"></span>
  </div>`;
  $('[data-activity-search]',root).value=activityState.query;
  $('[data-activity-status]',root).value=activityState.status;
  $('[data-activity-kind]',root).value=activityState.kind;
  root.addEventListener('input',event=>{
    if (!event.target.matches('[data-activity-search]')) return;
    activityState.query=event.target.value;activityState.limit=20;renderActivity({filterChange:true});
  });
  root.addEventListener('change',event=>{
    if (event.target.matches('[data-activity-status]')) activityState.status=event.target.value;
    else if (event.target.matches('[data-activity-kind]')) activityState.kind=event.target.value;
    else return;
    activityState.limit=20;renderActivity({filterChange:true});
  });
  root.addEventListener('toggle',event=>{
    const node=event.target;
    if (!node.matches('.activity-job') || !node.isConnected) return;
    const record=activityState.records.get(node.dataset.job);
    if (node.open && record) updateActivityJob(node,record);
    // A completed row being read during a filter mismatch remains visible
    // until the reader closes it, rather than disappearing under keyboard focus.
    if (!node.open && node.dataset.retained==='true') renderActivity();
  },true);
  root.addEventListener('click',handleActivityClick);
  return root;
}

function createActivityJob(record) {
  const node=document.createElement('details');
  node.className='activity-job';node.dataset.job=record.job.id;
  node.innerHTML=`<summary class="activity-job-summary"><span class="activity-operation-icon" aria-hidden="true"></span><span class="activity-job-main"><strong data-activity-source-name></strong><span class="activity-operation-name" data-activity-title></span><span class="activity-current-step" data-activity-step></span></span><span class="activity-status" data-activity-job-status></span><span class="activity-job-time"><time data-activity-time></time><span data-activity-duration></span></span><span class="activity-chevron" aria-hidden="true">${icon('arrow')}</span></summary>
    <div class="activity-job-detail"><p class="activity-retained-note" data-activity-retained-note hidden>Kept open after completion.</p><div class="activity-job-error" data-activity-error hidden></div><div class="activity-detail-heading"><h3>Log</h3><div class="activity-result-actions"><button type="button" class="button ghost small" data-activity-action="source" hidden>Open source${icon('arrow')}</button><button type="button" class="button secondary small" data-activity-action="export" hidden>View export${icon('arrow')}</button></div></div><pre class="activity-log" tabindex="0"></pre><details class="activity-job-metadata"><summary>Job details</summary><dl class="activity-job-facts"><div><dt>Started</dt><dd data-activity-started></dd></div><div><dt>Finished</dt><dd data-activity-finished></dd></div><div><dt>Job ID</dt><dd><code data-activity-job-id></code></dd></div></dl></details></div>`;
  activityText($('[data-activity-job-id]',node),record.job.id);
  return node;
}

function captureActivityView() {
  for(const [id,node] of activityState.nodes) {
    if(!node.open || !node.isConnected)continue;
    const log=$('.activity-log',node);if(!log.getClientRects().length)continue;
    activityState.logPositions.set(id,{top:log.scrollTop,left:log.scrollLeft,follow:log.scrollHeight-log.clientHeight-log.scrollTop<24});
  }
  activityState.visible=false;
}

function updateActivityJob(node,record,now=Date.now(),restorePosition=false) {
  const {job}=record,status=activityStatuses[job.status] || 'Unknown',time=activityDate(record.active?job.created_at:job.finished_at || job.created_at,now);
  node.classList.toggle('is-active',record.active);
  node.classList.toggle('is-failed',job.status==='failed');
  if (node.dataset.kind!==record.kind) {
    $('.activity-operation-icon',node).innerHTML=icon(record.kind==='build'?'stack':record.kind==='upload'?'upload':record.kind==='import'?'image':'activity');
    node.dataset.kind=record.kind;
  }
  activityText($('[data-activity-title]',node),record.title);
  activityText($('[data-activity-source-name]',node),record.source);
  $('[data-activity-source-name]',node).title=record.source;
  const statusNode=$('[data-activity-job-status]',node);
  activityText(statusNode,status);statusNode.dataset.status=job.status;
  activityText($('[data-activity-time]',node),time.short);
  $('[data-activity-time]',node).dateTime=time.iso;
  $('[data-activity-time]',node).title=time.full;
  activityText($('[data-activity-duration]',node),activityDuration(job,now));
  const step=$('[data-activity-step]',node);step.hidden=!record.active;
  if (record.active) activityText(step,activityLatest(job));
  const error=$('[data-activity-error]',node);error.hidden=!job.error;
  activityText(error,job.error || '');
  $('[data-activity-action="source"]',node).hidden=!record.imageId;
  $('[data-activity-action="export"]',node).hidden=!record.artifactId;
  activityText($('[data-activity-started]',node),activityDate(job.started_at).full==='Time unavailable'?'Not started':activityDate(job.started_at).full);
  activityText($('[data-activity-finished]',node),job.finished_at?activityDate(job.finished_at).full:record.active?'In progress':'Not recorded');
  if (node.open && state.view==='jobs') {
    const log=$('.activity-log',node),content=activityLog(job) || (job.status==='queued'?'Waiting for the image engine…':'No log messages recorded.');
    const saved=restorePosition?activityState.logPositions.get(job.id):null;
    const top=saved?saved.top:log.scrollTop,left=saved?saved.left:log.scrollLeft,follow=saved?saved.follow:log.dataset.loaded==='true' && log.scrollHeight-log.clientHeight-top<24;
    if (log.textContent!==content || saved) {
      if(log.textContent!==content)log.textContent=content;
      log.scrollTop=follow?log.scrollHeight:top;log.scrollLeft=left;
    }
    log.dataset.loaded='true';log.setAttribute('aria-label',`${record.title} log for ${record.source}`);
  }
}

function activityPlace(container,nodes) {
  let cursor=container.firstElementChild;
  for (const node of nodes) {
    if (node===cursor) cursor=cursor.nextElementSibling;
    else container.insertBefore(node,cursor);
  }
  const keep=new Set(nodes);
  for (const node of [...container.children]) if (!keep.has(node)) node.remove();
}

function renderActivity({filterChange=false}={}) {
  const root=mountActivity();if(!root)return;
  const visible=state.view==='jobs',returning=visible&&!activityState.visible;
  const focus=root.contains(document.activeElement)?document.activeElement:null;
  const focusedJob=focus?.closest('.activity-job')?.dataset.job;
  if(filterChange)for(const node of activityState.nodes.values())node.dataset.retained='false';
  const images=new Map(state.images.map(image=>[image.id,image])),artifacts=new Map(state.artifacts.map(artifact=>[artifact.id,artifact]));
  const records=state.jobs.filter(job=>job?.id).map(job=>activityRecord(job,images,artifacts));
  const prior=activityState.records;
  activityState.records=new Map(records.map(record=>[record.job.id,record]));
  const active=records.filter(record=>record.active).sort((a,b)=>(a.job.status==='running'?0:1)-(b.job.status==='running'?0:1) || (activityTimestamp(a.job.created_at)||0)-(activityTimestamp(b.job.created_at)||0));
  const history=records.filter(record=>!record.active).sort((a,b)=>(activityTimestamp(b.job.created_at)||0)-(activityTimestamp(a.job.created_at)||0));
  const query=activityState.query.trim().toLowerCase();
  const matches=history.filter(record=>(activityState.status==='all'||record.job.status===activityState.status) && (activityState.kind==='all'||record.kind===activityState.kind) && [record.source,record.title,record.job.id,record.job.image_id,record.job.error].filter(Boolean).join(' ').toLowerCase().includes(query));
  if (!filterChange && focusedJob) {
    const index=matches.findIndex(record=>record.job.id===focusedJob);
    if(index>=activityState.limit)activityState.limit=Math.ceil((index+1)/20)*20;
  }
  const normalPage=matches.slice(0,activityState.limit),shown=[...normalPage];
  // If a running job completes while its log is open, keep it readable even
  // when the terminal status does not match the user's history filter.
  if (!filterChange) for (const record of history) {
    const node=activityState.nodes.get(record.job.id);
    if(node?.open && (prior.get(record.job.id)?.active || node.dataset.retained==='true') && !shown.includes(record)) {
      shown.unshift(record);node.dataset.retained='true';
    }
  }
  const displayed=[...active,...shown],now=Date.now();
  for (const record of displayed) {
    let node=activityState.nodes.get(record.job.id);
    if (!node) {node=createActivityJob(record);activityState.nodes.set(record.job.id,node);}
    if (filterChange || normalPage.includes(record) || record.active) node.dataset.retained='false';
    $('[data-activity-retained-note]',node).hidden=node.dataset.retained!=='true';
    updateActivityJob(node,record,now,returning);
  }
  const logPositions=(visible?displayed:[]).map(record=>activityState.nodes.get(record.job.id)).filter(node=>node.open).map(node=>{
    const log=$('.activity-log',node);return {log,top:log.scrollTop,left:log.scrollLeft};
  });
  activityPlace($('[data-activity-active]',root),active.map(record=>activityState.nodes.get(record.job.id)));
  activityPlace($('[data-activity-history]',root),shown.map(record=>activityState.nodes.get(record.job.id)));
  for(const item of logPositions){item.log.scrollTop=item.top;item.log.scrollLeft=item.left;}
  for(const [id] of activityState.nodes)if(!activityState.records.has(id)){activityState.nodes.delete(id);activityState.logPositions.delete(id);}
  $('[data-activity-empty]',root).hidden=Boolean(records.length);
  $('[data-activity-current]',root).hidden=!active.length;
  $('[data-activity-history-section]',root).hidden=!records.length;
  const running=active.filter(record=>record.job.status==='running').length,queued=active.length-running;
  activityText($('[data-activity-active-count]',root),[running?`${running} running`:'',queued?`${queued} queued`:''].filter(Boolean).join(' · '));
  activityText($('[data-activity-history-count]',root),`${matches.length} ${query||activityState.status!=='all'||activityState.kind!=='all'?'matching ':''}${matches.length===1?'job':'jobs'}`);
  const filtered=Boolean(query||activityState.status!=='all'||activityState.kind!=='all');
  $('[data-activity-action="clear"]',root).hidden=!filtered;
  $('[data-activity-no-results]',root).hidden=Boolean(shown.length);
  activityText($('[data-activity-empty-message]',root),filtered?'No jobs match these filters.':'No past activity yet.');
  $('[data-activity-action="reset"]',root).hidden=!filtered;
  const more=matches.length>activityState.limit;
  $('[data-activity-pagination]',root).hidden=!more;
  activityText($('[data-activity-page-count]',root),`Showing ${Math.min(activityState.limit,matches.length)} of ${matches.length}`);
  activityText($('[data-activity-action="more"]',root),`Show ${Math.min(20,Math.max(0,matches.length-activityState.limit))} more`);
  if (visible && focus?.isConnected && document.activeElement!==focus) focus.focus({preventScroll:true});
  else if (visible && focus && !focus.isConnected && !filterChange) $('[data-activity-search]',root)?.focus({preventScroll:true});
  if(activityState.ready && state.view==='jobs') {
    const completed=records.filter(record=>!record.active && prior.get(record.job.id)?.active);
    if(completed.length) activityText($('[data-activity-announcement]',root),completed.map(record=>`${record.title} ${activityStatuses[record.job.status]?.toLowerCase()||record.job.status}.`).join(' '));
  }
  activityState.ready=true;activityState.visible=visible;
}

function openActivityJob(id) {
  if(!state.jobs.some(job=>job.id===id))return false;
  activityState.query='';activityState.status='all';activityState.kind='all';
  const history=state.jobs.filter(job=>!['queued','running'].includes(job.status)).sort((a,b)=>(activityTimestamp(b.created_at)||0)-(activityTimestamp(a.created_at)||0));
  const index=history.findIndex(job=>job.id===id);
  activityState.limit=Math.max(activityState.limit,Math.ceil((index+1)/20)*20);
  setView('jobs');renderActivity({filterChange:true});
  $('[data-activity-search]').value='';$('[data-activity-status]').value='all';$('[data-activity-kind]').value='all';
  const node=activityState.nodes.get(id);if(!node)return false;
  node.open=true;updateActivityJob(node,activityState.records.get(id));
  $('summary',node).focus({preventScroll:true});
  node.scrollIntoView({block:'nearest',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
  return true;
}

function handleActivityClick(event) {
  const button=event.target.closest('[data-activity-action]');if(!button)return;
  const action=button.dataset.activityAction,root=$('#jobs-content');
  if(action==='clear'||action==='reset') {
    activityState.query='';activityState.status='all';activityState.kind='all';activityState.limit=20;
    $('[data-activity-search]',root).value='';$('[data-activity-status]',root).value='all';$('[data-activity-kind]',root).value='all';
    renderActivity({filterChange:true});$('[data-activity-search]',root).focus();return;
  }
  if(action==='more') {
    const oldIds=new Set([...$('[data-activity-history]',root).children].map(node=>node.dataset.job));
    activityState.limit+=20;renderActivity();
    const next=[...$('[data-activity-history]',root).children].find(node=>!oldIds.has(node.dataset.job));
    if(next)$('summary',next).focus({preventScroll:true});return;
  }
  const record=activityState.records.get(button.closest('.activity-job')?.dataset.job);if(!record)return;
  if(action==='source' && record.imageId) {
    const select=$('#image-select');
    if(select) {select.value=record.imageId;select.dispatchEvent(new Event('change',{bubbles:true}));}
    setView('images');$('#image-select')?.focus({preventScroll:true});
  }
  if(action==='export' && record.artifactId) {
    if(typeof openExportArtifact==='function')openExportArtifact(record.artifactId);
    else setView('artifacts');
  }
}
