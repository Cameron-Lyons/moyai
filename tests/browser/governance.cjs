const assert=require('node:assert/strict');
const {test,before,after}=require('node:test');
const {spawn}=require('node:child_process');
const {mkdir}=require('node:fs/promises');
const {chromium}=require('playwright');
let server,browser,base;
before(async()=>{
  server=spawn(process.execPath,['scripts/settings_ui_preview.cjs','--port','0'],{stdio:['ignore','pipe','inherit']});
  base=await new Promise((resolve,reject)=>{server.once('error',reject);server.stdout.on('data',chunk=>{const match=chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+/);if(match)resolve(match[0]);});});
  browser=await chromium.launch({headless:true});
  await mkdir('/tmp/moyai-governance-ui',{recursive:true});
});
after(async()=>{await browser?.close();server?.kill();});
async function open(t,width=1440,fixture='populated'){
  const page=await browser.newPage({viewport:{width,height:1000},reducedMotion:'reduce'});
  const errors=[];page.on('pageerror',error=>errors.push(error.message));page.setDefaultTimeout(10000);
  t.after(async()=>{await page.close();assert.deepEqual(errors,[]);});
  await page.goto(`${base}/?fixture=${fixture}#governance`);
  return page;
}
for(const width of [1440,768,320])test(`Governance and policy editor work at ${width}px`,async t=>{
  const page=await open(t,width);
  await page.getByRole('heading',{name:'Workspace roles',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.getByRole('searchbox',{name:'Search roles'}).fill('missing-role');
  await page.getByText('No roles match your search.',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Clear search'}).click();
  await page.getByRole('button',{name:'Create role',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Create role',exact:true});
  await dialog.waitFor();
  const box=await dialog.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=width+1);
  await dialog.getByRole('textbox',{name:'Role name',exact:true}).fill('Preview reader '+width);
  await dialog.getByRole('textbox',{name:'Role ID',exact:true}).fill('preview-reader-'+width);
  await dialog.getByRole('checkbox',{name:/sessions.read/}).check();
  await dialog.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('heading',{name:'Preview reader '+width,exact:true}).waitFor();
  await page.getByRole('button',{name:'Security policies',exact:true}).click();
  await page.getByRole('heading',{name:'Organization defaults',exact:true}).waitFor();
  await page.screenshot({path:`/tmp/moyai-governance-ui/policies-${width}.png`,fullPage:true});
  await page.getByRole('button',{name:'Create policy',exact:true}).click();
  const policy=page.getByRole('dialog',{name:'Create security policy',exact:true});
  await policy.getByRole('textbox',{name:'Policy name',exact:true}).fill('Restricted review '+width);
  await policy.getByRole('checkbox',{name:'Restrict network destinations',exact:true}).check();
  await policy.getByRole('textbox',{name:'Allowed domains',exact:true}).fill('github.com\nregistry.npmjs.org');
  await policy.getByRole('combobox',{name:'Managed Git access',exact:true}).click();
  await page.getByRole('option',{name:'Read only',exact:true}).click();
  await page.screenshot({path:`/tmp/moyai-governance-ui/policy-editor-${width}.png`,fullPage:true});
  await policy.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('heading',{name:'Restricted review '+width,exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.getByRole('combobox',{name:'Default policy',exact:true}).click();
  await page.getByRole('option',{name:'Restricted review '+width,exact:true}).click();
  await page.getByRole('button',{name:'Save defaults',exact:true}).click();
  await page.getByText('Defaults saved',{exact:true}).waitFor();
});
test('Provisioning token appears once, cannot be dismissed by accident, and revocation supports cancellation',async t=>{
  const page=await open(t);
  await page.getByRole('button',{name:'Provisioning',exact:true}).click();
  await page.getByRole('button',{name:'Create token',exact:true}).click();
  let dialog=page.getByRole('dialog',{name:'Create provisioning token',exact:true});
  await dialog.getByRole('textbox',{name:'Token label',exact:true}).fill('Preview directory');
  await dialog.getByRole('button',{name:'Create token',exact:true}).click();
  await dialog.getByText('Provisioning token created',{exact:true}).waitFor();
  // A readonly text field keeps manual copy possible when the clipboard is blocked.
  assert.equal(await dialog.locator('#governance-token-secret').getAttribute('type'),'text');
  assert.match(await dialog.locator('#governance-token-secret').inputValue(),/^fixture-only-/);
  // The secret is shown once, so Escape cannot dismiss it; only Done closes the view.
  await page.keyboard.press('Escape');
  assert.equal(await dialog.locator('#governance-token-secret').count(),1);
  await dialog.getByRole('button',{name:'Done',exact:true}).click();
  await page.getByText('Preview directory',{exact:true}).waitFor();
  assert.equal(await page.locator('#governance-token-secret').count(),0);
  const row=page.getByRole('row').filter({hasText:'Preview directory'});
  await row.getByRole('button',{name:'Revoke',exact:true}).click();
  dialog=page.getByRole('dialog',{name:'Revoke provisioning token',exact:true});
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
  await row.getByRole('button',{name:'Revoke',exact:true}).click();
  await page.getByRole('dialog',{name:'Revoke provisioning token',exact:true}).getByRole('button',{name:'Revoke token',exact:true}).click();
  await page.getByRole('row').filter({hasText:'Preview directory'}).getByText('Revoked',{exact:true}).waitFor();
});
test('Members cannot fetch governance data and have no governance navigation',async t=>{
  const page=await open(t,1440,'member');
  let reads=0;page.on('request',request=>{if(/\/api\/admin\/(roles|scim|security-profiles)/.test(request.url()))reads++;});
  await page.reload();
  await page.getByText('Your role does not include governance settings.',{exact:true}).waitFor();
  assert.equal(reads,0);
  assert.equal(await page.getByRole('link',{name:'Governance',exact:true}).count(),0);
});
test('A delegated policy administrator sees only authorized tabs',async t=>{
  const page=await browser.newPage();t.after(()=>page.close());
  await page.route('**/api/session',async route=>{const response=await route.fetch(),data=await response.json();await route.fulfill({json:{...data,role:'member',permissions:['workspace.read','security.manage']}});});
  await page.goto(`${base}/#governance`);
  await page.getByRole('heading',{name:'Security policies',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Provisioning',exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Roles',exact:true}).count(),0);
});
test('A delegated auditor can page audit metadata without role administration',async t=>{
  const page=await browser.newPage();t.after(()=>page.close());
  await page.route('**/api/session',async route=>{const response=await route.fetch(),data=await response.json();await route.fulfill({json:{...data,role:'member',permissions:['workspace.read','audit.read']}});});
  await page.goto(`${base}/#governance`);
  await page.getByRole('heading',{name:'Governance audit history',exact:true}).waitFor();
  await page.getByText('security.defaults.updated',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Roles',exact:true}).count(),0);
  await page.getByRole('button',{name:'Load earlier changes',exact:true}).click();
  await page.getByText('role.created',{exact:true}).waitFor();
  assert.equal(await page.getByText('security.defaults.updated',{exact:true}).count(),1);
  assert.equal(await page.getByRole('button',{name:'Load earlier changes',exact:true}).isVisible(),false);
});
test('A session creator without connection access can open the composer',async t=>{
  const page=await browser.newPage();t.after(()=>page.close());
  const denied=[];
  await page.route('**/api/session',async route=>{const response=await route.fetch(),data=await response.json();await route.fulfill({json:{...data,role:'member',permissions:['workspace.read','sessions.create']}});});
  await page.route(/\/api\/(connections|environments|runs|session-folders)(?:\/|\?|$)/,route=>{denied.push(route.request().url());return route.fulfill({status:403,json:{detail:'This role cannot read that resource.'}});});
  await page.goto(`${base}/#tasks`);
  await page.getByRole('heading',{name:'What are we working on?',exact:true}).waitFor();
  await page.getByRole('button',{name:'Start session',exact:true}).waitFor();
  assert.deepEqual(denied,[]);
  await page.evaluate(()=>location.hash='#settings');
  await page.getByRole('heading',{name:'Settings',exact:true}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Connections',exact:true}).count(),0);
  assert.equal(await page.getByRole('link',{name:'Skills',exact:true}).count(),0);
});
test('An auditor without workspace metadata access can open governance directly',async t=>{
  const page=await browser.newPage();t.after(()=>page.close());
  const denied=[];
  await page.route('**/api/session',async route=>{const response=await route.fetch(),data=await response.json();await route.fulfill({json:{...data,role:'member',permissions:['audit.read']}});});
  await page.route(/\/api\/(config|organization|runs|session-folders)(?:\/|\?|$)/,route=>{denied.push(route.request().url());return route.fulfill({status:403,json:{detail:'This role cannot read that resource.'}});});
  await page.goto(`${base}/#governance`);
  await page.getByRole('heading',{name:'Governance audit history',exact:true}).waitFor();
  assert.deepEqual(denied,[]);
  await page.evaluate(()=>location.hash='#tasks');
  await page.getByRole('heading',{name:'Workspace access',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Start session',exact:true}).count(),0);
});
test('New-session context offers the organization policies and retains its selection',async t=>{
  const page=await open(t);
  await page.evaluate(()=>location.hash='#tasks');
  await page.getByRole('heading',{name:'What are we working on?',exact:true}).waitFor();
  await page.locator('.task-options summary').click();
  const select=page.getByRole('combobox',{name:'Security policy',exact:true});
  await select.click();
  await page.getByRole('option',{name:'Read-only investigation',exact:true}).click();
  await page.evaluate(()=>location.hash='#settings');
  await page.getByRole('heading',{name:'Settings',exact:true}).waitFor();
  await page.evaluate(()=>location.hash='#tasks');
  await page.getByRole('heading',{name:'What are we working on?',exact:true}).waitFor();
  if(!await page.getByRole('combobox',{name:'Security policy',exact:true}).isVisible())await page.locator('.task-options summary').click();
  assert.match(await page.getByRole('combobox',{name:'Security policy',exact:true}).innerText(),/Read-only investigation/);
});
for(const width of [1440,768,320])test(`Members keep managed session and workflow policies at ${width}px`,async t=>{
  const page=await open(t,width,'member');
  let reads=0,saved;
  page.on('request',request=>{if(new URL(request.url()).pathname==='/api/security-profiles')reads++;});
  await page.route('**/api/automations',async route=>{
    const response=await route.fetch(),data=await response.json();
    data.automations[0].definition.security_profile_id='f'.repeat(32);
    await route.fulfill({json:data});
  });
  await page.route('**/api/automations/auto-0',async route=>{
    saved=route.request().postDataJSON();
    await route.fulfill({json:{}});
  });
  await page.goto(`${base}/?fixture=member#tasks`);
  await page.getByRole('heading',{name:'What are we working on?',exact:true}).waitFor();
  await page.locator('.task-options summary').click();
  await page.getByText('Security policy is managed by your organization.',{exact:true}).waitFor();
  assert.equal(await page.getByRole('combobox',{name:'Security policy',exact:true}).count(),0);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:`/tmp/moyai-governance-ui/member-policy-${width}.png`,fullPage:true});
  await page.evaluate(()=>location.hash='#automations');
  await page.locator('[data-edit-automation="auto-0"]').click();
  const dialog=page.getByRole('dialog',{name:'Automation editor',exact:true});
  const notice=dialog.getByText('Saved policy retained. Ask a security policy manager to change it.',{exact:true});
  await notice.scrollIntoViewIfNeeded();
  assert.equal(await dialog.locator('[name=security_profile_id]').count(),0);
  const box=await dialog.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=width+1);
  await page.screenshot({path:`/tmp/moyai-governance-ui/member-workflow-policy-${width}.png`,fullPage:true});
  await dialog.getByRole('button',{name:'Save paused',exact:true}).click();
  await page.getByRole('heading',{name:'Automations',exact:true}).waitFor();
  assert.equal(saved?.definition.security_profile_id,'f'.repeat(32));
  assert.equal(reads,0);
});
test('Stale role saves keep the dialog open with a recoverable error',async t=>{
  const page=await open(t);
  await page.locator('[data-role-edit="auditor"]').click();
  await page.route('**/api/admin/roles/auditor',route=>route.fulfill({status:409,json:{detail:'This role changed. Refresh before saving.'}}));
  const dialog=page.getByRole('dialog',{name:'Edit role',exact:true});
  await dialog.getByRole('textbox',{name:'Role name',exact:true}).fill('Updated auditor');
  await dialog.getByRole('button',{name:'Save',exact:true}).click();
  await dialog.getByText('This role changed. Refresh before saving.',{exact:true}).waitFor();
  assert.equal(await dialog.getByRole('button',{name:'Save',exact:true}).isEnabled(),true);
  await dialog.press('Escape');
  assert.equal(await page.getByRole('dialog').count(),0);
});
test('Load failures offer retry and late reads cannot overwrite another page',async t=>{
  const page=await open(t,1440,'error');
  await page.getByRole('heading',{name:'Unable to load this page',exact:true}).waitFor();
  await page.route('**/api/admin/roles',route=>route.fulfill({json:{roles:[],permissions:[],assignments:[],group_roles:[],activity:[]}}));
  await page.getByRole('button',{name:'Try again',exact:true}).click();
  await page.getByRole('heading',{name:'Workspace roles',exact:true}).waitFor();
  let release,entered;const gate=new Promise(resolve=>release=resolve),pending=new Promise(resolve=>entered=resolve);
  await page.route('**/api/admin/roles',async route=>{entered();await gate;await route.fulfill({json:{roles:[],permissions:[],assignments:[],group_roles:[],activity:[]}});});
  await page.getByRole('button',{name:'Refresh',exact:true}).click();await pending;
  await page.evaluate(()=>location.hash='#settings');
  await page.getByRole('heading',{name:'Settings',exact:true}).waitFor();release();await page.unrouteAll({behavior:'wait'});
  assert.equal(await page.locator('#content h1').innerText(),'Settings');
});
test('Policy app choices are disabled until apps are restricted, and saved as shown',async t=>{
  const page=await open(t);
  await page.getByRole('button',{name:'Security policies',exact:true}).click();
  await page.getByRole('button',{name:'Create policy',exact:true}).click();
  const policy=page.getByRole('dialog',{name:'Create security policy',exact:true});
  const linear=policy.getByRole('checkbox',{name:'Linear',exact:true});
  assert.equal(await linear.isDisabled(),true);
  let saved;page.on('request',request=>{if(request.method()==='POST'&&request.url().endsWith('/api/admin/security-profiles'))saved=request.postDataJSON();});
  await policy.getByRole('checkbox',{name:'Restrict connected apps',exact:true}).check();
  assert.equal(await linear.isDisabled(),false);
  await linear.uncheck();
  await policy.getByRole('textbox',{name:'Policy name',exact:true}).fill('Apps shown');
  await policy.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('heading',{name:'Apps shown',exact:true}).waitFor();
  assert.deepEqual(saved.policy.connected_apps,['github','slack','notion']);
});
test('Role managers manage group grants from the Roles tab, and tab switches keep focus',async t=>{
  const page=await open(t);
  const row=page.getByRole('row').filter({hasText:'Engineering reviewers'});
  await row.getByRole('button',{name:'Change',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Assign group role',exact:true});
  assert.match(await dialog.getByRole('combobox',{name:'Directory group',exact:true}).innerText(),/Engineering reviewers/);
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
  await page.getByRole('button',{name:'Audit history',exact:true}).focus();
  await page.keyboard.press('Enter');
  await page.getByRole('heading',{name:'Governance audit history',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.activeElement?.dataset.governanceTab),'audit');
});

for(const width of [1440,768,320])test(`Audit filters retain UTC bounds, refresh and clear at ${width}px`,async t=>{
  const page=await open(t,width);
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.getByRole('heading',{name:'Governance audit history',exact:true}).waitFor();
  await page.screenshot({path:`/tmp/moyai-governance-ui/audit-after-${width}.png`,fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.locator('#governance-audit-actor').focus();await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(()=>document.activeElement?.id),'governance-audit-action');
  const fields={actor:'alex@example.com',action:'role.created',resource_type:'CustomRole',resource_id:'auditor',start:'2026-10-12T12:00',end:'2026-10-13T12:00'};
  for(const [name,value] of Object.entries(fields))await page.locator(`#governance-audit-${name}`).fill(value);
  const request=page.waitForRequest(request=>{const url=new URL(request.url());return url.pathname==='/api/admin/governance/audit'&&url.searchParams.get('action')==='role.created';});
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  const params=new URL((await request).url()).searchParams;
  assert.equal(params.get('start'),'2026-10-12T12:00:00.000Z');
  assert.equal(params.get('end'),'2026-10-13T12:00:00.000Z');
  for(const name of ['actor','action','resource_type','resource_id'])assert.equal(params.get(name),fields[name]);
  await page.getByText('role.created',{exact:true}).waitFor();
  assert.equal(await page.getByText('security.defaults.updated',{exact:true}).count(),0);
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await page.getByText('role.created',{exact:true}).waitFor();
  assert.equal(await page.locator('#governance-audit-actor').inputValue(),fields.actor);
  await page.locator('#governance-audit-actor').fill('missing@example.com');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.getByText('No governance changes match these filters.',{exact:true}).waitFor();
  await page.locator('#governance-audit-empty-clear').click();
  await page.getByText('security.defaults.updated',{exact:true}).waitFor();
  assert.equal(await page.locator('#governance-audit-actor').inputValue(),'');
  await page.locator('#governance-audit-start').fill('2026-10-13T12:00');
  await page.locator('#governance-audit-end').fill('2026-10-12T12:00');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.getByText('The end time must be later than the start time.',{exact:true}).waitFor();
});

test('CSV export starts a fresh filtered snapshot, follows its cursor and escapes spreadsheet formulas',async t=>{
  const page=await open(t);
  const exported=[];
  const row={id:'fresh-1',action:'role.created',actor:'alex@example.com',resource_type:'CustomRole',resource_id:'auditor',created_at:'2026-10-12T12:00:00Z'};
  await page.route('**/api/admin/governance/audit?*',async route=>{
    const params=new URL(route.request().url()).searchParams;
    if(params.get('limit')!=='100')return route.fulfill({json:{events:[{...row,id:'display-only',resource_id:'display-only'}],next_cursor:null}});
    exported.push(Object.fromEntries(params));
    await route.fulfill({json:params.get('cursor')?{events:[{...row,id:'fresh-2',action:' \t=1+1',resource_id:'line one, "quoted"\nline two'}],next_cursor:null}:{events:[row],next_cursor:'signed-snapshot-2'}});
  });
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.locator('#governance-audit-actor').fill('alex@example.com');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.getByText('display-only',{exact:true}).waitFor();
  const downloaded=page.waitForEvent('download');
  await page.getByRole('button',{name:'Export CSV',exact:true}).click();
  const download=await downloaded,csv=await require('node:fs/promises').readFile(await download.path(),'utf8');
  assert.match(csv,/"fresh-1"/);assert.match(csv,/"fresh-2"/);assert.doesNotMatch(csv,/display-only/);
  assert.ok(csv.includes('"\' \t=1+1"'));
  assert.ok(csv.includes('"line one, ""quoted""\nline two"'));
  assert.equal(exported.length,2);
  assert.deepEqual(exported.map(params=>params.actor),['alex@example.com','alex@example.com']);
  assert.equal(exported[0].cursor,undefined);assert.equal(exported[1].cursor,'signed-snapshot-2');
  await page.getByText('Exported 2 changes.',{exact:true}).waitFor();
});

test('CSV export refuses a partial download above 10,000 changes',async t=>{
  const page=await open(t);let downloads=0,reads=0;
  page.on('download',()=>downloads++);
  await page.route('**/api/admin/governance/audit?*',async route=>{
    const params=new URL(route.request().url()).searchParams;
    if(params.get('limit')!=='100')return route.fulfill({json:{events:[],next_cursor:null}});
    const offset=Number(params.get('cursor')||0);reads++;
    await route.fulfill({json:{events:Array.from({length:100},(_,index)=>({id:String(offset+index),action:'role.created',actor:'alex@example.com',resource_type:'CustomRole',resource_id:'auditor',created_at:'2026-10-12T12:00:00Z'})),next_cursor:String(offset+100)}});
  });
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.getByRole('button',{name:'Export CSV',exact:true}).click();
  await page.getByText('More than 10,000 changes match. Narrow the filters before exporting.',{exact:true}).waitFor();
  assert.equal(downloads,0);assert.equal(reads,100);
  assert.equal(await page.getByRole('button',{name:'Export CSV',exact:true}).isEnabled(),true);
});

test('A late export cannot download after leaving audit, and live access errors clear saved rows',async t=>{
  const page=await open(t);let downloads=0,release,entered;
  const gate=new Promise(resolve=>release=resolve),pending=new Promise(resolve=>entered=resolve);
  page.on('download',()=>downloads++);
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.getByText('security.defaults.updated',{exact:true}).waitFor();
  await page.route('**/api/admin/governance/audit?*',async route=>{
    const params=new URL(route.request().url()).searchParams;
    if(params.get('limit')==='100'){entered();await gate;return route.fulfill({json:{events:[],next_cursor:null}});}
    return route.fulfill({status:403,json:{detail:'Audit access was revoked.'}});
  });
  await page.getByRole('button',{name:'Export CSV',exact:true}).click();await pending;
  await page.getByRole('button',{name:'Roles',exact:true}).click();
  await page.getByRole('heading',{name:'Workspace roles',exact:true}).waitFor();
  release();await page.unrouteAll({behavior:'wait'});assert.equal(downloads,0);
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.getByText('security.defaults.updated',{exact:true}).waitFor();
  await page.route('**/api/admin/governance/audit?*',route=>route.fulfill({status:403,json:{detail:'Audit access was revoked.'}}));
  await page.getByRole('button',{name:'Load earlier changes',exact:true}).click();
  await page.getByText('Audit access was revoked.',{exact:true}).waitFor();
  assert.equal(await page.getByText('security.defaults.updated',{exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Export CSV',exact:true}).count(),0);
  await page.getByRole('button',{name:'Check access',exact:true}).waitFor();
});

test('Superseded audit filters cannot restore stale success or error responses',async t=>{
  const page=await open(t);let release,entered;
  const gate=new Promise(resolve=>release=resolve),pending=new Promise(resolve=>entered=resolve);
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.route('**/api/admin/governance/audit?*',async route=>{
    const actor=new URL(route.request().url()).searchParams.get('actor');
    if(actor==='old@example.com'){entered();await gate;return route.fulfill({status:503,json:{detail:'Old request failed.'}});}
    await route.fulfill({json:{events:[],next_cursor:null}});
  });
  await page.locator('#governance-audit-actor').fill('old@example.com');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();await pending;
  await page.locator('#governance-audit-actor').fill('new@example.com');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.getByText('No governance changes match these filters.',{exact:true}).waitFor();
  release();await page.unrouteAll({behavior:'wait'});
  assert.equal(await page.locator('#governance-audit-actor').inputValue(),'new@example.com');
  assert.equal(await page.getByRole('heading',{name:'Unable to load this page',exact:true}).count(),0);
});

test('Editing an audit filter cancels an in-flight export until filters are applied',async t=>{
  const page=await open(t);let downloads=0,release,entered;
  const gate=new Promise(resolve=>release=resolve),pending=new Promise(resolve=>entered=resolve);
  page.on('download',()=>downloads++);
  await page.getByRole('button',{name:'Audit history',exact:true}).click();
  await page.route('**/api/admin/governance/audit?*',async route=>{
    if(new URL(route.request().url()).searchParams.get('limit')!=='100')return route.continue();
    entered();await gate;await route.fulfill({json:{events:[],next_cursor:null}});
  });
  await page.getByRole('button',{name:'Export CSV',exact:true}).click();await pending;
  await page.locator('#governance-audit-actor').fill('new@example.com');
  await page.getByText('Apply filters to update the history and export.',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Export CSV',exact:true}).isDisabled(),true);
  assert.equal(await page.getByRole('button',{name:'Cancel export',exact:true}).isVisible(),false);
  release();await page.unrouteAll({behavior:'wait'});assert.equal(downloads,0);
});
