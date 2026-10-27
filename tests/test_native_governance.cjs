// Settings → Governance request builders and server-rendered rows. No browser,
// provider or backend authorization is exercised here.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const ts=require('typescript');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const root=path.resolve(__dirname,'..');
let server,gov,settings,permissions,sdk,api,homeSubmission;
test.before(async()=>{
  const {createServer}=await import('vite');
  server=await createServer({configFile:path.join(root,'native/web/vite.config.ts'),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
  gov=await server.ssrLoadModule('/governance.tsx');
  settings=await server.ssrLoadModule('/settings.tsx');
  permissions=await server.ssrLoadModule('/permissions.ts');
  sdk=await server.ssrLoadModule('/generated/api/index.ts');
  api=await server.ssrLoadModule('/api.ts');
  (await server.ssrLoadModule('/generated/api/client.gen.ts')).client.setConfig({baseUrl:'https://moyai.test'});
  const source=ts.createSourceFile('home.tsx',fs.readFileSync(path.join(root,'native/web/home.tsx'),'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
  const fn=source.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='homeSubmission');assert.ok(fn);
  const code=ts.transpileModule(fn.getText(source),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  ({homeSubmission}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64')));
});
test.after(async()=>{await server?.close();});
const render=(Component,props)=>renderToStaticMarkup(React.createElement(Component,props));
const stamp='2026-10-15T09:30:00+00:00';
const catalog=[
  {id:'sessions.read',label:'View sessions',description:'View sessions.',group:'Sessions'},
  {id:'sessions.create',label:'Start sessions',description:'Start sessions.',group:'Sessions'},
  {id:'audit.read',label:'Read the audit log',description:'Read audit history.',group:'Security'},
  {id:'roles.manage',label:'Manage custom roles and grants',description:'Manage roles.',group:'People'},
];
const role=(patch={})=>({id:'auditor',name:'Auditor',description:'Compliance <b>review</b>',permissions:['audit.read','sessions.read'],revision:3,archived:false,updated_at:stamp,updated_by:'admin@example.test',...patch});
const profile=(patch={})=>({id:'0123456789abcdef'.repeat(2),name:'Restricted',enabled:true,revision:2,policy:{connected_apps:['github'],tools:[],git_access:'read',network_domains:null,repositories:[7,42],models:null},updated_at:stamp,updated_by:'admin@example.test',...patch});
const limit=(patch={})=>({id:'organization',kind:'organization',subject:'',limit_usd:5000,revision:3,updated_at:stamp,updated_by:'admin@example.test',used_usd:1234.5,...patch});
const limits=()=>[limit(),limit({id:'user-default',kind:'user-default',limit_usd:null,revision:0,used_usd:null}),limit({id:'session-default',kind:'session-default',limit_usd:20,revision:1,used_usd:null})];

test('role IDs are derived safely and role bodies separate creation from revisioned edits',()=>{
  assert.equal(gov.roleIdFromName('Finance Reviewer (EU)'),'finance-reviewer-eu');
  assert.equal(gov.roleIdFromName('Équipe données'),'equipe-donnees');
  assert.equal(gov.roleIdFromName('2024 auditors'),'role-2024-auditors');
  assert.equal(gov.roleIdFromName('Admin'),'admin-custom');
  assert.equal(gov.roleIdFromName('Member'),'member-custom');
  const created=gov.roleBody({id:'finance-reviewer',name:' Finance reviewer ',description:'',permissions:['sessions.read','audit.read','audit.read']},undefined,catalog);
  assert.deepEqual(created,{id:'finance-reviewer',name:'Finance reviewer',description:'',permissions:['audit.read','sessions.read']});
  const updated=gov.roleBody({id:'ignored',name:'Auditor',description:'x',permissions:[]},role(),catalog);
  assert.deepEqual(updated,{name:'Auditor',description:'x',permissions:[],revision:3},'edits never send or change the role ID');
  assert.throws(()=>gov.roleBody({id:'admin',name:'Admins',description:'',permissions:[]},undefined,catalog),/Built-in role IDs/);
  assert.throws(()=>gov.roleBody({id:'Bad ID',name:'Bad',description:'',permissions:[]},undefined,catalog),/lowercase letters/);
  assert.throws(()=>gov.roleBody({id:'ok',name:'A',description:'',permissions:[]},undefined,catalog),/between 2 and 100/);
  assert.throws(()=>gov.roleBody({id:'ok',name:'Okay',description:'',permissions:['spend.manage']},undefined,catalog),/permission catalog/);
  assert.deepEqual(gov.permissionGroups(catalog).map(group=>[group.group,group.items.length]),[['Sessions',2],['Security',1],['People',1]]);
});

test('assignments carry both revisions, never grant admin, and group grants clear with null',()=>{
  const existing={email:'bob@example.test',role_id:'auditor',role_name:'Auditor',revision:2,role_revision:4,updated_at:stamp,updated_by:''};
  assert.deepEqual(gov.assignmentBody(' Erin@Example.TEST ','contractor',undefined),{email:'erin@example.test',role_id:'contractor',revision:0,role_revision:null});
  assert.deepEqual(gov.assignmentBody('ignored@example.test','member',existing),{email:'bob@example.test',role_id:'member',revision:2,role_revision:4});
  assert.throws(()=>gov.assignmentBody('erin@example.test','admin',undefined),/Users page/);
  assert.throws(()=>gov.assignmentBody('not-an-email','auditor',undefined),/work email/);
  assert.deepEqual(gov.groupRoleBody('',undefined),{role_id:null,revision:0});
  assert.deepEqual(gov.groupRoleBody('auditor',{revision:5}),{role_id:'auditor',revision:5});
  assert.throws(()=>gov.groupRoleBody('admin',undefined),/custom role/);
  assert.deepEqual(gov.roleUsage(role(),[existing,{...existing,email:'x@example.test',role_id:'other'}],[{group_id:'g',role_id:'auditor'}]),{people:1,groups:1});
});

test('security policy drafts keep unrestricted, nothing and listed values distinct',()=>{
  const draft=gov.policyDraft(profile());
  assert.equal(draft.apps,'selected');assert.equal(draft.tools,'none');assert.equal(draft.network,'all');
  assert.equal(draft.repositories,'selected');assert.equal(draft.models,'all');
  assert.deepEqual(gov.policyBody(draft,profile()).policy,profile().policy,'an unchanged draft round-trips exactly, IDs in numeric order');
  const body=gov.policyBody({...gov.policyDraft(),name:' Sandbox ',apps:'none',tools:'all',network:'listed',domains:'Registry.npmjs.org.\n*.Example.com, pypi.org pypi.org'},undefined);
  assert.deepEqual(body,{name:'Sandbox',enabled:true,revision:0,policy:{connected_apps:[],tools:null,git_access:'write',network_domains:['*.example.com','pypi.org','registry.npmjs.org'],repositories:null,models:null}},'every field is sent, so saved limits are never omitted');
  const limited=gov.policyBody({...gov.policyDraft(),name:'Limited',repositories:'selected',repository_ids:[100,9,9],models:'none',model_ids:['ignored']},undefined).policy;
  assert.deepEqual([limited.repositories,limited.models],[[9,100],[]]);
  assert.throws(()=>gov.policyBody({...gov.policyDraft(),name:'Repos',repositories:'selected',repository_ids:[]},undefined),/No repositories/);
  assert.throws(()=>gov.policyBody({...gov.policyDraft(),name:'Models',models:'selected',model_ids:[]},undefined),/No models/);
  assert.deepEqual(gov.policyBody({...gov.policyDraft(),name:'Offline',network:'none',domains:'ignored.example'},undefined).policy.network_domains,[],'blocking sends an empty list');
  assert.throws(()=>gov.policyBody({...gov.policyDraft(),name:'Empty',network:'listed',domains:'  '},undefined),/Block all outbound network access/);
  assert.throws(()=>gov.policyBody({...gov.policyDraft(),name:'Apps',apps:'selected',app_ids:[]},undefined),/No connected apps/);
  assert.throws(()=>gov.policyBody({...gov.policyDraft(),name:''},undefined),/policy name/);
  for(const bad of ['https://example.com','example.com:443','example.com/path','10.0.0.1','*.','*','user@example.com','localhost','exa mple.com'])
    assert.ok(gov.parseDomains(bad).invalid.length,`${bad} is rejected`);
  assert.deepEqual(gov.parseDomains('*.githubusercontent.com\ngithub.com').domains,['*.githubusercontent.com','github.com']);
  assert.throws(()=>gov.defaultsBody('disabled','',2,[profile({id:'disabled',enabled:false})]),/enabled security policy/);
  assert.deepEqual(gov.defaultsBody('',profile().id,2,[profile()]),{default_profile_id:'',mandatory_profile_id:profile().id,revision:2});
  assert.deepEqual(gov.policySummary(profile().policy,{app:id=>id==='github'?'GitHub':id,repository:id=>id===7?'acme/app':`Repository ${id}`}),
    {apps:'GitHub',tools:'No tools',git:'Read only',network:'Unrestricted network',repositories:'acme/app, Repository 42',models:'All models'});
  assert.deepEqual(gov.policySummary({...profile().policy,repositories:[],models:['a','b','c','d']}),{apps:'github',tools:'No tools',git:'Read only',network:'Unrestricted network',repositories:'No repositories',models:'4 models'});
  assert.equal(gov.repositoryLabel([{id:7,label:'acme/app'}],7),'acme/app');assert.equal(gov.repositoryLabel([],9),'Repository 9','a repository that left the catalog keeps its ID');
});

test('spend amounts: blank is no limit, zero blocks, and only changed rows are sent with their revisions',()=>{
  assert.equal(gov.parseUsd(''),null);assert.equal(gov.parseUsd(' $1,250.50 '),1250.5);assert.equal(gov.parseUsd('0'),0);
  for(const bad of ['-1','1.234','abc','1000000.01','1e3'])assert.throws(()=>gov.parseUsd(bad));
  assert.deepEqual(gov.spendChanges(limits(),{organization:'5000.00','user-default':'150','session-default':''}),
    [{id:'user-default',limit_usd:150,revision:0},{id:'session-default',limit_usd:null,revision:1}]);
  assert.deepEqual(gov.overrideChange(' Dan@Example.test ','0',undefined),{id:'user:dan@example.test',limit_usd:0,revision:0});
  assert.deepEqual(gov.overrideChange('ignored','',limit({id:'user:carol@example.test',kind:'user',revision:4})),{id:'user:carol@example.test',limit_usd:null,revision:4});
  assert.equal(gov.limitText(null),'No limit');assert.equal(gov.limitText(0),'Blocked ($0.00)');assert.equal(gov.usd(1234.5),'$1,234.50');
});

test('audit filters use whole UTC days, a 100-day window, normalized actors and matching export paths',async t=>{
  const filters={action:'role.created',actor:' Admin@Example.test ',resource_type:'role',from:'2026-07-08',to:'2026-10-15'};
  const query=gov.auditQuery(filters);
  assert.deepEqual(query,{action:'role.created',actor:'admin@example.test',resource_type:'role',after:'2026-07-08T00:00:00Z',before:'2026-10-16T00:00:00Z'});
  assert.throws(()=>gov.auditQuery({...filters,from:'2026-07-07'}),/at most 100 days/);
  assert.throws(()=>gov.auditQuery({...filters,from:'2026-10-16'}),/on or before/);
  assert.throws(()=>gov.auditQuery({...filters,from:'07/08/2026'}),/YYYY-MM-DD/);
  assert.deepEqual(gov.auditQuery(gov.emptyAuditFilters),{},'blank filters send no parameters');
  assert.deepEqual(gov.auditPageQuery(gov.emptyAuditFilters),{limit:50});
  assert.deepEqual(gov.auditPageQuery(filters,'opaque/cursor+1'),{...query,limit:50,cursor:'opaque/cursor+1'});
  // The generated client sends the page query with the opaque cursor encoded.
  const fetch=t.mock.method(global,'fetch',async()=>new Response(JSON.stringify({entries:[],next_cursor:null,facets:{actions:[],resource_types:[]}}),{headers:{'Content-Type':'application/json'}}));
  assert.deepEqual((await sdk.listGovernanceAudit({query:gov.auditPageQuery(filters,'opaque/cursor+1')})).data.entries,[]);
  assert.equal(fetch.mock.callCount(),1);
  const sent=new URL(fetch.mock.calls[0].arguments[0].url);
  assert.equal(sent.pathname,'/api/admin/governance/audit');assert.match(sent.search,/cursor=opaque%2Fcursor%2B1(&|$)/);
  assert.deepEqual(Object.fromEntries(sent.searchParams),{action:'role.created',actor:'admin@example.test',resource_type:'role',after:'2026-07-08T00:00:00Z',before:'2026-10-16T00:00:00Z',limit:'50',cursor:'opaque/cursor+1'});
  const exported=new URL(gov.auditExportPath(filters,'ndjson'),'https://moyai.test');
  assert.equal(exported.pathname,'/admin/governance/audit/export');
  assert.deepEqual(Object.fromEntries(exported.searchParams),{action:'role.created',actor:'admin@example.test',resource_type:'role',after:'2026-07-08T00:00:00Z',before:'2026-10-16T00:00:00Z',format:'ndjson'},'the export uses the same filters');
  assert.equal(gov.auditExportPath(gov.emptyAuditFilters,'csv'),'/admin/governance/audit/export?format=csv');
  assert.equal(gov.actionLabel('scim_token.revoked'),'SCIM token revoked');assert.equal(gov.actionLabel(''),'Change recorded');
  assert.equal(gov.detailText(['a','b']),'a, b');assert.equal(gov.detailText(null),'None');
});

test('an audit export that ends early is a friendly ApiError, and a cancelled export stays an abort',async t=>{
  const exportPath='/admin/governance/audit/export?format=csv';
  // The server streams pages after the 200 and closes the body if access is lost mid-export.
  t.mock.method(global,'fetch',async()=>new Response(new ReadableStream({start(stream){stream.enqueue(new TextEncoder().encode('id,action\n'));stream.error(new TypeError('network error'));}}),
    {headers:{'Content-Disposition':'attachment; filename="governance.csv"'}}));
  await assert.rejects(api.apiDownload(exportPath),error=>error instanceof api.ApiError&&error.status===0&&/interrupted before it finished/.test(error.message));
  const controller=new AbortController();
  t.mock.method(global,'fetch',async()=>new Response(new ReadableStream({start(stream){stream.enqueue(new TextEncoder().encode('id,action\n'));controller.abort();stream.error(new DOMException('The operation was aborted.','AbortError'));}})));
  await assert.rejects(api.apiDownload(exportPath,controller.signal),error=>!(error instanceof api.ApiError)&&error.name==='AbortError');
});

test('role rows escape content, show usage and hide actions for archived or out-of-reach roles',()=>{
  const html=render(gov.RoleRows,{roles:[role(),role({id:'ops',name:'Operations',permissions:['roles.manage'],archived:false}),role({id:'old',name:'Old',archived:true})],catalog,
    assignments:[{email:'bob@example.test',role_id:'auditor'}],groupRoles:[],grantable:['audit.read','sessions.read'],onEdit(){},onArchive(){}});
  assert.match(html,/Compliance &lt;b&gt;review&lt;\/b&gt;/);assert.doesNotMatch(html,/<b>review/);
  assert.match(html,/1 person · 0 groups/);assert.match(html,/Read the audit log/);
  assert.equal((html.match(/>Archive</g)||[]).length,1,'only the grantable active role can be archived');
  assert.match(html,/hold all of its permissions directly/);assert.match(html,/Archived/);
});

test('provisioning rows never render token secrets and state status in text',()=>{
  const tokens=[{id:'t1',label:'Okta',prefix:'moyai_scim_ab12',created_at:stamp,created_by:'admin@example.test',last_used_at:null,revoked_at:null,token:'NEVER_RENDER_SECRET',token_hash:'NEVER_RENDER_HASH'},
    {id:'t0',label:'Old',prefix:'moyai_scim_99zz',created_at:stamp,created_by:'',last_used_at:stamp,revoked_at:stamp}];
  const html=render(gov.TokenRows,{tokens,onRevoke(){}});
  assert.doesNotMatch(html,/NEVER_RENDER/);assert.match(html,/moyai_scim_ab12…/);assert.match(html,/Never used/);
  assert.equal((html.match(/>Revoke</g)||[]).length,1,'revoked tokens cannot be revoked again');
  assert.match(html,/aria-label="Provisioning tokens"/);assert.match(html,/tabindex="0"/);
  const users=render(gov.DirectoryUserRows,{users:[{id:'u',user_name:'dana@example.test',display_name:'',active:false,external_id:'',groups_count:0,updated_at:stamp}]});
  assert.match(users,/Deactivated/);assert.match(users,/dana@example.test/);
});

test('the network hint follows the deployment enforcement setting',()=>{
  for(const network of ['all','listed','none'])assert.match(gov.networkHint(network,'off'),/Network enforcement is off in this deployment, so sessions with a restricted network policy are refused before they start\.$/);
  assert.equal(gov.networkHint('all','modal'),'No outbound restriction is applied.');
  for(const network of ['listed','none']){const hint=gov.networkHint(network,'modal');
    assert.match(hint,/HTTPS \(port 443\) by hostname; plain HTTP, SSH and other ports are blocked\./);assert.match(hint,/DNS lookups are not restricted/);
    assert.match(hint,/shared CDN domain/);assert.match(hint,/Lambda computers refuse restricted policies/);assert.match(hint,/must restart\.$/);}
  assert.match(gov.networkHint('none','modal'),/^The machine cannot open outbound connections\./);assert.match(gov.networkHint('listed','modal'),/^Only these hostnames are reachable\./);
});

test('policy rows mark defaults, keep defaults enabled and summarize empty lists as nothing allowed',()=>{
  const defaults={default_profile_id:profile().id,mandatory_profile_id:'',revision:1,updated_at:stamp,updated_by:''};
  const other=profile({id:'f'.repeat(32),name:'Open',policy:{connected_apps:null,tools:null,git_access:'write',network_domains:[],repositories:null,models:null}});
  const html=render(gov.ProfileRows,{profiles:[profile(),other,profile({id:'e'.repeat(32),name:'Retired',enabled:false})],defaults,catalog:{connected_apps:[{id:'github',label:'GitHub'}],tools:[],repositories:[{id:7,label:'acme/app'}],models:[]},onEdit(){},onDisable(){},onEnable(){}});
  assert.match(html,/Default/);assert.match(html,/No tools/);assert.match(html,/No outbound network/);assert.match(html,/All connected apps/);
  assert.match(html,/<dt>Repositories<\/dt><dd>acme\/app, Repository 42<\/dd>/);assert.match(html,/<dt>Models<\/dt><dd>All models<\/dd>/);
  assert.equal((html.match(/>Disable</g)||[]).length,1,'the default policy cannot be disabled');assert.equal((html.match(/>Enable</g)||[]).length,1);
});

test('spend and audit rows: read-only viewers get no actions and details are escaped text',()=>{
  const overrides=render(gov.OverrideRows,{rows:[limit({id:'user:carol@example.test',kind:'user',subject:'carol@example.test',limit_usd:50,used_usd:60})],canManage:false,onEdit(){},onRemove(){}});
  assert.doesNotMatch(overrides,/>Edit<|>Remove</);assert.match(overrides,/Limit reached/);assert.doesNotMatch(overrides,/Actions/);
  const usage=(patch={})=>({organization_month_usd:10,period_start:'2026-10-01T00:00:00Z',unknown_requests:0,in_flight_requests:0,unresolved_requests:0,...patch});
  const summary=render(gov.SpendSummary,{data:{limits:limits(),usage:usage({organization_month_usd:6000}),can_manage:true}});
  assert.match(summary,/Limit reached/);assert.match(summary,/\$0\.00/);assert.doesNotMatch(summary,/still running|without a reported cost|could not be recovered/);
  const awaiting=render(gov.SpendSummary,{data:{limits:limits(),usage:usage({unknown_requests:2}),can_manage:true}});
  assert.match(awaiting,/Pending cost reconciliation/);assert.match(awaiting,/2 model requests finished without a reported cost/);
  // Running and unrecoverable requests do not block admission, so the remaining amount stays known.
  const reported=render(gov.SpendSummary,{data:{limits:limits(),usage:usage({in_flight_requests:3,unresolved_requests:1}),can_manage:true}});
  assert.match(reported,/Excludes 3 model requests still running/);assert.match(reported,/The cost of 1 model request could not be recovered/);
  assert.doesNotMatch(reported,/Pending cost reconciliation/);assert.match(reported,/\$4,990\.00/);
  assert.equal(render(gov.SpendSummary,{data:{limits:limits().map(row=>({...row,used_usd:null})),usage:null,can_manage:true}}),'','no summary without spend.read usage');
  const audit=render(gov.AuditRows,{entries:[{id:'a',source:'governance',action:'role.created',actor:'',resource_type:'role',resource_id:'<script>',details:{note:'<img src=x onerror=bad()>'},created_at:stamp}]});
  assert.doesNotMatch(audit,/<script>|<img/);assert.match(audit,/&lt;script&gt;/);assert.match(audit,/System/);assert.match(audit,/Role created/);
});

test('built-in role edits require explicit confirmation before replacing a custom role',()=>{
  const account={id:'bob',username:'bob',display_name:'Bob',role:'member',enabled:true,email:'bob@example.test',revision:4,access_role:{id:'auditor',name:'Auditor',revision:2}};
  assert.throws(()=>settings.productRoleBody(account,'member',false),/Confirm replacing the custom role Auditor/);
  assert.deepEqual(settings.productRoleBody(account,'member',true),{email:'bob@example.test',role:'member',revision:4,replace_custom_role:true,access_revision:2});
  const plain={...account,access_role:null};
  assert.equal(settings.productRoleBody(plain,'member',false),null,'an unchanged role sends nothing');
  assert.deepEqual(settings.productRoleBody(plain,'admin',false),{email:'bob@example.test',role:'admin',revision:4},'the existing body is unchanged without a custom role');
  assert.throws(()=>settings.productRoleBody(plain,'owner',false),/Administrator or Member/);
});

test('permission checks use /api/me permissions and fall back to built-in sets for older servers',()=>{
  assert.equal(permissions.can({role:'member',permissions:['audit.read']},'audit.read'),true);
  assert.equal(permissions.can({role:'admin',permissions:['audit.read']},'roles.manage'),false,'an explicit list is authoritative');
  assert.equal(permissions.can({role:'admin'},'roles.manage'),true);assert.equal(permissions.can({role:'member'},'users.read'),false);
  assert.equal(permissions.canOpenPage({role:'member',permissions:['spend.read']},'spend-limits'),true);
  assert.equal(permissions.canOpenPage({role:'member',permissions:['spend.manage']},'spend-limits'),true,'limit managers read the revisions they write');
  assert.equal(permissions.canOpenPage({role:'member',permissions:['runtime.manage']},'performance'),false,'performance reports include cost');
  assert.equal(permissions.canOpenPage({role:'member',permissions:['runtime.manage','spend.read']},'performance'),true);
  assert.equal(permissions.pagePermissionText('performance'),'runtime.manage and spend.read');
  assert.equal(permissions.pagePermissionText('spend-limits'),'spend.read or spend.manage');
  assert.equal(permissions.canOpenPage({role:'member',permissions:['spend.read']},'usage'),true);
  assert.equal(permissions.canOpenPage({role:'member',permissions:[]},'skills'),true);
  assert.equal(permissions.canOpenPage({role:'member',permissions:[]},'audit-log'),false);
  assert.equal(permissions.permissionKey({role:'member',permissions:['b','a']}),'a,b');
});

test('Home sends a chosen security policy only when it is still offered',()=>{
  const id='0123456789abcdef'.repeat(2);
  const chosen=homeSubmission('Task','model',true,[],[],[],id,[id]);
  assert.deepEqual(chosen.session,{model:'model',visibility:'private',security_profile_id:id});
  assert.notEqual(chosen.signature,homeSubmission('Task','model',true,[],[],[]).signature,'a different policy is a different admission');
  assert.deepEqual(homeSubmission('Task','model',false,[],[],[]).session,{model:'model',visibility:'shared'},'the default leaves the choice to the server');
  assert.throws(()=>homeSubmission('Task','model',true,[],[],[],id,[]),/no longer available/);
  assert.throws(()=>homeSubmission('Task','model',true,[],[],[],'../x',['../x']),/no longer available/);
});

const python=path.join(root,'.venv/bin/python');
test('the UI permission sets match the shared Python catalog',{skip:!fs.existsSync(python)&&'Native Python environment not installed'},()=>{
  const result=spawnSync(python,['-c','import json; from app.permissions import PERMISSIONS, MEMBER_PERMISSIONS; print(json.dumps({"all":sorted(PERMISSIONS),"member":sorted(MEMBER_PERMISSIONS)}))'],{cwd:root,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const value=JSON.parse(result.stdout);
  assert.deepEqual([...permissions.ALL_PERMISSIONS].sort(),value.all);assert.deepEqual([...permissions.MEMBER_PERMISSIONS].sort(),value.member);
});
