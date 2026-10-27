// Real React Settings → Governance pages against a synthetic governance API.
// The fixture proves presentation, request bodies and client gating only; the
// server's authorization, anti-escalation and SCIM behavior are tested in Python.
const assert = require('node:assert/strict');
const {test,before,after} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
let server,browser,base,state;
const screens = process.env.MOYAI_GOVERNANCE_SCREENS || '';
const P1='0123456789abcdef'.repeat(2), P2='fedcba9876543210'.repeat(2), P3='00112233445566778899aabbccddeeff';
const STALE='This changed elsewhere. Reload and try again.';
const stamp='2026-10-15T09:30:00+00:00';
const catalogRows=[
  ['workspace.read','View workspace settings','Workspace'],
  ['sessions.read','View sessions','Sessions'],['sessions.create','Start sessions','Sessions'],['sessions.manage','Steer and organize sessions','Sessions'],
  ['connections.read','Use connected apps to read','Connections'],['connections.write','Use connected apps to make changes','Connections'],['connections.manage','Manage organization connections','Connections'],
  ['automations.read','View automations','Automations'],['automations.manage','Manage automations','Automations'],
  ['environments.read','Use environments','Environments'],
  ['skills.read','Use skills','Skills'],['skills.manage','Manage personal skills','Skills'],['skills.publish','Publish organization skills','Skills'],
  ['memory.read','Recall memory','Memory'],['memory.manage','Manage memory','Memory'],
  ['credentials.read','Use credentials','Credentials'],['credentials.manage','Manage personal credentials','Credentials'],['credentials.publish','Manage organization credentials','Credentials'],
  ['users.read','View the user directory','People'],['users.manage','Change built-in roles','People'],['roles.manage','Manage custom roles and grants','People'],['scim.manage','Manage directory provisioning','People'],
  ['spend.personal','View personal spend','Spend'],['spend.read','View organization spend and limits','Spend'],['spend.manage','Manage spend limits and billing','Spend'],
  ['runtime.manage','View performance and runtime details','Operations'],['security.manage','Manage security policies','Security'],['audit.read','Read the audit log','Security'],
];
const ALL=catalogRows.map(row=>row[0]);
const MEMBER=['workspace.read','sessions.read','sessions.create','sessions.manage','connections.read','connections.write','automations.read','automations.manage','environments.read','skills.read','skills.manage','memory.read','memory.manage','credentials.read','credentials.manage','spend.personal'];
const entry=(id,action,resource_type,resource_id,details={},actor='admin@example.test',source='governance',created_at=stamp)=>({id,source,action,actor,resource_type,resource_id,details,created_at});
const MODELS=['test-model','openai/gpt-6-astra','openai/gpt-6-astra-ultrafast'], SID='c'.repeat(32);
// GitHub rows carry their permanent repository ID in policy.product, as the product catalog returns them.
const connection=(id,kind,name,repository_id=null)=>({id,name,kind,owner_id:'',shared:true,read_only:false,enabled:true,revision:1,source:'product',
  policy:{allowed_tools:null,require_approval:false,product:{repository_id}}});
const CONNECTIONS=[connection('gh-101','github','synthetic-org/api',101),connection('gh-102','github','synthetic-org/web',102),connection('linear','linear','Linear')];
const profile=(id,name,policy,patch={})=>({id,name,enabled:true,revision:2,policy:{connected_apps:null,tools:null,git_access:'write',network_domains:null,repositories:null,models:null,...policy},updated_at:stamp,updated_by:'admin@example.test',...patch});
function reset(overrides={}) {
  state={mode:'existing',role:'admin',permissions:[...ALL],accessRole:null,requests:[],conflict:false,forbidRoles:false,networkEnforcement:'off',
    connections:[],preferences:{delivery_mode:'when_idle',connection_ids:null},session:false,sessionModel:'test-model',sessionPolicy:null,
    roles:[
      {id:'auditor',name:'Auditor',description:'Read-only compliance access for reviews.',permissions:['audit.read','sessions.read','spend.read'],revision:3,archived:false,updated_at:stamp,updated_by:'admin@example.test'},
      {id:'contractor',name:'Contractor',description:'Project sessions without organization settings.',permissions:['sessions.create','sessions.read'],revision:1,archived:false,updated_at:stamp,updated_by:'admin@example.test'},
      {id:'legacy-ops',name:'Legacy operations',description:'',permissions:['runtime.manage'],revision:4,archived:true,updated_at:stamp,updated_by:'admin@example.test'},
    ],
    assignments:[{email:'bob@example.test',role_id:'auditor',role_name:'Auditor',revision:2,role_revision:4,updated_at:stamp,updated_by:'admin@example.test'}],
    groupRoles:[{group_id:'g-eng',group_name:'Engineering',role_id:'contractor',role_name:'Contractor',revision:1,updated_at:stamp,updated_by:'admin@example.test'}],
    groups:[{id:'g-eng',display_name:'Engineering',member_count:12},{id:'g-fin',display_name:'Finance',member_count:3}],
    tokens:[{id:'tok-1',label:'Okta production',prefix:'moyai_scim_ab12',created_at:stamp,created_by:'admin@example.test',last_used_at:stamp,revoked_at:null},
      {id:'tok-0',label:'Old connector',prefix:'moyai_scim_99zz',created_at:'2026-01-02T10:00:00+00:00',created_by:'admin@example.test',last_used_at:null,revoked_at:'2026-02-01T10:00:00+00:00'}],
    profiles:[profile(P1,'Standard engineering',{network_domains:['github.com','registry.npmjs.org','*.githubusercontent.com']}),
      profile(P2,'Restricted review',{connected_apps:['github'],tools:['read_file','search_files'],git_access:'read',network_domains:[],repositories:[101,9001],models:['openai/gpt-6-astra']},{revision:5}),
      profile(P3,'Retired policy',{git_access:'none'},{enabled:false,revision:1})],
    defaults:{default_profile_id:P1,mandatory_profile_id:'',revision:2,updated_at:stamp,updated_by:'admin@example.test'},
    limits:[
      {id:'organization',kind:'organization',subject:'',limit_usd:5000,revision:3,updated_at:stamp,updated_by:'admin@example.test',used_usd:1234.56},
      {id:'user-default',kind:'user-default',subject:'',limit_usd:200,revision:1,updated_at:stamp,updated_by:'admin@example.test',used_usd:null},
      {id:'session-default',kind:'session-default',subject:'',limit_usd:null,revision:0,updated_at:null,updated_by:'',used_usd:null},
      {id:'user:carol@example.test',kind:'user',subject:'carol@example.test',limit_usd:500,revision:2,updated_at:stamp,updated_by:'admin@example.test',used_usd:87.1},
    ],
    users:[
      {email:'admin@example.test',name:'Synthetic admin',role:'admin',revision:1,access_role:null,active:true},
      {email:'bob@example.test',name:'Bob Reviewer',role:'member',revision:4,access_role:{id:'auditor',name:'Auditor',revision:2},active:true},
      {email:'dana@example.test',name:'Dana Former',role:'member',revision:0,access_role:null,active:false},
    ],
    ...overrides};
}
const scimUsers=[
  [{id:'u1',user_name:'bob@example.test',display_name:'Bob Reviewer',active:true,external_id:'00u1bob',groups_count:2,updated_at:stamp},
   {id:'u2',user_name:'dana@example.test',display_name:'Dana Former',active:false,external_id:'00u2dana',groups_count:0,updated_at:stamp}],
  [{id:'u3',user_name:'erin@example.test',display_name:'Erin Analyst',active:true,external_id:'',groups_count:1,updated_at:stamp}],
];
const auditPages=[
  [entry('a1','role.created','role','auditor',{permissions:['audit.read','sessions.read']}),entry('a2','scim_token.revoked','scim_token','tok-0',{label:'Old connector'}),
   entry('a3','role.changed','user_role','bob@example.test',{previous:'member',replacement:'admin'},'admin@example.test','user_roles')],
  [entry('a4','spend_limit.updated','spend_limit','organization',{limit_usd:5000,previous_usd:null}),
   entry('a5','ai_guardrail.violation','ai_guardrail','phi-presidio',{session_id:'s1',model:'openai/gpt-6-astra',mode:'pre_call',guardrails:['phi-presidio','prompt-injection']},'bob@example.test')],
];
const rolesView=()=>({roles:state.roles,assignments:state.assignments,group_roles:state.groupRoles,groups:state.groups,grantable:state.role==='admin'?null:state.permissions,builtin_admin:state.role==='admin'});
// Like the server, spend.manage alone can read the listing, and both GET and writes return
// null usage totals (and a null used_usd on each row) to a caller without spend.read.
const spendView=(usage=true)=>({limits:usage?state.limits:state.limits.map(row=>({...row,used_usd:null})),
  usage:usage?{organization_month_usd:1234.56,period_start:'2026-10-01T00:00:00+00:00',unknown_requests:0}:null,can_manage:state.permissions.includes('spend.manage')});
async function handle(req,res,next) {
  const url=new URL(req.url,'http://localhost');
  if(!url.pathname.startsWith('/api/'))return next();
  let body=''; for await(const chunk of req)body+=chunk;
  const data=body?JSON.parse(body):null, method=req.method, p=decodeURIComponent(url.pathname);
  state.requests.push({path:p,query:url.search,method,body:data,csrf:req.headers['x-moyai-csrf']});
  const json=(value,status=200)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));};
  const has=permission=>state.permissions.includes(permission);
  const deny=()=>json({detail:'Your workspace role does not allow this action.'},403);
  if(p==='/api/me')return json({user:{id:'admin@example.test',name:'Synthetic admin',role:state.role,individual:true},csrf:'fixture-csrf',models:MODELS,default_model:'test-model',product_mode:state.mode,preferences:state.preferences,
    ...(state.omitPermissions?{}:{permissions:state.permissions,access_role:state.accessRole})});
  if(p==='/api/connections')return json(state.connections);
  if(p==='/api/session-folders')return json([]);
  // Like ProductGovernance.new_session_policy: the selected or default profile, and session_model's implicit choice.
  const newSession=requested=>{
    const chosen=state.profiles.find(row=>row.id===(requested||state.defaults.default_profile_id)&&row.enabled);
    const policy=chosen?.policy??profile('','',{}).policy, allowed=MODELS.filter(model=>policy.models===null||policy.models.includes(model));
    return {policy,default_model:allowed.includes('test-model')?'test-model':allowed[0]??null};
  };
  if(p==='/api/security-policy/new-session'){
    const requested=url.searchParams.get('profile_id')||'';
    if(requested&&!has('security.manage'))return deny();
    return json(newSession(requested));
  }
  const governed=()=>({id:SID,title:'Governed work',owner_id:'admin@example.test',visibility:'shared',surface:'web',model:state.sessionModel,status:'idle',active_turn:null,archived:false,deleted:false,pinned:false,folder:'',can_manage:true});
  if(state.session&&p===`/api/sessions/${SID}`&&method==='GET')return json({session:governed(),reference:{...governed(),source:'native',url:'/#'+SID},turns:[],messages:[],activity:[],effects:[],pending:null,goal:null,
    can_answer:null,can_reply_with_text:null,credential_requests:null,has_unsettled_effects:false,question_deadline:null,slack_delivery:null,transcript_version:null});
  if(state.session&&p===`/api/sessions/${SID}/security-policy`){await state.policyGate;return json({policy:state.sessionPolicy});}
  if(state.session&&p===`/api/sessions/${SID}/read`)return json({});
  if(p==='/api/pull-requests/statuses')return json({});
  if(p==='/api/history/sessions'||p==='/api/history/search')return json({sessions:[],ancestors:[],has_more:false,next_cursor:null,notice:null});
  // As session_model: an explicitly requested model must be allowed by the policy the session binds.
  if(p==='/api/sessions'&&method==='POST'&&data.model&&!(newSession(data.security_profile_id).policy.models??[data.model]).includes(data.model))
    return json({detail:'This model is not allowed by the session security policy.'},403);
  if(p==='/api/sessions'&&method==='POST')return json({id:'c'.repeat(32),title:'New conversation',owner_id:'admin@example.test',visibility:data.visibility,surface:'web',model:'test-model',status:'idle',active_turn:null,archived:false});
  if(p==='/api/sessions')return json([]);
  if(p.startsWith('/api/sessions/')&&p.endsWith('/messages')&&method==='POST')return json({id:'turn-1',session_id:'c'.repeat(32),status:'queued',actor_id:'admin@example.test',connections:[]});
  if(p.startsWith('/api/sessions/'))return json({detail:'Not part of this fixture.'},404);
  if(p==='/api/security-profiles')return json({profiles:state.profiles.filter(row=>row.enabled).map(({id,name,policy})=>({id,name,policy})),default_profile_id:state.defaults.default_profile_id,mandatory:null});
  if(p==='/api/permissions')return json({permissions:state.permissions,catalog:catalogRows.map(([id,label,group])=>({id,label,group,description:`Synthetic description for ${id}.`})),builtin_roles:{admin:ALL,member:MEMBER}});
  // Roles & access
  if(p.startsWith('/api/admin/roles')||p.startsWith('/api/admin/role-assignments')||p.startsWith('/api/admin/group-roles')) {
    if(!has('roles.manage')||state.forbidRoles){state.permissions=[...MEMBER];return deny();}
    if(p==='/api/admin/roles'&&method==='GET')return json(rolesView());
    if(p==='/api/admin/roles'&&method==='POST'){const role={...data,revision:1,archived:false,updated_at:stamp,updated_by:'admin@example.test'};state.roles.push(role);return json(role,201);}
    const roleMatch=p.match(/^\/api\/admin\/roles\/([^/]+)$/);
    if(roleMatch){const role=state.roles.find(row=>row.id===decodeURIComponent(roleMatch[1]));if(!role)return json({detail:'Role not found.'},404);
      if(state.conflict)return json({detail:STALE},409);
      if(method==='PUT'){Object.assign(role,{name:data.name,description:data.description,permissions:data.permissions,revision:role.revision+1});return json(role);}
      if(method==='DELETE'){if(Number(url.searchParams.get('revision'))!==role.revision)return json({detail:STALE},409);role.archived=true;role.revision++;return json(role);}}
    if(p==='/api/admin/role-assignments'&&method==='PUT'){
      const existing=state.assignments.find(row=>row.email===data.email);
      if((existing?.revision??0)!==data.revision)return json({detail:STALE},409);
      if(data.role_id==='member'){state.assignments=state.assignments.filter(row=>row.email!==data.email);return json({email:data.email,role_id:'member',role_name:'Member',revision:data.revision+1,role_revision:0,updated_at:stamp,updated_by:'admin@example.test'});}
      const role=state.roles.find(row=>row.id===data.role_id);const row={email:data.email,role_id:data.role_id,role_name:role.name,revision:data.revision+1,role_revision:data.role_revision??0,updated_at:stamp,updated_by:'admin@example.test'};
      state.assignments=[...state.assignments.filter(item=>item.email!==data.email),row];return json(row);}
    const groupMatch=p.match(/^\/api\/admin\/group-roles\/([^/]+)$/);
    if(groupMatch&&method==='PUT'){const id=decodeURIComponent(groupMatch[1]),group=state.groups.find(row=>row.id===id),role=state.roles.find(row=>row.id===data.role_id);
      const row={group_id:id,group_name:group.display_name,role_id:data.role_id,role_name:role?.name??null,revision:data.revision+1,updated_at:stamp,updated_by:'admin@example.test'};
      state.groupRoles=[...state.groupRoles.filter(item=>item.group_id!==id),row];return json(row);}
  }
  // Provisioning
  if(p.startsWith('/api/admin/scim')) {
    if(!has('scim.manage'))return deny();
    if(p==='/api/admin/scim'&&method==='GET'){const page=url.searchParams.get('cursor')==='users-2'?1:0;
      return json({base_url:'https://moyai.example.test/scim/v2',users:{items:page&&state.emptyNextPage?[]:scimUsers[page],next_cursor:page?null:'users-2'},
        groups:state.groups.map(group=>{const grant=state.groupRoles.find(row=>row.group_id===group.id&&row.role_id);return {...group,role_id:grant?.role_id??null,role_name:grant?.role_name??null};}),
        tokens:state.tokens,activity:[entry('s1','scim_user.deactivated','scim_user','u2',{},'Okta production'),entry('s2','scim_token.created','scim_token','tok-1')],can_create_tokens:state.role==='admin'});}
    // 201 with the token record plus its one-time secret, as a single object.
    if(p==='/api/admin/scim/tokens'&&method==='POST'){const token={id:'tok-2',label:data.label,prefix:'moyai_scim_new1',created_at:stamp,created_by:'admin@example.test',last_used_at:null,revoked_at:null};
      state.tokens=[token,...state.tokens];return json({...token,token:'moyai_scim_new1_SYNTHETIC_ONE_TIME_SECRET'},201);}
    const tokenMatch=p.match(/^\/api\/admin\/scim\/tokens\/([^/]+)$/);
    // 200 with the revoked token record.
    if(tokenMatch&&method==='DELETE'){const token=state.tokens.find(row=>row.id===decodeURIComponent(tokenMatch[1]));token.revoked_at=stamp;return json(token);}
  }
  // Security policies
  if(p.startsWith('/api/admin/security-profiles')) {
    if(!has('security.manage'))return deny();
    if(p==='/api/admin/security-profiles'&&method==='GET')return json({profiles:state.profiles,defaults:state.defaults,catalog:{
      connected_apps:[{id:'github',label:'GitHub'},{id:'linear',label:'Linear'},{id:'slack',label:'Slack'},{id:'notion',label:'Notion'}],
      tools:[{id:'read_file',label:'Read files',group:'Workspace'},{id:'write_file',label:'Write files',group:'Workspace'},{id:'search_files',label:'Search files',group:'Workspace'},{id:'run_shell',label:'Run shell commands',group:'Workspace'},
        {id:'create_pull_request',label:'Create pull request',group:'GitHub'},{id:'update_pull_request',label:'Update pull request',group:'GitHub'},{id:'browser_navigate',label:'Browse the web',group:'Browser'},{id:'memory_save',label:'Save memory',group:'Memory'}],
      repositories:[{id:101,label:'synthetic-org/api'},{id:102,label:'synthetic-org/web'},{id:103,label:'synthetic-org/infra'}],
      models:[{id:'openai/gpt-6-astra',label:'GPT-6 Astra'},{id:'openai/gpt-6-astra-ultrafast',label:'GPT-6 Astra Ultrafast'},{id:'anthropic/claude-opus-5-5',label:'Claude Opus 5.5'}],
      network_enforcement:state.networkEnforcement}});
    if(p==='/api/admin/security-profiles/defaults'&&method==='PUT'){if(data.revision!==state.defaults.revision)return json({detail:STALE},409);state.defaults={...data,revision:data.revision+1,updated_at:stamp,updated_by:'admin@example.test'};return json(state.defaults);}
    if(p==='/api/admin/security-profiles'&&method==='POST'){const row={...profile('abcdefabcdefabcdefabcdefabcdefab',data.name,data.policy),enabled:data.enabled,revision:1};state.profiles.push(row);return json(row,201);}
    const match=p.match(/^\/api\/admin\/security-profiles\/([0-9a-f]{32})$/);
    if(match){const row=state.profiles.find(item=>item.id===match[1]);
      if(method==='PUT'){if(data.revision!==row.revision)return json({detail:STALE},409);Object.assign(row,{name:data.name,enabled:data.enabled,policy:data.policy,revision:row.revision+1});return json(row);}
      if(method==='DELETE'){row.enabled=false;row.revision++;return json(row);}}
  }
  // Spend limits
  if(p.startsWith('/api/admin/spend-limits')) {
    if(!has('spend.read')&&!has('spend.manage'))return deny();
    if(method==='GET')return json(spendView(has('spend.read')));
    // Writes always return the full listing; usage depends on the caller's spend.read.
    const listing=()=>spendView(has('spend.read'));
    if(!has('spend.manage'))return deny();
    if(method==='PUT'){for(const change of data.changes){const row=state.limits.find(item=>item.id===change.id);
        if((row?.revision??0)!==change.revision)return json({detail:STALE},409);}
      for(const change of data.changes){const row=state.limits.find(item=>item.id===change.id);
        if(row)Object.assign(row,{limit_usd:change.limit_usd,revision:row.revision+1,updated_at:stamp});
        else state.limits.push({id:change.id,kind:'user',subject:change.id.slice(5),limit_usd:change.limit_usd,revision:1,updated_at:stamp,updated_by:'admin@example.test',used_usd:0});}
      return json(listing());}
    const match=p.match(/^\/api\/admin\/spend-limits\/(.+)$/);
    if(match&&method==='DELETE'){const id=decodeURIComponent(match[1]),row=state.limits.find(item=>item.id===id);
      if(!row||Number(url.searchParams.get('revision'))!==row.revision)return json({detail:STALE},409);
      state.limits=state.limits.filter(item=>item.id!==id);return json(listing());}
  }
  // Audit log
  if(p==='/api/admin/governance/audit/export') {
    if(!has('audit.read'))return deny();
    if(state.exportError)return json({detail:state.exportError},400);
    const format=url.searchParams.get('format');
    res.writeHead(200,{'Content-Type':format==='csv'?'text/csv':'application/x-ndjson','Content-Disposition':`attachment; filename="governance.${format}"`,'Cache-Control':'no-store'});
    return res.end(format==='csv'?'id,action\na2,scim_token.revoked\n':'{"id":"a2","action":"scim_token.revoked"}\n');
  }
  if(p==='/api/admin/governance/audit') {
    if(!has('audit.read'))return deny();
    const page=url.searchParams.get('cursor')==='audit-2'?1:0;
    let entries=page&&state.emptyNextPage?[]:auditPages[page];
    if(url.searchParams.get('action'))entries=entries.filter(row=>row.action===url.searchParams.get('action'));
    return json({entries,next_cursor:page||url.searchParams.get('action')?null:'audit-2',facets:{actions:['ai_guardrail.violation','role.created','role.changed','scim_token.revoked','spend_limit.updated'],resource_types:['role','user_role','scim_token','spend_limit','ai_guardrail']}});
  }
  // Users directory (existing route, governance fields)
  if(p==='/api/settings/users')return has('users.read')?json({source:'product',note:'Organization sign-in manages accounts.',capabilities:{roles:has('users.manage'),create:false,update:false,delete:false},
    users:state.users.map(row=>({...row,id:row.email,username:row.email,display_name:row.name,enabled:true}))}):deny();
  if(p==='/api/settings/users/role')return json({email:data.email,role:data.role,revision:data.revision+1});
  if(p==='/api/settings/overview')return json({counts:{},capabilities:{}});
  return json({detail:'Fixture endpoint not implemented: '+p},404);
}
async function waitFor(predicate,label='condition') {const end=Date.now()+10000;while(!predicate()){if(Date.now()>end)throw new Error('Timed out: '+label);await new Promise(resolve=>setTimeout(resolve,25));}}
const last=(pathname,method)=>[...state.requests].reverse().find(req=>req.path===pathname&&(!method||req.method===method));
async function pageFor(t,route,width=1440,height=1000) {
  const context=await browser.newContext({viewport:{width,height},reducedMotion:'reduce',permissions:['clipboard-read','clipboard-write']});
  const page=await context.newPage();t.after(()=>context.close());
  const errors=[];page.on('pageerror',error=>errors.push(error.message));t.after(()=>assert.deepEqual(errors,[]));
  await page.goto(base+'/'+route);return page;
}
async function choose(scope,page,label,option) {await scope.getByRole('combobox',{name:label}).click();await page.getByRole('option',{name:option,exact:true}).click();}
async function noOverflow(page,width) {
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`document overflows at ${width}px`);
  const wide=await page.evaluate(()=>[...document.querySelectorAll('.ns-content *')].filter(el=>{const box=el.getBoundingClientRect();return box.width>0&&box.right>innerWidth+1&&!el.closest('.ns-table');}).map(el=>el.className||el.tagName).slice(0,5));
  assert.deepEqual(wide,[],`elements extend past the viewport at ${width}px`);
}
async function shoot(page,name) {
  if(!screens)return;
  fs.mkdirSync(screens,{recursive:true});
  const size=page.viewportSize(), height=await page.evaluate(()=>{const content=document.querySelector('.ns-content');return content?content.scrollHeight+content.getBoundingClientRect().top+8:document.body.scrollHeight;});
  await page.setViewportSize({width:size.width,height:Math.min(Math.max(size.height,Math.ceil(height)),7000)});
  await page.waitForTimeout(150);await page.screenshot({path:path.join(screens,name)});
  await page.setViewportSize(size);
}
before(async()=>{
  reset();const {createServer}=await import('vite');
  server=await createServer({configFile:path.resolve('native/web/vite.config.ts'),server:{host:'127.0.0.1',port:0,strictPort:false},plugins:[{name:'synthetic-governance-api',configureServer(vite){vite.middlewares.use((req,res,next)=>{void handle(req,res,next).catch(error=>{res.writeHead(500);res.end(JSON.stringify({detail:error.message}));});});}}]});
  await server.listen();base=`http://127.0.0.1:${server.httpServer.address().port}`;browser=await chromium.launch({headless:true});
});
after(async()=>{await browser?.close();await server?.close();});

const pages=[
  {id:'roles',title:'Roles & access',ready:'Custom roles',api:'/api/admin/roles'},
  {id:'provisioning',title:'Provisioning',ready:'Provisioning tokens',api:'/api/admin/scim'},
  {id:'security-policies',title:'Security policies',ready:'Organization defaults',api:'/api/admin/security-profiles'},
  {id:'spend-limits',title:'Spend limits',ready:'Per-person overrides',api:'/api/admin/spend-limits'},
  {id:'audit-log',title:'Audit log',ready:'Apply filters',api:'/api/admin/governance/audit'},
];

for(const width of [1440,768,320])test(`governance pages render with one heading, labelled tables and no overflow at ${width}px`,async t=>{
  reset();const page=await pageFor(t,'#settings/overview',width);
  await page.locator('#native-settings-content').getByRole('heading',{name:'Governance',exact:true}).waitFor();
  for(const item of pages) {
    await page.evaluate(id=>{location.hash='settings/'+id;},item.id);
    await page.getByRole('heading',{level:1,name:item.title,exact:true}).waitFor();
    await page.getByText(item.ready,{exact:true}).first().waitFor();
    assert.equal(await page.getByRole('heading',{level:1}).count(),1,`${item.id} has one page heading`);
    assert.equal(await page.title(),`${item.title} · Moyai`);
    for(const region of await page.locator('.ns-table').all()) {assert.ok(await region.getAttribute('aria-label'));assert.equal(await region.getAttribute('tabindex'),'0');}
    await noOverflow(page,width);
    if(width!==768)await shoot(page,`${item.id}-${width}.png`);
  }
  if(width!==768){await page.evaluate(()=>{location.hash='settings/users';});await page.getByRole('heading',{level:1,name:'Users'}).waitFor();await page.getByText('bob@example.test').first().waitFor();await shoot(page,`users-${width}.png`);
    await page.evaluate(()=>{location.hash='settings/overview';});await page.getByRole('heading',{level:1,name:'Settings'}).waitFor();await shoot(page,`overview-${width}.png`);}
});

test('navigation, palette and direct routes follow permissions, and standalone hides governance',async t=>{
  reset({role:'member',permissions:[...MEMBER,'audit.read','spend.read']});
  const page=await pageFor(t,'#settings/overview');const nav=page.getByRole('navigation',{name:'Settings'});
  await nav.getByRole('link',{name:'Audit log'}).waitFor();
  assert.deepEqual(await nav.locator('section').filter({hasText:'Governance'}).getByRole('link').allTextContents(),['Spend limits','Audit log']);
  assert.equal(await nav.getByRole('link',{name:'Users'}).count(),0);
  await page.evaluate(()=>{location.hash='settings/roles';});
  await page.getByRole('heading',{name:'Permission required'}).waitFor();
  assert.ok(!state.requests.some(req=>req.path==='/api/admin/roles'),'no protected request without the permission');
  await page.evaluate(()=>{location.hash='settings/spend-limits';});await page.getByText('You can view limits. Changing them requires the spend.manage permission.').waitFor();
  assert.equal(await page.getByRole('button',{name:'Save limits'}).count(),0);assert.equal(await page.getByRole('button',{name:/Add override/}).count(),0);
  await page.keyboard.press('Control+k');const palette=page.getByRole('dialog',{name:'Commands and session search'});await palette.getByRole('combobox').fill('Roles');
  assert.equal(await palette.getByRole('option',{name:/Roles & access/}).count(),0);
  await palette.getByRole('combobox').fill('Audit');await palette.getByRole('option',{name:/Audit log/}).waitFor();await page.keyboard.press('Escape');
  await page.evaluate(()=>{location.hash='settings/overview';});reset({mode:'standalone'});await page.reload();await page.locator('#native-settings-content').getByRole('heading',{name:'Administration',exact:true}).waitFor();
  assert.equal(await page.getByRole('heading',{name:'Governance',exact:true}).count(),0);
  reset({omitPermissions:true,role:'member'});await page.reload();await page.locator('#native-settings-content').getByRole('heading',{name:'Workflows',exact:true}).waitFor();
  assert.equal(await page.getByRole('heading',{name:'Administration',exact:true}).count(),0,'older servers fall back to the built-in member set');
});

test('roles: create with grouped permissions, assign by email, grant a group and archive with an explained effect',async t=>{
  reset();const page=await pageFor(t,'#settings/roles');
  await page.getByRole('heading',{name:'Auditor'}).waitFor();
  const meReads=()=>state.requests.filter(req=>req.path==='/api/me').length,reads=meReads();
  assert.equal(await page.getByRole('heading',{name:'Legacy operations'}).count(),0,'archived roles are filtered out by default');
  await page.getByRole('button',{name:'New role',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'New role'});await dialog.waitFor();
  assert.equal(await dialog.getByRole('textbox',{name:'Role name'}).evaluate(el=>el===document.activeElement),true);
  await dialog.getByRole('textbox',{name:'Role name'}).fill('Finance Reviewer');
  assert.equal(await dialog.getByRole('textbox',{name:'Role ID'}).inputValue(),'finance-reviewer');
  assert.equal(await dialog.getByRole('group',{name:'People'}).count(),1);
  for(const name of ['Read the audit log','View organization spend and limits','View sessions'])await dialog.getByRole('checkbox',{name}).click();
  for(let index=0;index<40;index++)await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(()=>Boolean(document.activeElement?.closest('[role=dialog]'))),true,'focus stays in the dialog');
  await dialog.getByRole('button',{name:'Create role'}).click();await dialog.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/roles','POST').body,{id:'finance-reviewer',name:'Finance Reviewer',description:'',permissions:['audit.read','sessions.read','spend.read']});
  await page.getByRole('heading',{name:'Finance Reviewer'}).waitFor();

  await page.getByRole('button',{name:'Assign role',exact:true}).click();
  const assign=page.getByRole('dialog',{name:'Assign a custom role'});await assign.getByRole('textbox',{name:'Work email'}).fill('  Erin@Example.test ');
  await choose(assign,page,'Role','Contractor');await assign.getByRole('button',{name:'Assign role'}).click();await assign.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/role-assignments','PUT').body,{email:'erin@example.test',role_id:'contractor',revision:0,role_revision:null});

  await page.getByRole('button',{name:'Change role for bob@example.test'}).click();
  const change=page.getByRole('dialog',{name:'Change role for bob@example.test'});assert.equal(await change.getByRole('textbox',{name:'Work email'}).isDisabled(),true);
  await choose(change,page,'Role','Finance Reviewer');await change.getByRole('button',{name:'Assign role'}).click();await change.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/role-assignments','PUT').body,{email:'bob@example.test',role_id:'finance-reviewer',revision:2,role_revision:4});

  await page.getByRole('button',{name:'Change grant for Finance'}).click();
  const grant=page.getByRole('dialog',{name:'Grant for Finance'});await choose(grant,page,'Additional role','Auditor');await grant.getByRole('button',{name:'Save grant'}).click();await grant.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/group-roles/g-fin','PUT').body,{role_id:'auditor',revision:0});

  await page.getByRole('button',{name:'Archive Contractor'}).click();
  const archive=page.getByRole('dialog',{name:'Archive Contractor?'});
  await archive.getByText(/1 person is assigned this role directly\. They lose all of its permissions immediately/).waitFor();
  await archive.getByText(/1 directory group stops adding its permissions/).waitFor();
  await archive.getByRole('button',{name:'Cancel'}).click();await archive.waitFor({state:'hidden'});
  assert.equal(state.requests.filter(req=>req.method==='DELETE').length,0,'cancel sends nothing');
  await page.getByRole('button',{name:'Archive Contractor'}).click();await page.getByRole('dialog',{name:'Archive Contractor?'}).getByRole('button',{name:'Archive role'}).click();
  await waitFor(()=>last('/api/admin/roles/contractor','DELETE'));assert.equal(last('/api/admin/roles/contractor','DELETE').query,'?revision=1');
  await page.getByRole('heading',{name:'Contractor'}).waitFor({state:'detached'});
  // The server refuses changes that reach the signed-in person, so saves only refresh this page.
  assert.equal(meReads(),reads,'successful saves do not re-read access or reset the workspace');
});

test('roles: a stale edit offers reload and a 403 clears the page once permission is lost',async t=>{
  reset({conflict:true});const page=await pageFor(t,'#settings/roles');
  await page.getByRole('button',{name:'Edit Auditor'}).click();const dialog=page.getByRole('dialog',{name:'Edit Auditor'});
  assert.equal(await dialog.getByRole('textbox',{name:'Role ID'}).isDisabled(),true);
  await dialog.getByRole('checkbox',{name:'View sessions'}).click();await dialog.getByRole('button',{name:'Save role'}).click();
  await dialog.getByRole('alert').getByText(STALE).waitFor();
  assert.deepEqual(last('/api/admin/roles/auditor','PUT').body,{name:'Auditor',description:'Read-only compliance access for reviews.',permissions:['audit.read','spend.read'],revision:3});
  const reads=state.requests.filter(req=>req.path==='/api/admin/roles'&&req.method==='GET').length;
  await dialog.getByRole('button',{name:'Reload'}).click();await dialog.waitFor({state:'hidden'});
  await waitFor(()=>state.requests.filter(req=>req.path==='/api/admin/roles'&&req.method==='GET').length>reads,'reload');
  state.conflict=false;state.forbidRoles=true;
  await page.getByRole('button',{name:'Edit Auditor'}).click();const again=page.getByRole('dialog',{name:'Edit Auditor'});await again.getByRole('button',{name:'Save role'}).click();
  await page.getByRole('heading',{name:'Permission required'}).waitFor();
  assert.equal(await page.getByRole('heading',{name:'Auditor'}).count(),0,'protected role data is removed');
  assert.equal(await page.getByRole('navigation',{name:'Settings'}).getByRole('link',{name:'Roles & access'}).count(),0);
});

test('provisioning: copy the SCIM URL, show a new token once, page directory users and revoke with confirmation',async t=>{
  reset();const page=await pageFor(t,'#settings/provisioning');
  await page.getByRole('textbox',{name:'SCIM base URL'}).waitFor();assert.equal(await page.getByRole('textbox',{name:'SCIM base URL'}).inputValue(),'https://moyai.example.test/scim/v2');
  await page.getByRole('button',{name:'Copy SCIM base URL'}).click();await page.getByText('Copied to the clipboard.').waitFor();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'https://moyai.example.test/scim/v2');
  await page.getByRole('button',{name:'Create token'}).click();
  const dialog=page.getByRole('dialog',{name:'Create provisioning token'});await dialog.getByRole('textbox',{name:'Token label'}).fill('Entra staging');
  await dialog.getByRole('button',{name:'Create token'}).click();
  const reveal=page.getByRole('dialog',{name:'Copy your provisioning token'});await reveal.waitFor();
  assert.deepEqual(last('/api/admin/scim/tokens','POST').body,{label:'Entra staging'});
  await reveal.getByRole('alert').getByText('This token is shown only once.').waitFor();
  // The one-time view reads the label and secret from the created token object.
  const secret=reveal.getByRole('textbox',{name:'Bearer token for Entra staging'});assert.equal(await secret.inputValue(),'moyai_scim_new1_SYNTHETIC_ONE_TIME_SECRET');
  assert.equal(await secret.evaluate(el=>el===document.activeElement),true);
  assert.equal(await reveal.getByRole('button',{name:'Close'}).count(),0,'only Done closes the one-time view');
  await page.keyboard.press('Escape');assert.equal(await reveal.isVisible(),true,'Escape cannot discard the token');
  await reveal.getByRole('button',{name:/^Copy/}).click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'moyai_scim_new1_SYNTHETIC_ONE_TIME_SECRET');
  await shoot(page,'provisioning-token-dialog-1440.png');
  await reveal.getByRole('button',{name:'Done'}).click();await reveal.waitFor({state:'hidden'});
  assert.equal(await page.getByText('SYNTHETIC_ONE_TIME_SECRET',{exact:false}).count(),0);
  assert.equal(await page.evaluate(()=>document.body.innerHTML.includes('SYNTHETIC_ONE_TIME_SECRET')),false,'the secret is not retained in the DOM');
  await page.getByRole('cell',{name:/^Entra staging/}).waitFor();
  const users=page.getByRole('region',{name:'Directory users'});await users.getByText('Dana Former').waitFor();await users.getByText('Deactivated',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Load more users'}).click();await users.getByText('Erin Analyst').waitFor();
  assert.equal(await page.getByRole('button',{name:'Load more users'}).count(),0);
  await choose(page,page,'Directory status','Deactivated');assert.equal(await users.getByText('Bob Reviewer').count(),0);await users.getByText('Dana Former').waitFor();
  await page.getByRole('button',{name:'Revoke Okta production'}).click();const revoke=page.getByRole('dialog',{name:'Revoke Okta production?'});
  await revoke.getByText(/can no longer sync with this token/).waitFor();await revoke.getByRole('button',{name:'Revoke token'}).click();await revoke.waitFor({state:'hidden'});
  assert.ok(last('/api/admin/scim/tokens/tok-1','DELETE'));
  await page.getByRole('button',{name:'Revoke Okta production'}).waitFor({state:'detached'});
  assert.equal(await page.getByRole('row').filter({hasText:'Okta production'}).getByText('Revoked',{exact:true}).count(),1,'the revoked token is listed as revoked');
  await page.getByRole('region',{name:'Directory groups'}).getByText('Contractor').waitFor();
});

test('security policies: explicit null-versus-empty choices, validation, defaults and disable',async t=>{
  reset();const page=await pageFor(t,'#settings/security-policies');
  await page.getByRole('heading',{name:'Restricted review'}).waitFor();
  const restricted=page.locator('article').filter({hasText:'Restricted review'});
  await restricted.getByText('No outbound network').waitFor();await restricted.getByText('Read only').waitFor();await restricted.getByText('GitHub',{exact:true}).waitFor();
  await restricted.getByText('synthetic-org/api, Repository 9001').waitFor();await restricted.getByText('GPT-6 Astra',{exact:true}).waitFor();
  await page.locator('article').filter({hasText:'Standard engineering'}).getByText('All repositories').waitFor();
  await page.getByRole('searchbox',{name:'Search policies'}).fill('synthetic-org/api');
  assert.deepEqual(await page.locator('article h3').allTextContents(),['Restricted review'],'repository names are searchable');
  await page.getByRole('searchbox',{name:'Search policies'}).fill('');
  await page.getByRole('button',{name:'New policy'}).click();const dialog=page.getByRole('dialog',{name:'New security policy'});
  await dialog.getByRole('textbox',{name:'Policy name'}).fill('Contractor sandbox');
  await choose(dialog,page,'Connected apps','No connected apps');
  await choose(dialog,page,'Agent tools','Only selected tools');
  await dialog.getByRole('group',{name:/Allowed tools/}).waitFor();
  await dialog.getByRole('searchbox',{name:'Filter tools'}).fill('files');assert.equal(await dialog.getByRole('checkbox',{name:'Run shell commands'}).count(),0);
  await dialog.getByRole('checkbox',{name:'Read files'}).click();await dialog.getByRole('checkbox',{name:'Search files'}).click();
  await choose(dialog,page,'Git access','No Git access');
  await choose(dialog,page,'Repositories','Only selected repositories');
  await dialog.getByRole('group',{name:'Allowed repositories, 0 selected'}).waitFor();
  await dialog.getByRole('searchbox',{name:'Filter repositories'}).fill('web');assert.equal(await dialog.getByRole('checkbox',{name:'synthetic-org/api'}).count(),0);
  await dialog.getByRole('checkbox',{name:'synthetic-org/web'}).click();await dialog.getByRole('group',{name:'Allowed repositories, 1 selected'}).waitFor();
  await dialog.getByRole('searchbox',{name:'Filter repositories'}).fill('');await dialog.getByRole('checkbox',{name:'synthetic-org/api'}).click();
  await dialog.getByText(/Every other repository is refused, including public ones/).waitFor();
  await choose(dialog,page,'Models','Only selected models');
  await dialog.getByRole('checkbox',{name:'GPT-6 Astra Ultrafast'}).click();
  await choose(dialog,page,'Network access','Only listed domains');
  await dialog.getByText(/Network enforcement is off in this deployment, so sessions with a restricted network policy are refused/).waitFor();
  await dialog.getByRole('textbox',{name:'Allowed domains'}).fill('https://evil.test/path');
  await dialog.getByRole('button',{name:'Create policy'}).click();
  await dialog.getByRole('alert').getByText(/Use hostnames such as registry\.npmjs\.org/).waitFor();
  assert.equal(state.requests.filter(req=>req.path==='/api/admin/security-profiles'&&req.method==='POST').length,0);
  await dialog.getByRole('textbox',{name:'Allowed domains'}).fill('Registry.npmjs.org\n*.example.com, pypi.org');
  await dialog.getByRole('button',{name:'Create policy'}).click();await dialog.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/security-profiles','POST').body,{name:'Contractor sandbox',enabled:true,revision:0,
    policy:{connected_apps:[],tools:['read_file','search_files'],git_access:'none',network_domains:['*.example.com','pypi.org','registry.npmjs.org'],
      repositories:[101,102],models:['openai/gpt-6-astra-ultrafast']}});
  // Saved entries outside the current catalog stay listed and selected, so an edit never drops them.
  await page.getByRole('button',{name:'Edit Restricted review'}).click();const review=page.getByRole('dialog',{name:'Edit Restricted review'});
  const repositories=review.getByRole('group',{name:'Allowed repositories, 2 selected'});
  await repositories.getByRole('group',{name:'Saved, not in the current catalog'}).getByRole('checkbox',{name:'Repository 9001'}).waitFor();
  assert.equal(await repositories.getByRole('checkbox',{name:'Repository 9001'}).isChecked(),true);
  await choose(review,page,'Models','No models');await review.getByText(/cannot start or continue/).waitFor();
  await review.getByRole('button',{name:'Save policy'}).click();await review.waitFor({state:'hidden'});
  assert.deepEqual(last(`/api/admin/security-profiles/${P2}`,'PUT').body.policy,{connected_apps:['github'],tools:['read_file','search_files'],git_access:'read',network_domains:[],
    repositories:[101,9001],models:[]});
  await page.getByRole('button',{name:'Edit Standard engineering'}).click();const edit=page.getByRole('dialog',{name:'Edit Standard engineering'});
  assert.equal(await edit.getByRole('checkbox',{name:'Available for new sessions'}).isDisabled(),true,'the default stays enabled');
  await choose(edit,page,'Network access','Unrestricted');await edit.getByRole('button',{name:'Save policy'}).click();await edit.waitFor({state:'hidden'});
  assert.deepEqual(last(`/api/admin/security-profiles/${P1}`,'PUT').body.policy,{connected_apps:null,tools:null,git_access:'write',network_domains:null,repositories:null,models:null});
  await choose(page,page,'Mandatory policy','Restricted review');await page.getByText('Unsaved changes.').waitFor();
  await page.getByRole('button',{name:'Save defaults'}).click();await page.getByText('Defaults saved.').waitFor();
  assert.deepEqual(last('/api/admin/security-profiles/defaults','PUT').body,{default_profile_id:P1,mandatory_profile_id:P2,revision:2});
  await page.locator('article').filter({hasText:'Restricted review'}).getByText('Mandatory',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Disable Standard engineering'}).count(),0,'defaults cannot be disabled');
  await page.getByRole('button',{name:'Disable Contractor sandbox'}).click();const disable=page.getByRole('dialog',{name:'Disable Contractor sandbox?'});
  await disable.getByText(/keep their recorded policy/).waitFor();await disable.getByRole('button',{name:'Disable policy'}).click();await disable.waitFor({state:'hidden'});
  assert.match(last('/api/admin/security-profiles/abcdefabcdefabcdefabcdefabcdefab','DELETE').query,/revision=1/);
});

test('security policies: the network hint states what Modal enforcement covers',async t=>{
  reset({networkEnforcement:'modal'});const page=await pageFor(t,'#settings/security-policies');
  await page.getByRole('button',{name:'Edit Restricted review'}).click();const review=page.getByRole('dialog',{name:'Edit Restricted review'});
  await review.getByText(/cannot open outbound connections\. .*Enforced on Modal computers for HTTPS \(port 443\) by hostname; plain HTTP, SSH and other ports are blocked\. DNS lookups are not restricted/).waitFor();
  await review.getByText(/Lambda computers refuse restricted policies\. A running computer started under a wider policy must restart\./).waitFor();
  assert.equal(await review.getByText(/Network enforcement is off/).count(),0);
  await choose(review,page,'Network access','Unrestricted');await review.getByText('No outbound restriction is applied.',{exact:true}).waitFor();
  assert.equal(await review.getByText(/Enforced on Modal computers/).count(),0,'an unrestricted choice has no enforcement caveats');
});

test('spend limits: blank means no limit, overrides add/edit/remove, and only changed rows are sent',async t=>{
  reset();const page=await pageFor(t,'#settings/spend-limits');
  await page.getByText('$1,234.56').first().waitFor();await page.getByText('$3,765.44').waitFor();
  const spendReads=()=>state.requests.filter(req=>req.path==='/api/admin/spend-limits'&&req.method==='GET').length,reads=spendReads();
  assert.equal(await page.getByRole('button',{name:'Save limits'}).isDisabled(),true);
  await page.getByRole('textbox',{name:'Organization monthly limit'}).fill('6000');
  await page.getByRole('textbox',{name:'Limit per session'}).fill('25.5');
  await page.getByText('2 unsaved changes.').waitFor();
  await page.getByRole('textbox',{name:'Default monthly limit per person'}).fill('12.345');await page.getByRole('alert').getByText(/up to two decimal places/).waitFor();
  await page.getByRole('textbox',{name:'Default monthly limit per person'}).fill('200.00');
  await page.getByRole('button',{name:'Save limits'}).click();await page.getByText('Limits saved.').waitFor();
  assert.deepEqual(last('/api/admin/spend-limits','PUT').body,{changes:[{id:'organization',limit_usd:6000,revision:3},{id:'session-default',limit_usd:25.5,revision:0}]});
  await page.getByText(/Current: \$6,000\.00/).waitFor();await page.getByText('$4,765.44').waitFor();
  await page.getByRole('button',{name:'Add override'}).click();const add=page.getByRole('dialog',{name:'Add a per-person override'});
  await add.getByRole('textbox',{name:'Work email'}).fill('Dan@Example.test');await add.getByRole('textbox',{name:'Monthly limit (USD)'}).fill('0');
  await add.getByRole('button',{name:'Add override'}).click();await add.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/spend-limits','PUT').body,{changes:[{id:'user:dan@example.test',limit_usd:0,revision:0}]});
  const table=page.getByRole('region',{name:'Per-person spend overrides'});await table.getByText('dan@example.test',{exact:true}).waitFor();await table.getByText('Blocked ($0.00)').waitFor();
  await page.getByRole('button',{name:'Edit limit for carol@example.test'}).click();const edit=page.getByRole('dialog',{name:'Edit limit for carol@example.test'});
  await edit.getByRole('textbox',{name:'Monthly limit (USD)'}).fill('');await edit.getByRole('button',{name:'Save limit'}).click();await edit.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/admin/spend-limits','PUT').body,{changes:[{id:'user:carol@example.test',limit_usd:null,revision:2}]});
  await page.getByRole('button',{name:'Remove override for carol@example.test'}).click();const remove=page.getByRole('dialog',{name:'Remove the override for carol@example.test?'});
  await remove.getByText(/They return to the default monthly limit \(\$200\.00\)/).waitFor();await remove.getByRole('button',{name:'Remove override'}).click();await remove.waitFor({state:'hidden'});
  assert.equal(last('/api/admin/spend-limits/user:carol@example.test','DELETE').query,'?revision=3');
  await table.getByText('carol@example.test').waitFor({state:'detached'});
  assert.equal(spendReads(),reads,'saves that return the full listing replace it without another read');
  const summary=page.getByRole('definition').filter({hasText:'$1,234.56'});assert.equal(await summary.count(),1);
  state.permissions=state.permissions.filter(x=>x!=='spend.read');
  await page.getByRole('button',{name:'Edit limit for dan@example.test'}).click();const bare=page.getByRole('dialog',{name:'Edit limit for dan@example.test'});
  await bare.getByRole('textbox',{name:'Monthly limit (USD)'}).fill('40');await bare.getByRole('button',{name:'Save limit'}).click();await bare.waitFor({state:'hidden'});
  await table.getByText('$40.00').waitFor();
  await page.locator('dl[aria-label="Organization spend this month"]').waitFor({state:'detached'});
  assert.equal(await summary.count(),0,'usage totals are hidden when the listing has none');
  assert.equal(await table.getByRole('row').filter({hasText:'dan@example.test'}).getByRole('cell',{name:'—',exact:true}).count(),1,'per-person spend is unknown without usage');
  assert.equal(spendReads(),reads,'a listing without usage still replaces the page without another read');
});

test('spend limits: spend.manage without spend.read edits limits without seeing usage',async t=>{
  reset({role:'member',permissions:[...MEMBER,'spend.manage']});const page=await pageFor(t,'#settings/spend-limits');
  await page.getByText('Per-person overrides',{exact:true}).waitFor();
  const table=page.getByRole('region',{name:'Per-person spend overrides'});await table.getByText('carol@example.test',{exact:true}).waitFor();
  assert.equal(await page.locator('dl[aria-label="Organization spend this month"]').count(),0,'no usage totals without spend.read');
  assert.equal(await page.getByText('You can view limits. Changing them requires the spend.manage permission.').count(),0);
  assert.equal(await table.getByRole('row').filter({hasText:'carol@example.test'}).getByRole('cell',{name:'—',exact:true}).count(),1,'per-person spend is unknown without usage');
  const save=page.getByRole('button',{name:'Save limits'});assert.equal(await save.isDisabled(),true);
  await page.getByRole('textbox',{name:'Organization monthly limit'}).fill('6000');await save.click();await page.getByText('Limits saved.').waitFor();
  assert.deepEqual(last('/api/admin/spend-limits','PUT').body,{changes:[{id:'organization',limit_usd:6000,revision:3}]});
  assert.equal(await page.locator('dl[aria-label="Organization spend this month"]').count(),0,'the saved listing has no usage either');
});

test('audit log: filters, date validation, cursor paging and exports',async t=>{
  reset();const page=await pageFor(t,'#settings/audit-log');
  const table=page.getByRole('region',{name:'Audit log entries'});await table.getByText('Role created',{exact:true}).waitFor();
  await page.getByText('3 entries shown; more are available.').waitFor();
  await page.getByRole('button',{name:'Load more'}).click();await table.getByText('Spend limit updated',{exact:true}).waitFor();await page.getByText('5 entries shown.').waitFor();
  const refusal=table.getByRole('row').filter({hasText:'AI guardrail violation'}),refusalText=await refusal.textContent();
  assert.ok(['ai_guardrail.violation','bob@example.test','ai_guardrail','phi-presidio'].every(text=>refusalText.includes(text)));
  await refusal.locator('details summary').click();await refusal.getByText('phi-presidio, prompt-injection').waitFor();
  await table.locator('details summary').first().click();await table.getByText('audit.read, sessions.read').waitFor();
  await page.getByLabel('From (UTC)').fill('2026-10-10');await page.getByLabel('To (UTC)').fill('2026-01-01');await page.getByRole('button',{name:'Apply filters'}).click();
  await page.getByRole('alert').getByText('Choose a start date on or before the end date.').waitFor();
  await page.getByLabel('From (UTC)').fill('2026-10-01');await page.getByLabel('To (UTC)').fill('2026-10-15');
  await choose(page,page,'Action','SCIM token revoked');await page.getByRole('textbox',{name:'Actor email'}).fill(' Admin@Example.test ');
  await page.getByRole('button',{name:'Apply filters'}).click();
  await waitFor(()=>state.requests.some(req=>req.path==='/api/admin/governance/audit'&&req.query.includes('action=')),'filtered request');
  const query=new URLSearchParams(last('/api/admin/governance/audit').query);
  assert.equal(query.get('action'),'scim_token.revoked');assert.equal(query.get('actor'),'admin@example.test');
  assert.equal(query.get('after'),'2026-10-01T00:00:00Z');assert.equal(query.get('before'),'2026-10-16T00:00:00Z');assert.equal(query.get('cursor'),null);
  await page.getByText('1 entry shown.').waitFor();assert.equal(await table.getByText('Role created',{exact:true}).count(),0);
  await page.evaluate(()=>{const revoke=URL.revokeObjectURL.bind(URL);window.revoked=[];URL.revokeObjectURL=url=>{window.revoked.push(url);revoke(url);};});
  for(const [label,format,content] of [['Export CSV','csv','id,action\na2,scim_token.revoked\n'],['Export NDJSON','ndjson','{"id":"a2","action":"scim_token.revoked"}\n']]) {
    const [file]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:label}).click()]);
    assert.equal(file.suggestedFilename(),`governance.${format}`);assert.equal(fs.readFileSync(await file.path(),'utf8'),content);
    const request=last('/api/admin/governance/audit/export'),exported=new URLSearchParams(request.query);
    assert.equal(request.csrf,'fixture-csrf');assert.equal(exported.get('format'),format);assert.equal(exported.get('action'),'scim_token.revoked');assert.equal(exported.get('after'),'2026-10-01T00:00:00Z');
  }
  await page.waitForFunction(()=>window.revoked.length===2&&window.revoked.every(url=>url.startsWith('blob:')));
  state.exportError='Exports are limited to 50,000 entries. Narrow the date range.';
  let downloads=0;page.on('download',()=>downloads++);
  await page.getByRole('button',{name:'Export CSV'}).click();await page.getByRole('alert').getByText(state.exportError).waitFor();
  assert.equal(downloads,0,'a failed export downloads nothing');assert.equal(await page.getByRole('button',{name:'Export CSV'}).isEnabled(),true);
  await page.getByRole('button',{name:'Clear filters'}).first().click();await page.getByText('3 entries shown; more are available.').waitFor();
  assert.equal(await page.getByText(state.exportError).count(),0,'new filters clear the export error');
});

test('load more with an empty final page stops paging instead of returning to the first cursor',async t=>{
  reset({emptyNextPage:true});const page=await pageFor(t,'#settings/audit-log');
  const cursorReads=(pathname,cursor)=>state.requests.filter(req=>req.path===pathname&&new URLSearchParams(req.query).get('cursor')===cursor).length;
  await page.getByText('3 entries shown; more are available.').waitFor();
  await page.getByRole('button',{name:'Load more'}).click();await page.getByText('3 entries shown.').waitFor();
  assert.equal(await page.getByRole('button',{name:'Load more'}).count(),0);assert.equal(cursorReads('/api/admin/governance/audit','audit-2'),1);
  await page.evaluate(()=>{location.hash='settings/provisioning';});
  const users=page.getByRole('region',{name:'Directory users'});await users.getByText('Dana Former').waitFor();
  await page.getByRole('button',{name:'Load more users'}).click();await waitFor(()=>cursorReads('/api/admin/scim','users-2')===1,'second directory page');
  await page.getByRole('button',{name:'Loading users…'}).waitFor({state:'detached'});
  assert.equal(await page.getByRole('button',{name:'Load more users'}).count(),0);assert.equal(await users.getByRole('row').count(),3);
});

test('losing access while loading more clears audit and directory rows and re-reads access',async t=>{
  reset();const page=await pageFor(t,'#settings/audit-log');
  const meReads=()=>state.requests.filter(req=>req.path==='/api/me').length;
  const table=page.getByRole('region',{name:'Audit log entries'});await table.getByText('Role created',{exact:true}).waitFor();
  let reads=meReads();state.permissions=state.permissions.filter(x=>x!=='audit.read');
  await page.getByRole('button',{name:'Load more'}).click();
  await page.getByRole('heading',{name:'Permission required'}).waitFor();
  assert.ok(meReads()>reads,'own access is re-read after a 403');
  assert.equal(await page.getByText('Role created',{exact:true}).count(),0,'loaded audit entries are removed');
  reset();await page.evaluate(()=>{location.hash='settings/provisioning';});await page.reload();
  const users=page.getByRole('region',{name:'Directory users'});await users.getByText('Dana Former').waitFor();
  reads=meReads();state.permissions=state.permissions.filter(x=>x!=='scim.manage');
  await page.getByRole('button',{name:'Load more users'}).click();
  await page.getByRole('heading',{name:'Permission required'}).waitFor();
  assert.ok(meReads()>reads,'own access is re-read after a 403');
  assert.equal(await page.getByText('Dana Former').count(),0,'loaded directory users are removed');
});

test('Users shows custom roles and replacing one needs explicit confirmation',async t=>{
  reset();const page=await pageFor(t,'#settings/users');
  const table=page.getByRole('region',{name:'Workspace users'});await table.getByText('Custom role · built-in Member').waitFor();await table.getByText('Deactivated by directory').waitFor();
  await page.getByRole('button',{name:'Edit role for bob@example.test'}).click();const dialog=page.getByRole('dialog',{name:'Edit workspace role'});
  await dialog.getByText(/has the custom role/).waitFor();const save=dialog.getByRole('button',{name:'Save',exact:true});assert.equal(await save.isDisabled(),true);
  await dialog.getByRole('checkbox',{name:'Replace the custom role Auditor'}).click();await save.click();await dialog.waitFor({state:'hidden'});
  assert.deepEqual(last('/api/settings/users/role','PUT').body,{email:'bob@example.test',role:'member',revision:4,replace_custom_role:true,access_revision:2});
  reset({role:'member',permissions:[...MEMBER,'users.read']});await page.reload();
  await page.getByText('You can view the directory. Changing roles requires the users.manage permission.').waitFor();
  assert.equal(await page.getByRole('button',{name:/Edit role/}).count(),0);
});

test('Home offers enabled security policies, sends only an explicit choice and follows its model and repository limits',async t=>{
  reset({connections:CONNECTIONS});const page=await pageFor(t,'');await page.getByRole('textbox',{name:'Message Moyai'}).waitFor();
  const trigger=page.getByRole('combobox',{name:'Security policy'});await trigger.waitFor();assert.match(await trigger.innerText(),/Organization default · Standard engineering/);
  await waitFor(()=>last('/api/security-policy/new-session'),'the default policy read');assert.equal(last('/api/security-policy/new-session').query,'','the default needs no profile');
  await page.getByRole('combobox',{name:'Model'}).click();
  assert.deepEqual(await page.getByRole('option').allTextContents(),['test-model','gpt-6-astra','gpt-6-astra-ultrafast'],'an unrestricted policy offers every model');
  await page.keyboard.press('Escape');
  await page.getByRole('textbox',{name:'Message Moyai'}).fill('Default policy task');await page.getByRole('button',{name:'Send message'}).click();
  await waitFor(()=>last('/api/sessions','POST'));assert.deepEqual(last('/api/sessions','POST').body,{model:'test-model',visibility:'shared'});
  await waitFor(()=>last(`/api/sessions/${SID}/messages`,'POST'));
  assert.deepEqual(last(`/api/sessions/${SID}/messages`,'POST').body.connections,['gh-101','gh-102','linear'],'an unrestricted policy keeps every connection');
  await page.goto(base+'/');
  await page.getByRole('combobox',{name:'Security policy'}).click();
  assert.deepEqual(await page.getByRole('option').allTextContents(),['Organization default · Standard engineering','Standard engineering','Restricted review'],'disabled policies are not offered');
  await page.getByRole('option',{name:'Restricted review',exact:true}).click();
  assert.equal(await page.getByRole('combobox',{name:'Security policy'}).innerText(),'Restricted review');
  await waitFor(()=>last('/api/security-policy/new-session')?.query===`?profile_id=${P2}`,'the chosen policy read');
  // Restricted review allows one model and repositories 101 and 9001 (not in the catalog) through GitHub only.
  const model=page.getByRole('combobox',{name:'Model'});
  await page.getByText('2 connections are not allowed by this security policy').waitFor();
  assert.equal(await model.innerText(),'gpt-6-astra','a refused choice falls back to the policy default');
  await model.click();assert.deepEqual(await page.getByRole('option').allTextContents(),['gpt-6-astra']);await page.keyboard.press('Escape');
  if(screens)await page.screenshot({path:path.join(screens,'home-policy-1440.png')});
  await page.getByRole('textbox',{name:'Message Moyai'}).fill('Restricted task');await page.getByRole('button',{name:'Send message'}).click();
  await waitFor(()=>state.requests.filter(req=>req.path==='/api/sessions'&&req.method==='POST').length===2);
  assert.deepEqual(last('/api/sessions','POST').body,{model:'openai/gpt-6-astra',visibility:'shared',security_profile_id:P2});
  await waitFor(()=>state.requests.filter(req=>req.path===`/api/sessions/${SID}/messages`&&req.method==='POST').length===2);
  const message=last(`/api/sessions/${SID}/messages`,'POST').body;
  assert.equal(message.model,'openai/gpt-6-astra');assert.deepEqual(message.connections,['gh-101'],'only the listed repository is selected');
});

test('Home blocks sending when its policy allows no model, and a member reads only the default policy',async t=>{
  reset({role:'member',permissions:[...MEMBER]});state.profiles[0].policy.models=[];
  const page=await pageFor(t,'');await page.getByRole('textbox',{name:'Message Moyai'}).waitFor();
  await page.getByText('This security policy allows no models. Choose another policy or ask an administrator.').waitFor();
  assert.equal(await page.getByRole('combobox',{name:'Security policy'}).count(),0,'only security.manage holders choose a profile');
  assert.ok(state.requests.filter(req=>req.path==='/api/security-policy/new-session').every(req=>req.query===''));
  assert.equal(await page.getByRole('combobox',{name:'Model'}).isDisabled(),true);
  await page.getByRole('textbox',{name:'Message Moyai'}).fill('Nothing allowed');
  assert.equal(await page.getByRole('button',{name:'Send message'}).isDisabled(),true);
  await page.keyboard.press('Enter');await page.waitForTimeout(100);
  assert.equal(last('/api/sessions','POST'),undefined,'nothing is admitted');
  for(const width of [768,320]){await page.setViewportSize({width,height:900});await noOverflow(page,width);}
  if(screens)await page.screenshot({path:path.join(screens,'home-no-model-320.png')});
});

test('Home reads its policy again after a refused send and retries with an allowed model',async t=>{
  reset();const page=await pageFor(t,'');await page.getByRole('textbox',{name:'Message Moyai'}).waitFor();
  await waitFor(()=>last('/api/security-policy/new-session'),'the default policy read');
  const reads=()=>state.requests.filter(req=>req.path==='/api/security-policy/new-session').length, before=reads();
  state.profiles[0].policy.models=['openai/gpt-6-astra'];  // An administrator narrows the default after Home read it.
  await page.getByRole('textbox',{name:'Message Moyai'}).fill('Narrowed task');await page.getByRole('button',{name:'Send message'}).click();
  await page.getByText('This model is not allowed by the session security policy.').waitFor();
  await waitFor(()=>reads()>before,'the policy read again');
  await page.waitForFunction(()=>document.querySelector('[aria-label="Model"]')?.textContent==='gpt-6-astra');
  await page.getByRole('button',{name:'Send message'}).click();
  await waitFor(()=>last('/api/sessions','POST')?.body.model==='openai/gpt-6-astra','the retry uses the allowed model');
  await waitFor(()=>last(`/api/sessions/${SID}/messages`,'POST'));
});

test('the composer waits for its session policy before sending',async t=>{
  let release;const gate=new Promise(resolve=>{release=resolve;});t.after(()=>release());
  reset({session:true,sessionPolicy:{...profile('','',{}).policy,models:['openai/gpt-6-astra']},policyGate:gate});
  const page=await pageFor(t,'#'+SID);await page.getByRole('heading',{name:'Governed work'}).first().waitFor();
  const input=page.getByRole('textbox',{name:/Message/}).last();await input.click();await page.keyboard.type('Too early');
  await page.getByText('Loading security policy…').waitFor();
  assert.equal(await page.getByRole('button',{name:'Send message'}).isDisabled(),true,'no send before the policy read');
  await page.keyboard.press('Enter');await page.waitForTimeout(100);
  assert.equal(last(`/api/sessions/${SID}/messages`,'POST'),undefined,'the stored model is not sent before the read');
  release();
  await page.waitForFunction(()=>[...document.querySelectorAll('[aria-label="Model"]')].some(el=>el.textContent==='openai/gpt-6-astra'));
  await page.getByRole('button',{name:'Send message'}).click();
  await waitFor(()=>last(`/api/sessions/${SID}/messages`,'POST'));
  assert.equal(last(`/api/sessions/${SID}/messages`,'POST').body.model,'openai/gpt-6-astra','the refused session model is never sent');
});

test('the composer follows the session policy, including a mandatory narrowing of its own model',async t=>{
  const limited={...profile('','',{}).policy,connected_apps:['github'],repositories:[101],models:['openai/gpt-6-astra-ultrafast','openai/gpt-6-astra']};
  reset({session:true,sessionPolicy:limited,connections:CONNECTIONS,preferences:{delivery_mode:'when_idle',connection_ids:['gh-101','gh-102','linear']}});
  const page=await pageFor(t,'#'+SID);await page.getByRole('heading',{name:'Governed work'}).first().waitFor();
  await waitFor(()=>last(`/api/sessions/${SID}/security-policy`),'the session policy read');
  const model=page.getByRole('combobox',{name:'Model'});
  await page.waitForFunction(()=>[...document.querySelectorAll('[aria-label="Model"]')].some(el=>el.textContent==='openai/gpt-6-astra'));
  await model.click();assert.deepEqual(await page.getByRole('option').allTextContents(),['openai/gpt-6-astra','openai/gpt-6-astra-ultrafast'],'workspace order');
  if(screens)await page.screenshot({path:path.join(screens,'composer-policy-1440.png')});
  await page.getByRole('option',{name:'openai/gpt-6-astra-ultrafast',exact:true}).click();
  const input=page.getByRole('textbox',{name:/Message/}).last();await input.click();await page.keyboard.type('Governed follow-up');
  await page.getByRole('button',{name:'Send message'}).click();
  await waitFor(()=>last(`/api/sessions/${SID}/messages`,'POST'));
  const body=last(`/api/sessions/${SID}/messages`,'POST').body;
  assert.equal(body.model,'openai/gpt-6-astra-ultrafast');assert.deepEqual(body.connections,['gh-101'],'preferred connections outside the policy are left out');
  assert.equal(await page.locator('.global-error').count(),0);
});

for(const width of [1440,320])test(`role and policy editors stay labelled, contained and scrollable at ${width}px`,async t=>{
  reset();const page=await pageFor(t,'#settings/roles',width,width===320?640:1000);
  await page.getByRole('button',{name:'New role',exact:true}).click();
  const role=page.getByRole('dialog',{name:'New role'});await role.waitFor();
  const check=async dialog=>{
    const box=await dialog.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=width+1&&box.y>=0&&box.y+box.height<=(width===320?640:1000)+1,'dialog fits the viewport');
    assert.equal(await dialog.evaluate(el=>getComputedStyle(el).overflowY),'auto');
    assert.ok(await dialog.getAttribute('aria-describedby'),'dialog has a description');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  };
  await check(role);
  if(width===320){
    assert.equal(await role.getByRole('textbox',{name:'Role name'}).evaluate(el=>getComputedStyle(el).fontSize),'16px','mobile inputs avoid zoom');
    const heights=await role.locator('.ns-gov-check label').evaluateAll(labels=>labels.map(label=>label.getBoundingClientRect().height));
    assert.ok(heights.length>0&&heights.every(height=>height>=44),'permission labels are 44px tap targets');
  }
  await role.getByRole('textbox',{name:'Role name'}).fill('Synthetic reviewer');await role.getByRole('checkbox',{name:'Read the audit log'}).click();
  if(screens)await page.screenshot({path:path.join(screens,`roles-editor-${width}.png`)});
  await role.getByRole('button',{name:'Cancel'}).click();await role.waitFor({state:'hidden'});
  assert.equal(await page.getByRole('button',{name:'New role',exact:true}).evaluate(el=>el===document.activeElement),true,'focus returns to the opener');
  await page.evaluate(()=>{location.hash='settings/security-policies';});
  await page.getByRole('button',{name:'Edit Restricted review'}).click();const policy=page.getByRole('dialog',{name:'Edit Restricted review'});await policy.waitFor();
  await check(policy);await policy.getByRole('group',{name:/Allowed tools/}).waitFor();
  if(screens)await page.screenshot({path:path.join(screens,`policy-editor-${width}.png`)});
  await page.keyboard.press('Escape');await policy.waitFor({state:'hidden'});
});
