/* Synthetic governance data for the local visual preview. No production writes. */
const permissions=Object.entries({
  'workspace.read':'View workspace configuration',
  'sessions.read':'View accessible sessions',
  'sessions.create':'Start agent sessions',
  'sessions.manage':'Manage accessible sessions',
  'connections.read':'View connections',
  'connections.write':'Use enabled organization app write tools',
  'connections.manage':'Manage organization connections',
  'users.read':'View the user directory',
  'roles.manage':'Manage custom roles and group grants',
  'scim.manage':'Manage directory provisioning',
  'security.manage':'Manage session security policies',
  'audit.read':'Read governance audit activity',
}).map(([id,description])=>({id,description}));
let roles=[
  {id:'admin',name:'Administrator',description:'Built-in workspace role',permissions:permissions.map(p=>p.id),revision:0,builtin:true,archived:false},
  {id:'member',name:'Internal user',description:'Built-in workspace role',permissions:['workspace.read','sessions.read','sessions.create','sessions.manage','connections.read'],revision:0,builtin:true,archived:false},
  {id:'auditor',name:'Engineering auditor',description:'Read sessions and governance audit history.',permissions:['workspace.read','sessions.read','audit.read'],revision:1,builtin:false,archived:false},
];
let assignments=[{email:'riley@example.com',role_id:'auditor',revision:1}],groupRoles=[];
const profileId='f'.repeat(32);
let profiles=[{id:profileId,name:'Read-only investigation',revision:1,enabled:true,policy:{network_domains:null,connected_apps:['github'],tools:null,git_access:'read'}}];
let defaults={revision:0,default_profile_id:'',floor_profile_id:''};
let tokens=[{id:'fixture-directory',label:'Company directory',prefix:'fixture-token',created_at:'2026-10-13T12:00:00Z',revoked_at:''}];
const users=[{id:'fixture-user',userName:'riley@example.com',displayName:'Riley Chen',active:true}];
const groups=[{id:'fixture-engineering',displayName:'Engineering reviewers',members:[{value:'fixture-user'}]}];
const json=(res,status,body)=>{res.writeHead(status,{'content-type':'application/json'});res.end(status===204?'':JSON.stringify(body));};
module.exports=function(req,res,url,body,role,fixture){
  const path=url.pathname;
  if(!/^\/api\/(?:admin\/(?:roles|role-assignments|group-roles|scim|security-profiles|governance)|security-profiles)(?:\/|$)/.test(path))return false;
  if(role!=='admin'&&path!=='/api/security-profiles'){json(res,403,{detail:'Your role does not include this governance setting.'});return true;}
  if(fixture==='error'){json(res,503,{detail:'This preview simulates a governance outage.'});return true;}
  const empty=fixture==='empty',method=req.method;
  if(path==='/api/admin/governance/audit'){
    let rows=empty?[]:[
      {id:'fixture-audit-2',action:'security.defaults.updated',actor:'alex@example.com',resource_type:'Organization',resource_id:'1',created_at:'2026-10-13T12:00:00Z'},
      {id:'fixture-audit-1',action:'role.created',actor:'alex@example.com',resource_type:'CustomRole',resource_id:'auditor',created_at:'2026-10-12T12:00:00Z'},
    ];
    for(const name of ['actor','action','resource_type','resource_id'])if(url.searchParams.get(name))rows=rows.filter(row=>row[name]===url.searchParams.get(name));
    if(url.searchParams.get('start'))rows=rows.filter(row=>Date.parse(row.created_at)>=Date.parse(url.searchParams.get('start')));
    if(url.searchParams.get('end'))rows=rows.filter(row=>Date.parse(row.created_at)<Date.parse(url.searchParams.get('end')));
    // A single-row display page keeps pagination reviewable; exports honor limit.
    const offset=Number(url.searchParams.get('cursor')||0),limit=url.searchParams.get('limit')==='100'?100:1;
    json(res,200,{events:rows.slice(offset,offset+limit),next_cursor:offset+limit<rows.length?String(offset+limit):null});
  }else if(path==='/api/admin/roles'&&method==='GET')json(res,200,{roles:empty?roles.filter(r=>r.builtin):roles,permissions,assignments:empty?[]:assignments,group_roles:groupRoles,groups:empty?[]:groups.map(group=>({id:group.id,display_name:group.displayName,members:group.members.length})),activity:[]});
  else if(path==='/api/admin/roles'&&method==='POST'){
    const row={...body,revision:1,builtin:false,archived:false};roles.push(row);json(res,201,row);
  }else if(path.startsWith('/api/admin/roles/')){
    const id=path.split('/').at(-1),row=roles.find(r=>r.id===id);
    if(!row)json(res,404,{detail:'Role not found.'});
    else if(method==='DELETE'){row.archived=true;row.revision++;json(res,200,row);}
    else if(body.revision!==row.revision)json(res,409,{detail:'This role changed. Reload before saving.'});
    else{Object.assign(row,body,{revision:row.revision+1});json(res,200,row);}
  }else if(path==='/api/admin/role-assignments'){
    const old=assignments.find(r=>r.email===body.email),row={...body,revision:(old?.revision||0)+1};
    assignments=assignments.filter(r=>r.email!==body.email);assignments.push(row);json(res,200,row);
  }else if(path.startsWith('/api/admin/group-roles/')){
    const group_id=path.split('/').at(-1),old=groupRoles.find(r=>r.group_id===group_id),row={...body,group_id,revision:(old?.revision||0)+1};
    groupRoles=groupRoles.filter(r=>r.group_id!==group_id);groupRoles.push(row);json(res,200,row);
  }else if(path==='/api/admin/scim')json(res,200,{base_url:`http://${req.headers.host}/scim/v2`,tokens:empty?[]:tokens,users:empty?[]:users,groups:empty?[]:groups,activity:[]});
  else if(path==='/api/admin/scim/tokens'&&method==='POST'){
    const row={id:'fixture-'+tokens.length,label:body.label,prefix:'fixture-only',created_at:new Date().toISOString(),revoked_at:''};tokens.push(row);
    json(res,201,{...row,token:'fixture-only-provisioning-token-never-valid',base_url:`http://${req.headers.host}/scim/v2`});
  }else if(path.startsWith('/api/admin/scim/tokens/')&&method==='DELETE'){
    const row=tokens.find(t=>t.id===path.split('/').at(-1));if(row)row.revoked_at=new Date().toISOString();json(res,204,{});
  }else if(path==='/api/admin/security-profiles/defaults'&&method==='PUT'){
    if(body.revision!==defaults.revision)json(res,409,{detail:'The defaults changed. Refresh before saving.'});
    else{defaults={...body,revision:defaults.revision+1};json(res,200,defaults);}
  }else if(path==='/api/admin/security-profiles'&&method==='POST'){
    const row={...body,id:(profiles.length+1).toString(16).padStart(32,'0'),revision:1};profiles.push(row);json(res,201,row);
  }else if(path.startsWith('/api/admin/security-profiles/')&&method==='PUT'){
    const row=profiles.find(p=>p.id===path.split('/').at(-1));
    if(!row)json(res,404,{detail:'Policy not found.'});
    else if(body.revision!==row.revision)json(res,409,{detail:'This policy changed. Refresh before saving.'});
    else{Object.assign(row,body,{revision:row.revision+1});json(res,200,row);}
  }else if(path==='/api/security-profiles')json(res,200,profiles.filter(p=>p.enabled));
  else if(path==='/api/admin/security-profiles')json(res,200,{profiles:empty?[]:profiles,defaults,network_enforcement:{supported_providers:['substrate']}});
  else json(res,404,{detail:'Fixture endpoint not found.'});
  return true;
};
