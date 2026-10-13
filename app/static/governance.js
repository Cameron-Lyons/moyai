const governanceState = {tab:'roles', query:''};
const governanceTabs = [
  ['roles','Roles','roles.manage'],
  ['provisioning','Provisioning','scim.manage'],
  ['policies','Security policies','security.manage'],
  ['audit','Audit history','audit.read'],
];

globalThis.MoyaiSecurityProfiles = {
  options(profiles,selected='') {
    const rows=Array.isArray(profiles)?profiles:[];
    return `<option value="">Organization default</option>${selected&&!rows.some(profile=>profile.id===selected)?`<option value="${esc(selected)}" selected>Saved policy · unavailable</option>`:''}${rows.map(profile=>`<option value="${esc(profile.id)}" ${profile.id===selected?'selected':''}>${esc(profile.name)}</option>`).join('')}`;
  },
};

async function renderGovernance() {
  const version=state.pageVersion;
  MoyaiUI.render($('#content'), '<p class="subtext" role="status">Loading governance…</p>');
  const session=await api('/api/session');
  if(version!==state.pageVersion)return;
  applyUserSession(session);
  const tabs=governanceTabs.filter(([, ,permission])=>hasWorkspacePermission(permission));
  if(!tabs.length){
    MoyaiUI.render($('#content'), '<div class="page-heading"><div><h1>Governance</h1><p class="subtext">Your role does not include governance settings.</p></div></div>');
    return;
  }
  if(!tabs.some(([id])=>id===governanceState.tab))governanceState.tab=tabs[0][0];
  const tab=governanceState.tab;
  const path={roles:'/api/admin/roles',provisioning:'/api/admin/scim',policies:'/api/admin/security-profiles',audit:'/api/admin/governance/audit'}[tab];
  const data=await api(path);
  if(version!==state.pageVersion||tab!==governanceState.tab)return;
  MoyaiUI.render($('#content'), `<section class="governance-page">
    <div class="page-heading"><div><h1>Governance</h1><p class="subtext">Control workspace permissions, user provisioning, and agent access.</p></div><button id="governance-refresh" class="quiet">Refresh</button></div>
    <div class="analytics-tabs governance-tabs" role="group" aria-label="Governance settings">${tabs.map(([id,label])=>`<button data-governance-tab="${id}" aria-pressed="${tab===id}">${label}</button>`).join('')}</div>
    <div id="governance-panel">${tab==='roles'?governanceRoles(data):tab==='provisioning'?governanceProvisioning(data):tab==='audit'?governanceAudit(data):governancePolicies(data)}</div>
  </section>`);
  $('#governance-refresh').onclick=()=>renderGovernance().catch(error=>settingsLoadError('Governance',error,()=>renderGovernance()));
  document.querySelectorAll('[data-governance-tab]').forEach(button=>button.onclick=()=>{
    governanceState.tab=button.dataset.governanceTab;
    renderGovernance().catch(error=>settingsLoadError('Governance',error,()=>renderGovernance()));
  });
  if(tab==='roles')bindGovernanceRoles(data,version);
  else if(tab==='provisioning')bindGovernanceProvisioning(data,version);
  else if(tab==='audit')bindGovernanceAudit(data,version);
  else bindGovernancePolicies(data,version);
}

function governanceAudit(data) {
  return `<section class="governance-section"><h2>Governance audit history</h2><p class="subtext">Saved role, provisioning, and security policy changes. This history contains action metadata.</p><div id="governance-audit-table">${governanceAuditRows(data.events)}</div>${data.next_cursor?'<button class="quiet" id="governance-audit-more">Load earlier changes</button>':''}<p id="governance-audit-status" role="status"></p></section>`;
}

function governanceAuditRows(rows) {
  return governanceTable('Governance audit history',['When','Action','Actor','Resource'],rows.map(row=>`<tr><td>${esc(new Date(row.created_at).toLocaleString())}</td><td>${esc(row.action)}</td><td>${esc(row.actor)}</td><td>${esc(row.resource_type)}<small>${esc(row.resource_id)}</small></td></tr>`),'No governance changes have been recorded yet.');
}

function bindGovernanceAudit(data,version) {
  const button=$('#governance-audit-more');
  if(!button)return;
  button.onclick=async()=>{
    button.disabled=true;$('#governance-audit-status').textContent='Loading…';
    try{
      const page=await api('/api/admin/governance/audit?cursor='+encodeURIComponent(data.next_cursor));
      if(version!==state.pageVersion||governanceState.tab!=='audit')return;
      data.events.push(...page.events);data.next_cursor=page.next_cursor;
      MoyaiUI.render($('#governance-audit-table'),governanceAuditRows(data.events));
      button.hidden=!data.next_cursor;$('#governance-audit-status').textContent='';
    }catch(error){if(version===state.pageVersion&&governanceState.tab==='audit')$('#governance-audit-status').textContent=error.message;}
    finally{if(version===state.pageVersion)button.disabled=false;}
  };
}

function governanceTable(label,headings,rows,empty) {
  return rows.length?`<div class="analytics-table-frame" role="region" aria-label="${esc(label)}" tabindex="0"><table class="users-table"><thead><tr>${headings.map(heading=>`<th scope="col">${heading}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`:`<p class="subtext">${esc(empty)}</p>`;
}

function governanceRoles(data) {
  const roles=data.roles.filter(role=>!role.archived);
  return `<section class="governance-section"><div class="section-header"><div><h2>Workspace roles</h2><p class="subtext">Custom roles replace internal user permissions. Group memberships can add permissions.</p></div><button id="governance-new-role" class="primary">Create role</button></div>
    <label class="governance-search">Search roles<input id="governance-role-search" type="search" value="${esc(governanceState.query)}" placeholder="Name, description, or permission"></label>
    <div id="governance-role-list">${roles.map(role=>`<article class="governance-row" data-governance-role="${esc(role.id)}" data-search="${esc([role.name,role.description,...role.permissions].join(' ').toLowerCase())}"><div><h3>${esc(role.name)} ${role.builtin?'<span class="badge">Built-in</span>':''}</h3><p class="subtext">${esc(role.description||'Custom workspace permissions')}</p><details><summary>${role.permissions.length} permissions</summary><ul>${role.permissions.map(permission=>`<li><code>${esc(permission)}</code></li>`).join('')}</ul></details></div>${role.builtin?'':`<div class="governance-actions"><button class="quiet" data-role-edit="${esc(role.id)}">Edit</button><button class="quiet danger" data-role-delete="${esc(role.id)}">Archive</button></div>`}</article>`).join('')}</div>
    <div id="governance-role-empty" hidden><p>No roles match your search.</p><button class="quiet" id="governance-clear-search">Clear search</button></div>
  </section><section class="governance-section"><div class="section-header"><div><h2>User assignments</h2><p class="subtext">Assign a role to an eligible work email. Changes apply on the next request.</p></div><button id="governance-assign-role" class="quiet">Assign role</button></div>
    ${governanceTable('Explicit user role assignments',['Work email','Role',''],(data.assignments||[]).map(row=>`<tr><td>${esc(row.email)}</td><td>${esc(roles.find(role=>role.id===row.role_id)?.name||row.role_id)}</td><td><button class="quiet" data-role-assign="${esc(row.email)}">Change role</button></td></tr>`),'No custom assignments yet. Existing administrator and internal user roles still apply.')}
  </section><details class="governance-section"><summary>Recent role activity</summary>${governanceActivity(data.activity)}</details>`;
}

function governanceActivity(rows=[]) {
  return rows.length?`<ul class="governance-activity">${rows.map(row=>`<li><strong>${esc(row.action||row.resource_type||'Updated')}</strong><span>${esc(row.actor||'')} ${esc(row.email||row.resource_id||row.role_id||'')}</span><time>${esc(new Date(row.created_at).toLocaleString())}</time></li>`).join('')}</ul>`:'<p class="subtext">Changes will appear here after they are saved.</p>';
}

function governanceDialog(title,html) {
  const dialog=MoyaiUI.createDialog();
  dialog.dataset.dialogScope='settings';
  dialog.dataset.dialogId='governance';
  dialog.setAttribute('aria-label',title);
  MoyaiUI.render(dialog, `<form id="governance-form"><button class="dialog-close" type="button" data-governance-cancel aria-label="Close">×</button><h2>${esc(title)}</h2>${html}<p id="governance-error" role="alert"></p><div class="credential-actions"><button type="button" class="quiet" data-governance-cancel>Cancel</button><button type="submit" class="primary">Save</button></div></form>`);
  document.body.append(dialog);
  dialog.querySelectorAll('[data-governance-cancel]').forEach(button=>button.onclick=()=>dialog.close());
  dialog.addEventListener('close',()=>dialog.remove(),{once:true});
  dialog.showModal();
  return dialog;
}

function governanceSave(dialog,version,submit) {
  dialog.querySelector('form').onsubmit=async event=>{
    event.preventDefault();
    const button=dialog.querySelector('[type="submit"]');button.disabled=true;
    try{
      await submit();
      if(!dialog.isConnected)return;
      dialog.close();
      if(version===state.pageVersion&&state.view==='governance')await renderGovernance();
    }catch(error){
      if(dialog.isConnected){dialog.querySelector('#governance-error').textContent=error.message;button.disabled=false;}
      else if(version===state.pageVersion)toast(error.message);
    }
  };
}

function bindGovernanceRoles(data,version) {
  const filter=()=>{
    governanceState.query=$('#governance-role-search').value;
    let count=0;
    document.querySelectorAll('[data-governance-role]').forEach(row=>{row.hidden=!row.dataset.search.includes(governanceState.query.trim().toLowerCase());if(!row.hidden)count++;});
    $('#governance-role-empty').hidden=count>0;
  };
  $('#governance-role-search').oninput=filter;filter();
  $('#governance-clear-search').onclick=()=>{$('#governance-role-search').value='';filter();$('#governance-role-search').focus();};
  const edit=role=>{
    const groups=Object.groupBy(data.permissions,permission=>permission.id.split('.')[0]);
    const dialog=governanceDialog(role?'Edit role':'Create role', `<div class="field"><label for="governance-role-name">Role name</label><input id="governance-role-name" required maxlength="80" value="${esc(role?.name||'')}"></div><div class="field"><label for="governance-role-id">Role ID</label><input id="governance-role-id" required pattern="[a-z][a-z0-9-]*" maxlength="64" value="${esc(role?.id||'')}" ${role?'readonly':''}></div><div class="field"><label for="governance-role-description">Description</label><textarea id="governance-role-description" rows="2">${esc(role?.description||'')}</textarea></div><div class="governance-permissions">${Object.entries(groups).map(([group,permissions])=>`<fieldset><legend>${esc(group[0].toUpperCase()+group.slice(1))}</legend>${permissions.map(permission=>`<label class="governance-check"><input type="checkbox" name="permission" value="${esc(permission.id)}" ${role?.permissions.includes(permission.id)?'checked':''}><span><strong>${esc(permission.id)}</strong><small>${esc(permission.description)}</small></span></label>`).join('')}</fieldset>`).join('')}</div>`);
    governanceSave(dialog,version,()=>{
      const id=dialog.querySelector('#governance-role-id').value.trim();
      return api(role?'/api/admin/roles/'+encodeURIComponent(id):'/api/admin/roles',{method:role?'PUT':'POST',body:JSON.stringify({id,name:dialog.querySelector('#governance-role-name').value,description:dialog.querySelector('#governance-role-description').value,permissions:[...dialog.querySelectorAll('[name="permission"]:checked')].map(input=>input.value),revision:role?.revision||0})});
    });
  };
  $('#governance-new-role').onclick=()=>edit();
  document.querySelectorAll('[data-role-edit]').forEach(button=>button.onclick=()=>edit(data.roles.find(role=>role.id===button.dataset.roleEdit)));
  document.querySelectorAll('[data-role-delete]').forEach(button=>button.onclick=async()=>{
    const role=data.roles.find(role=>role.id===button.dataset.roleDelete);
    if(!await confirmSettingsAction('Archive role',`Archive ${role.name}? Its permissions will stop applying to assigned users and groups immediately.`,'Archive role'))return;
    try{await api('/api/admin/roles/'+encodeURIComponent(role.id)+'?revision='+role.revision,{method:'DELETE'});if(version===state.pageVersion)await renderGovernance();}catch(error){toast(error.message);}
  });
  const assign=row=>{
    const dialog=governanceDialog('Assign role',`<div class="field"><label for="governance-assignment-email">Work email</label><input id="governance-assignment-email" type="email" required value="${esc(row?.email||'')}" ${row?'readonly':''}></div><div class="field"><label for="governance-assignment-role">Role</label><select id="governance-assignment-role">${data.roles.filter(role=>!role.archived).map(role=>`<option value="${esc(role.id)}" ${role.id===(row?.role_id||'member')?'selected':''}>${esc(role.name)}</option>`).join('')}</select></div>`);
    governanceSave(dialog,version,()=>api('/api/admin/role-assignments',{method:'PUT',body:JSON.stringify({email:dialog.querySelector('#governance-assignment-email').value,role_id:dialog.querySelector('#governance-assignment-role').value,revision:row?.revision||0})}));
  };
  $('#governance-assign-role').onclick=()=>assign();
  document.querySelectorAll('[data-role-assign]').forEach(button=>button.onclick=()=>assign(data.assignments.find(row=>row.email===button.dataset.roleAssign)));
}

function governanceProvisioning(data) {
  return `<section class="governance-section"><div class="section-header"><div><h2>Directory provisioning</h2><p class="subtext">Connect your identity provider to create users, manage groups, and deactivate access.</p></div><button class="primary" id="governance-new-token">Create token</button></div><div class="field"><label for="governance-scim-url">SCIM base URL</label><input id="governance-scim-url" readonly value="${esc(data.base_url)}"></div>
    ${governanceTable('SCIM tokens',['Token','Created','Status',''],data.tokens.map(token=>`<tr><td><strong>${esc(token.label)}</strong><small>${esc(token.prefix)}</small></td><td>${esc(new Date(token.created_at).toLocaleDateString())}</td><td>${token.revoked_at?'Revoked':'Active'}</td><td>${token.revoked_at?'':`<button class="quiet danger" data-scim-revoke="${esc(token.id)}">Revoke</button>`}</td></tr>`),'Create a provisioning token to connect your directory.')}
  </section><section class="governance-section"><h2>Provisioned users</h2>${governanceTable('Provisioned users',['User','Work email','Status'],data.users.map(user=>`<tr><td>${esc(user.displayName||user.userName)}</td><td>${esc(user.userName)}</td><td><span class="badge">${user.active?'Active':'Deactivated'}</span></td></tr>`),'No users have been provisioned yet.')}</section>
    <section class="governance-section"><div class="section-header"><div><h2>Directory groups</h2><p class="subtext">Group roles add permissions to each active member.</p></div>${hasWorkspacePermission('roles.manage')?'<button id="governance-group-role" class="quiet">Assign group role</button>':''}</div>${governanceTable('Provisioned groups',['Group','Members'],data.groups.map(group=>`<tr><td>${esc(group.displayName)}</td><td>${group.members?.length||0}</td></tr>`),'No groups have been provisioned yet.')}</section>
    <details class="governance-section"><summary>Recent provisioning activity</summary>${governanceActivity(data.activity)}</details>`;
}

function bindGovernanceProvisioning(data,version) {
  $('#governance-new-token').onclick=()=>{
    const dialog=governanceDialog('Create provisioning token','<div class="field"><label for="governance-token-label">Token label</label><input id="governance-token-label" required maxlength="80" placeholder="Identity provider"></div>');
    dialog.querySelector('[type="submit"]').textContent='Create token';
    dialog.querySelector('form').onsubmit=async event=>{
      event.preventDefault();const button=dialog.querySelector('[type="submit"]');button.disabled=true;
      try{
        const saved=await api('/api/admin/scim/tokens',{method:'POST',body:JSON.stringify({label:dialog.querySelector('#governance-token-label').value})});
        if(!dialog.isConnected)return;
        MoyaiUI.render(dialog,`<h2>Provisioning token created</h2><p>Copy this token into your identity provider. It is shown only once.</p><div class="field"><label for="governance-token-secret">Bearer token</label><input id="governance-token-secret" type="password" readonly autocomplete="off" value="${esc(saved.token)}"></div><div class="credential-actions"><button id="governance-token-copy" class="primary">Copy token</button><button id="governance-token-done" class="quiet">Done</button></div><p id="governance-token-status" role="status"></p>`);
        dialog.querySelector('#governance-token-copy').onclick=async()=>{
          try{await navigator.clipboard.writeText(saved.token);dialog.querySelector('#governance-token-status').textContent='Copied';}catch{dialog.querySelector('#governance-token-status').textContent='Clipboard unavailable. Select and copy the token field.';dialog.querySelector('#governance-token-secret').select();}
        };
        dialog.querySelector('#governance-token-done').onclick=()=>{dialog.close();if(version===state.pageVersion)renderGovernance().catch(error=>toast(error.message));};
      }catch(error){if(dialog.isConnected){dialog.querySelector('#governance-error').textContent=error.message;button.disabled=false;}}
    };
  };
  document.querySelectorAll('[data-scim-revoke]').forEach(button=>button.onclick=async()=>{
    if(!await confirmSettingsAction('Revoke provisioning token','The directory using this token will lose access immediately. Existing users and groups remain saved.','Revoke token'))return;
    try{await api('/api/admin/scim/tokens/'+encodeURIComponent(button.dataset.scimRevoke),{method:'DELETE'});if(version===state.pageVersion)await renderGovernance();}catch(error){toast(error.message);}
  });
  if($('#governance-group-role'))$('#governance-group-role').onclick=async()=>{
    try{
      const roles=await api('/api/admin/roles');
      if(version!==state.pageVersion||governanceState.tab!=='provisioning')return;
      const dialog=governanceDialog('Assign group role',`<div class="field"><label for="governance-group">Directory group</label><select id="governance-group" required>${data.groups.map(group=>`<option value="${esc(group.id)}">${esc(group.displayName)}</option>`).join('')}</select></div><div class="field"><label for="governance-group-role-id">Additional role</label><select id="governance-group-role-id"><option value="">No additional permissions</option>${roles.roles.filter(role=>!role.archived&&role.id!=='admin').map(role=>`<option value="${esc(role.id)}">${esc(role.name)}</option>`).join('')}</select></div>`);
      const synchronize=()=>{const mapping=roles.group_roles.find(row=>row.group_id===dialog.querySelector('#governance-group').value);dialog.querySelector('#governance-group-role-id').value=mapping?.role_id||'';};
      dialog.querySelector('#governance-group').onchange=synchronize;synchronize();
      governanceSave(dialog,version,()=>{const group=dialog.querySelector('#governance-group').value,mapping=roles.group_roles.find(row=>row.group_id===group);return api('/api/admin/group-roles/'+encodeURIComponent(group),{method:'PUT',body:JSON.stringify({role_id:dialog.querySelector('#governance-group-role-id').value||null,revision:mapping?.revision||0})});});
    }catch(error){toast(error.message);}
  };
}

function governancePolicies(data) {
  const options=selected=>`<option value="">Unrestricted</option>${data.profiles.filter(profile=>profile.enabled).map(profile=>`<option value="${profile.id}" ${selected===profile.id?'selected':''}>${esc(profile.name)}</option>`).join('')}`;
  return `<section class="governance-section"><div class="section-header"><div><h2>Security policies</h2><p class="subtext">Limit connected apps, tools, managed Git access, and network destinations.</p></div><button id="governance-new-profile" class="primary">Create policy</button></div><p class="subtext">Domain restrictions require Substrate. Other providers reject restricted sessions before starting a machine.</p>
    ${data.profiles.length?data.profiles.map(profile=>`<article class="governance-row"><div><h3>${esc(profile.name)} ${profile.enabled?'':'<span class="badge">Disabled</span>'}</h3><p class="subtext">Managed Git: ${esc(profile.policy.git_access)} · Apps: ${profile.policy.connected_apps===null?'all':esc(profile.policy.connected_apps.join(', ')||'none')} · Network: ${profile.policy.network_domains===null?'unrestricted':esc(profile.policy.network_domains.join(', ')||'blocked')}</p><small>Revision ${profile.revision}</small></div><button class="quiet" data-profile-edit="${profile.id}">Edit</button></article>`).join(''):'<p class="subtext">No policies yet. Create a policy to restrict agent access.</p>'}
  </section><section class="governance-section"><h2>Organization defaults</h2><p class="subtext">The default applies to new sessions. The mandatory policy constrains every session and its delegated agents.</p><form id="governance-defaults"><div class="governance-form-grid"><div class="field"><label for="governance-default-profile">Default policy</label><select id="governance-default-profile">${options(data.defaults.default_profile_id)}</select></div><div class="field"><label for="governance-floor-profile">Mandatory policy</label><select id="governance-floor-profile">${options(data.defaults.floor_profile_id)}</select></div></div><div class="credential-actions"><button class="primary" type="submit">Save defaults</button></div><p id="governance-defaults-status" role="status"></p></form></section>`;
}

function bindGovernancePolicies(data,version) {
  const edit=profile=>{
    const policy=profile?.policy||{network_domains:null,connected_apps:null,tools:null,git_access:'write'};
    const dialog=governanceDialog(profile?'Edit security policy':'Create security policy',`<div class="field"><label for="governance-policy-name">Policy name</label><input id="governance-policy-name" required maxlength="80" value="${esc(profile?.name||'')}"></div><label class="governance-check"><input id="governance-policy-enabled" type="checkbox" ${profile?.enabled!==false?'checked':''}><span>Available for new sessions</span></label><div class="field"><label for="governance-git-access">Managed Git access</label><select id="governance-git-access">${[['write','Read and write'],['read','Read only'],['none','No managed Git access']].map(([id,label])=>`<option value="${id}" ${policy.git_access===id?'selected':''}>${label}</option>`).join('')}</select></div><label class="governance-check"><input id="governance-restrict-network" type="checkbox" ${policy.network_domains!==null?'checked':''}><span>Restrict network destinations</span></label><div class="field"><label for="governance-network-domains">Allowed domains</label><textarea id="governance-network-domains" rows="3" placeholder="registry.npmjs.org&#10;github.com">${esc((policy.network_domains||[]).join('\n'))}</textarea><small>Exact hostnames, one per line. An empty restricted list blocks outbound traffic except Moyai’s broker. Requires Substrate.</small></div><label class="governance-check"><input id="governance-restrict-apps" type="checkbox" ${policy.connected_apps!==null?'checked':''}><span>Restrict connected apps</span></label><div class="governance-apps">${['github','linear','slack','notion'].map(id=>`<label class="governance-check"><input name="policy-app" type="checkbox" value="${id}" ${policy.connected_apps===null||policy.connected_apps.includes(id)?'checked':''}><span>${id[0].toUpperCase()+id.slice(1)}</span></label>`).join('')}</div><label class="governance-check"><input id="governance-restrict-tools" type="checkbox" ${policy.tools!==null?'checked':''}><span>Restrict agent tools</span></label><div class="field"><label for="governance-allowed-tools">Allowed broker tool names</label><textarea id="governance-allowed-tools" rows="3">${esc((policy.tools||[]).join('\n'))}</textarea><small>An empty restricted list disables all broker tools. Native shell operations follow the machine's network policy.</small></div>`);
    const toggle=()=>{dialog.querySelector('#governance-network-domains').disabled=!dialog.querySelector('#governance-restrict-network').checked;dialog.querySelector('#governance-allowed-tools').disabled=!dialog.querySelector('#governance-restrict-tools').checked;dialog.querySelectorAll('[name="policy-app"]').forEach(input=>input.disabled=!dialog.querySelector('#governance-restrict-apps').checked);};
    dialog.querySelectorAll('[id^="governance-restrict-"]').forEach(input=>input.onchange=toggle);toggle();
    const list=id=>dialog.querySelector(id).value.split(/[\s,]+/).filter(Boolean);
    governanceSave(dialog,version,()=>api(profile?'/api/admin/security-profiles/'+profile.id:'/api/admin/security-profiles',{method:profile?'PUT':'POST',body:JSON.stringify({name:dialog.querySelector('#governance-policy-name').value,revision:profile?.revision||0,enabled:dialog.querySelector('#governance-policy-enabled').checked,policy:{git_access:dialog.querySelector('#governance-git-access').value,network_domains:dialog.querySelector('#governance-restrict-network').checked?list('#governance-network-domains'):null,connected_apps:dialog.querySelector('#governance-restrict-apps').checked?[...dialog.querySelectorAll('[name="policy-app"]:checked')].map(input=>input.value):null,tools:dialog.querySelector('#governance-restrict-tools').checked?list('#governance-allowed-tools'):null}})}));
  };
  $('#governance-new-profile').onclick=()=>edit();
  document.querySelectorAll('[data-profile-edit]').forEach(button=>button.onclick=()=>edit(data.profiles.find(profile=>profile.id===button.dataset.profileEdit)));
  $('#governance-defaults').onsubmit=async event=>{
    event.preventDefault();const button=event.currentTarget.querySelector('[type="submit"]');button.disabled=true;
    try{const saved=await api('/api/admin/security-profiles/defaults',{method:'PUT',body:JSON.stringify({revision:data.defaults.revision,default_profile_id:$('#governance-default-profile').value,floor_profile_id:$('#governance-floor-profile').value})});if(version!==state.pageVersion)return;data.defaults=saved;$('#governance-defaults-status').textContent='Defaults saved';}catch(error){if(version===state.pageVersion)$('#governance-defaults-status').textContent=error.message;}finally{if(version===state.pageVersion)button.disabled=false;}
  };
}
