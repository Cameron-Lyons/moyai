"""Workspace permissions and the authorization contract for existing routes.

Built-in roles retain their previous access. Custom roles are explicit allowlists;
the route map is deliberately conservative for legacy administrator endpoints.
"""
import re
from urllib.parse import urlparse


PERMISSIONS = {
    'workspace.read': 'View workspace settings and configuration',
    'sessions.read': 'View accessible sessions, files and activity',
    'sessions.create': 'Start agent sessions',
    'sessions.manage': 'Steer, stop and organize accessible sessions',
    'connections.read': 'View app connections and use enabled app read tools',
    'connections.write': 'Use enabled organization app write tools',
    'connections.manage': 'Connect apps and change organization connection policies',
    'automations.read': 'View workflows and their run history',
    'automations.manage': 'Create and manage owned workflows',
    'environments.read': 'Use prepared project environments',
    'environments.manage': 'Create, build and change organization environments',
    'skills.read': 'Discover and read authorized skills',
    'skills.manage': 'Create and manage personal skills',
    'skills.publish': 'Publish and manage organization skills',
    'memory.read': 'Recall personal memory',
    'memory.manage': 'Save and manage personal memory',
    'credentials.read': 'Discover and use authorized credentials',
    'credentials.manage': 'Create and manage personal credentials',
    'credentials.publish': 'Create and manage organization credentials',
    'users.read': 'View the workspace user directory',
    'users.manage': 'Assign built-in user roles',
    'roles.manage': 'Manage custom roles, assignments and group grants',
    'spend.personal': 'View personal model spend',
    'spend.read': 'View organization spend and adoption',
    'spend.manage': 'Manage infrastructure billing and spend identity links',
    'runtime.manage': 'View performance, capacity, pull-request and deployment details; configure session titles',
    'organization.manage': 'Change organization settings',
    'audit.read': 'Read enterprise governance audit history',
    'security.manage': 'Manage security profiles, policies and profile selections',
    'scim.manage': 'View directory provisioning and revoke provisioning credentials',
}

MEMBER_PERMISSIONS = frozenset({
    'workspace.read', 'sessions.read', 'sessions.create', 'sessions.manage',
    'connections.read', 'connections.write', 'automations.read', 'automations.manage', 'environments.read',
    'skills.read', 'skills.manage', 'memory.read', 'memory.manage',
    'credentials.read', 'credentials.manage', 'spend.personal',
})
BUILTIN_PERMISSIONS = {'admin': frozenset(PERMISSIONS), 'member': MEMBER_PERMISSIONS}

# Broker capabilities retain their existing ownership and provider policies.
# A live session capability alone must not restore permissions removed by a
# custom role. These guards describe capability use, not connection setup.
TOOL_PERMISSIONS = {
    **dict.fromkeys({'sessions_read', 'sessions_search', 'history_read',
                     'computer_operation_read', 'artifacts_list', 'artifact_read',
                     'artifact_fetch', 'media_list', 'agents_results',
                     'agents_read_artifact', 'agents_wait', 'swarm_board',
                     'slack_context'}, 'sessions.read'),
    **dict.fromkeys({'goal', 'computer_handoff', 'artifact_publish', 'media_share',
                     'media_revoke', 'model_switch', 'agents_send', 'agents_cancel',
                     'swarm_claim_lead', 'swarm_publish', 'swarm_assign',
                     'slack_participation'}, 'sessions.manage'),
    **dict.fromkeys({'swarm_start', 'agents_fanout', 'agents_retry'}, 'sessions.create'),
    **dict.fromkeys({'workspace_diagnostics', 'model_list'}, 'workspace.read'),
    **dict.fromkeys({'automation_list', 'automation_history', 'automation_self_read',
                     'automation_webhook_info'}, 'automations.read'),
    **dict.fromkeys({'automation_grant', 'automation_self_update', 'automation_create',
                     'automation_update', 'automation_enable', 'automation_pause',
                     'automation_webhook_setup', 'automation_claim_item'}, 'automations.manage'),
    'automation_environments': 'environments.read',
    **dict.fromkeys({'repository_context_search', 'repository_context_read'}, 'connections.read'),
    **dict.fromkeys({'bundled_skill_read', 'skills_search', 'skills_load',
                     'skills_read_file'}, 'skills.read'),
    'skills_save': 'skills.manage',
    **dict.fromkeys({'memory_search', 'memory_read'}, 'memory.read'),
    **dict.fromkeys({'memory_save', 'memory_forget'}, 'memory.manage'),
    **dict.fromkeys({'credentials_list', 'credentials_resolve', 'credentials_request',
                     'credentials_run', 'credentials_report_failure', 'credentials_aws_login',
                     'credentials_http_request', 'slack_personal_search',
                     'slack_personal_conversations', 'slack_personal_history',
                     'slack_personal_thread'}, 'credentials.read'),
}


def tool_permission(name):
    permission = TOOL_PERMISSIONS.get(name)
    if permission:
        return permission
    if isinstance(name, str) and name.startswith(('github_', 'linear_', 'slack_', 'notion_')):
        from .connectors import TOOLS
        spec = TOOLS.get(name)
        return 'connections.write' if spec and spec[1] else 'connections.read'
    return None


def catalog():
    return [{'id': key, 'description': description} for key, description in PERMISSIONS.items()]


def shared_actor_role(actor_id, settings):
    parts = actor_id.split(':') if isinstance(actor_id, str) else []
    if len(parts) != 3 or parts[0] != 'shared' or parts[2] not in BUILTIN_PERMISSIONS:
        return None
    method, role = parts[1:]
    if method == 'local':
        local = urlparse(settings.public_url).hostname in {'localhost', '127.0.0.1', '::1'}
        return role if local and not settings.workspace_password and not settings.person_login_enabled() else None
    if method == 'password' and settings.password_login_enabled:
        configured = settings.workspace_password if role == 'admin' else settings.workspace_member_password
        return role if configured else None
    return None


def route_permission(request):
    """Map a concrete public route to its permission; unknown routes stay unchanged."""
    scope = getattr(request, 'scope', {})
    path = scope.get('path', '')
    method = scope.get('method', 'GET').upper()
    read = method in {'GET', 'HEAD'} or scope.get('type') == 'websocket'
    if path in {'/api/config', '/api/organization'}:
        return 'workspace.read' if read else 'organization.manage'
    if path == '/api/settings/model-preference':
        return 'workspace.read'
    if path == '/api/settings/preferences':
        return 'workspace.read'
    if path == '/api/settings/session-titles':
        return 'workspace.read' if read else 'runtime.manage'
    if path == '/api/security-profiles':
        return 'security.manage'
    if path == '/api/runs':
        return 'sessions.read' if read else 'sessions.create'
    if re.fullmatch(r'/api/runs/[0-9a-f]{32}(?:/.*)?', path):
        return 'sessions.read' if read else 'sessions.manage'
    if path.startswith('/api/session-folders') or path.startswith('/api/attachments'):
        return 'sessions.read' if read else 'sessions.manage'
    if path == '/api/connections':
        return 'connections.read'
    if path.startswith('/api/connections/'):
        return 'connections.manage'
    if re.fullmatch(r'/(?:auth/github/register|oauth/(?:github/(?:app-callback|callback)|(?:linear|slack|notion)/callback))', path):
        return 'connections.manage'
    if path.startswith('/api/automations'):
        return 'automations.read' if read else 'automations.manage'
    if path == '/api/environments':
        return 'environments.read'
    if path.startswith('/api/admin/environments') or path.startswith('/api/admin/environment-builds/'):
        return 'environments.manage'
    if path.startswith('/api/skills'):
        return 'skills.read' if read else 'skills.manage'
    if path.startswith('/api/skill-learning'):
        return 'skills.read' if read else 'skills.manage'
    if path.startswith('/api/memory'):
        return 'memory.read' if read else 'memory.manage'
    if path.startswith('/api/credentials'):
        return 'credentials.read' if read else 'credentials.manage'
    if path == '/api/admin/users':
        return 'users.read'
    if path == '/api/admin/users/role':
        return 'users.manage'
    if path.startswith('/api/admin/identities/'):
        return 'users.read' if read else 'users.manage'
    if path == '/api/spend':
        return 'spend.personal'
    if path in {'/api/admin/spend', '/api/admin/adoption'}:
        return 'spend.read'
    if path.startswith('/api/admin/spend/'):
        return 'spend.manage'
    if path in {'/api/admin/pull-requests', '/api/admin/capacity', '/api/admin/performance'}:
        return 'runtime.manage'
    if path == '/api/settings/sandboxes':
        # The provider receives materialized credentials for every session, so
        # changing it keeps the built-in administrator boundary.
        return 'workspace.read' if read else None
    if path.startswith('/api/admin/security'):
        return 'security.manage'
    return None
