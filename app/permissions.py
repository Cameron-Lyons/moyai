"""Workspace permissions shared by canonical services and the native runtime.

Built-in roles retain their previous access: admin holds every permission and
member holds MEMBER_PERMISSIONS. Custom roles are explicit allowlists.

Tool permissions describe capability use inside an already admitted turn; they
never authorize connection setup. Every native tool has an explicit entry, and a
tool without one resolves to the session-scoped DEFAULT_TOOL_PERMISSION instead
of "no check", so an empty or archived custom role never fails open.
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
    'spend.read': 'View organization spend, adoption and spend limits',
    'spend.manage': 'Manage spend limits, infrastructure billing and spend identity links',
    'runtime.manage': 'View performance, capacity, pull-request and deployment details; configure session titles',
    'organization.manage': 'Change organization settings',
    'audit.read': 'Read enterprise governance audit history',
    'security.manage': 'Manage security profiles and policies',
    'scim.manage': 'View directory provisioning and revoke provisioning credentials',
}

MEMBER_PERMISSIONS = frozenset({
    'workspace.read', 'sessions.read', 'sessions.create', 'sessions.manage',
    'connections.read', 'connections.write', 'automations.read', 'automations.manage', 'environments.read',
    'skills.read', 'skills.manage', 'memory.read', 'memory.manage',
    'credentials.read', 'credentials.manage', 'spend.personal',
})
BUILTIN_PERMISSIONS = {'admin': frozenset(PERMISSIONS), 'member': MEMBER_PERMISSIONS}


def route_permission(request):
    """Permissions for the native HTTP surface, independent of navigation visibility."""
    path = request.scope.get('path', '')
    read = request.method in {'GET', 'HEAD', 'OPTIONS'}
    if path in {'/api/me', '/api/permissions', '/api/logout', '/api/login'}:
        return None
    if path.startswith('/api/admin/roles') or path.startswith('/api/admin/role-assignments') or path.startswith('/api/admin/group-roles'):
        return 'roles.manage'
    if path.startswith('/api/admin/scim'):
        return 'scim.manage'
    if path.startswith(('/api/security-profiles', '/api/admin/security-profiles')):
        return 'security.manage'
    if path.startswith('/api/admin/governance'):
        return 'audit.read'
    if path.startswith('/api/admin/spend-limits'):
        return 'spend.read' if read else 'spend.manage'
    if path.startswith('/api/admin/spend'):
        return 'spend.read' if read else 'spend.manage'
    if path == '/api/spend':
        return 'spend.personal'
    if path.startswith('/api/product/automations'):
        return 'automations.read' if read else 'automations.manage'
    if path.startswith('/api/product/memory'):
        return 'memory.read' if read else 'memory.manage'
    if path.startswith(('/api/product/skills', '/api/skills')):
        return 'skills.read' if read else 'skills.manage'
    if path.startswith('/api/product/environments'):
        return 'environments.read'
    if path.startswith('/api/product/connections'):
        return 'connections.read' if read else 'connections.manage'
    if path.startswith(('/api/product/credentials', '/api/product/credential-requests')):
        return 'credentials.read' if read else 'credentials.manage'
    if path.startswith('/api/product/sessions'):
        return 'sessions.read' if read else 'sessions.create'
    if path.startswith(('/api/history', '/api/files/', '/api/pull-requests')):
        return 'sessions.read'
    if path.startswith('/api/effects/'):
        return 'sessions.manage'
    if path.startswith('/api/session-folders'):
        return 'sessions.read' if read else 'sessions.manage'
    if path.startswith('/api/uploads'):
        return 'sessions.read' if read else 'sessions.create'
    if not read and path.startswith('/api/sessions/') and path.endswith('/messages'):
        return 'sessions.create'
    if path == '/api/sessions':
        return 'sessions.read' if read else 'sessions.create'
    if path.startswith(('/api/sessions/', '/api/turns/', '/api/folders', '/api/uploads', '/api/artifacts', '/api/computer', '/api/goals', '/api/swarms')):
        return 'sessions.read' if read else 'sessions.manage'
    if path.startswith('/api/connections'):
        return 'connections.read' if read else 'connections.manage'
    if path.startswith(('/api/automations', '/api/settings/automations')):
        return 'automations.read' if read else 'automations.manage'
    if path.startswith('/api/settings/users'):
        return 'users.read' if read else 'users.manage'
    if path.startswith('/api/settings/skills'):
        return 'skills.read' if read else 'skills.manage'
    if path.startswith('/api/settings/memory'):
        return 'memory.read' if read else 'memory.manage'
    if path.startswith(('/api/settings/secrets', '/api/credentials')):
        return 'credentials.read' if read else 'credentials.manage'
    if path.startswith('/api/settings/connections'):
        return 'connections.read' if read else 'connections.manage'
    if path.startswith(('/api/settings/usage', '/api/settings/billing')):
        return 'spend.read' if read else 'spend.manage'
    if path.startswith(('/api/settings/performance', '/api/admin/performance')):
        return 'runtime.manage'
    return 'workspace.read' if path.startswith('/api/settings') else None

# Display label and group per permission. The UI groups by `group` in order of first appearance.
LABELS = {
    'workspace.read': ('View workspace settings', 'Workspace'),
    'organization.manage': ('Change organization settings', 'Workspace'),
    'sessions.read': ('View sessions', 'Sessions'),
    'sessions.create': ('Start sessions', 'Sessions'),
    'sessions.manage': ('Steer and organize sessions', 'Sessions'),
    'connections.read': ('Use connected apps to read', 'Connections'),
    'connections.write': ('Use connected apps to make changes', 'Connections'),
    'connections.manage': ('Manage organization connections', 'Connections'),
    'automations.read': ('View automations', 'Automations'),
    'automations.manage': ('Manage automations', 'Automations'),
    'environments.read': ('Use environments', 'Environments'),
    'environments.manage': ('Manage environments', 'Environments'),
    'skills.read': ('Use skills', 'Skills'),
    'skills.manage': ('Manage personal skills', 'Skills'),
    'skills.publish': ('Publish organization skills', 'Skills'),
    'memory.read': ('Recall memory', 'Memory'),
    'memory.manage': ('Manage memory', 'Memory'),
    'credentials.read': ('Use credentials', 'Credentials'),
    'credentials.manage': ('Manage personal credentials', 'Credentials'),
    'credentials.publish': ('Manage organization credentials', 'Credentials'),
    'users.read': ('View the user directory', 'People'),
    'users.manage': ('Change built-in roles', 'People'),
    'roles.manage': ('Manage custom roles and grants', 'People'),
    'scim.manage': ('Manage directory provisioning', 'People'),
    'spend.personal': ('View personal spend', 'Spend'),
    'spend.read': ('View organization spend and limits', 'Spend'),
    'spend.manage': ('Manage spend limits and billing', 'Spend'),
    'runtime.manage': ('View performance and runtime details', 'Operations'),
    'security.manage': ('Manage security policies', 'Security'),
    'audit.read': ('Read the audit log', 'Security'),
}


def catalog():
    """Every permission once, in PERMISSIONS order, with its label, description and display group."""
    return [{'id': key, 'label': LABELS[key][0], 'description': description, 'group': LABELS[key][1]}
            for key, description in PERMISSIONS.items()]


def shared_actor_role(actor_id, settings):
    """The built-in role of a shared `shared:<method>:<role>` actor while its sign-in method is enabled."""
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


# Turn admission already requires sessions.create, so tools that act only on the
# session's own computer, plan, transcript or questions use it too: a narrower
# read permission would break the agent loop for roles that may start sessions.
DEFAULT_TOOL_PERMISSION = 'sessions.create'
SESSION_TOOLS = (
    # Harness Coder: FileSystem, every registrable Shell tool, and SubAgents.
    'read_file', 'write_file', 'edit_file', 'list_files', 'grep',
    'shell', 'run_command', 'start_command', 'check_command', 'stop_command', 'delegate_task',
    # Harness Planning (enable_subtasks=True), AskUser and ConversationSearch.
    'write_plan', 'read_plan', 'add_task', 'update_task_status', 'update_task_statuses',
    'remove_task', 'add_subtask', 'set_dependency', 'get_available_tasks',
    'ask_user_question', 'search_conversation_history',
    # Pydantic AI discovery of deferred tools.
    'search_tools',
    # Native session capabilities: artifacts, input attachments and the shared browser.
    'save_artifact', 'attach_link', 'attachment_copy', 'browser_open', 'browser_read', 'browser_action',
)
TOOL_PERMISSIONS = {
    **dict.fromkeys(('get_goal', 'swarm_board', 'swarm_read'), 'sessions.read'),
    **dict.fromkeys(('update_goal', 'request_browser_login', 'swarm_assign', 'swarm_claim_lead',
                     'swarm_finish', 'swarm_publish'), 'sessions.manage'),
    **dict.fromkeys(('skill_list', 'skill_read'), 'skills.read'),
    **dict.fromkeys(('skill_create', 'skill_update', 'skill_delete'), 'skills.manage'),
    **dict.fromkeys(('checkout', 'stack', 'stacks'), 'connections.read'),
    **dict.fromkeys(('add_to_stack', 'close_pull_request', 'convert_pull_request_to_draft',
                     'create_branch', 'create_review', 'create_stack', 'delete_pending_review',
                     'edit_pending_review', 'open_pull_request', 'publish_branch', 'rebase_pull_request',
                     'reopen_pull_request', 'request_pr_lifecycle_access', 'retarget_pull_request',
                     'submit_review'), 'connections.write'),
    **dict.fromkeys(SESSION_TOOLS, DEFAULT_TOOL_PERMISSION),
    # Native deferred capabilities are saved and bundled skills.
    'load_capability': 'skills.read',
    **dict.fromkeys(('read_memory', 'search_memory'), 'memory.read'),
    **dict.fromkeys(('write_memory', 'delete_memory'), 'memory.manage'),
    **dict.fromkeys(('credentials_list', 'credentials_request', 'credentials_run'), 'credentials.read'),
    **dict.fromkeys(('automation_list', 'automation_preview', 'automation_history', 'automation_self_read',
                     'automation_webhook_info'), 'automations.read'),
    'automation_environments': 'environments.read',
    **dict.fromkeys(('automation_webhook_setup', 'automation_grant', 'automation_self_update',
                     'automation_claim_item', 'automation_create', 'automation_update', 'automation_migrate',
                     'automation_enable', 'automation_pause', 'automation_retire'), 'automations.manage'),
    # Product GitHub publication tools; the model sees them under a GitHub grant prefix.
    'publication_status': 'connections.read',
    **dict.fromkeys(('create_pull_request', 'update_pull_request', 'request_pull_request_write_access'),
                    'connections.write'),
}
GITHUB_PUBLICATION_TOOLS = frozenset({
    'publication_status', 'create_pull_request', 'update_pull_request', 'request_pull_request_write_access',
    'checkout', 'stack', 'stacks', 'add_to_stack', 'close_pull_request',
    'convert_pull_request_to_draft', 'create_branch', 'create_review', 'create_stack',
    'delete_pending_review', 'edit_pending_review', 'open_pull_request', 'publish_branch',
    'rebase_pull_request', 'reopen_pull_request', 'request_pr_lifecycle_access',
    'retarget_pull_request', 'submit_review',
})
# Every tool name native agents register outside connector toolsets.
NATIVE_TOOL_NAMES = frozenset(TOOL_PERMISSIONS)
CONNECTOR_PROVIDERS = ('github', 'linear', 'notion', 'slack')
# Connector tools reach the model as `<kind>_<first 8 grant-id characters>_<tool>`.
CONNECTOR_TOOL = re.compile(r'(github|linear|notion|slack)_([0-9a-f]{8})_([a-z][a-z0-9_]*)')


def connector_tool(name):
    """(provider, unprefixed tool name) for a grant-prefixed connector tool, else None."""
    match = CONNECTOR_TOOL.fullmatch(name) if isinstance(name, str) else None
    return (match[1], match[3]) if match else ('github', name) if name in GITHUB_PUBLICATION_TOOLS else None


def tool_permission(name, *, read_only=None):
    """The permission one tool call requires; never None.

    Native tools use TOOL_PERMISSIONS. Connector tools, grant-prefixed or
    canonical, resolve through app.connectors.TOOLS: writes need
    connections.write and reads connections.read. A prefixed provider tool the
    canonical catalog does not know (harness GitHub reads, standalone provider
    tools) follows read_only, the server-built definition's readOnlyHint, and
    is a write when that is unknown. Anything else is DEFAULT_TOOL_PERMISSION.
    """
    if not isinstance(name, str):
        return DEFAULT_TOOL_PERMISSION
    if name in TOOL_PERMISSIONS:
        return TOOL_PERMISSIONS[name]
    from .connectors import TOOLS
    prefixed = connector_tool(name)
    if prefixed:
        provider, operation = prefixed
        if provider == 'github' and operation in GITHUB_PUBLICATION_TOOLS:
            return TOOL_PERMISSIONS[operation]
        # Canonical names keep their provider prefix unless they never had one.
        name = provider + '_' + operation
        if name not in TOOLS and TOOLS.get(operation, ('',))[0] == provider:
            name = operation
    spec = TOOLS.get(name)
    if spec is not None:
        return 'connections.write' if spec[1] else 'connections.read'
    if prefixed:
        return 'connections.read' if read_only is True else 'connections.write'
    return DEFAULT_TOOL_PERMISSION
