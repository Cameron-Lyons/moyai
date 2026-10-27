"""One immutable organization per deployment and its database.

Explicit organization IDs isolate default infrastructure namespaces. This is a
deployment guard, not a request-selected tenant or a shared control plane.
Legacy deployments with no ID retain their existing configuration. Temporal
namespaces are provisioned externally (Cloud IDs are <name>.<account>), so an
organization deployment names its own instead of receiving a derived one.
"""
from .database import DatabaseError
from .db import now
from .schema_initializers import initialize_organization_scope as initialize_schema


POPULATED_TABLES = ('runs', 'users', 'connections', 'automations', 'provider_secrets',
                    'memory_notes', 'skills', 'user_roles', 'enterprise_roles',
                    'scim_users', 'scim_groups', 'security_profiles')


def scoped_name(value, organization_id, maximum=None):
    suffix = '-org-' + organization_id
    if not value:
        return value
    if value.endswith(suffix):
        if not maximum or len(value) <= maximum:
            return value
        value = value[:-len(suffix)]
    if maximum:
        value = value[:maximum - len(suffix)].rstrip('-')
    return value + suffix


def scoped_prefix(value, organization_id):
    suffix = '/organizations/' + organization_id
    return value if not value or value.endswith(suffix) else value + suffix


def scope_settings(settings):
    """Idempotent for model_dump round trips and saved sandbox overrides."""
    identity = settings.moyai_organization_id
    if not identity:
        return settings
    settings.temporal_task_queue = scoped_name(settings.temporal_task_queue, identity, 200)
    for field in ('modal_app_name', 'modal_volume_name'):
        setattr(settings, field, scoped_name(getattr(settings, field), identity, 64))
    settings.substrate_atespace = scoped_name(settings.substrate_atespace, identity, 63)
    settings.object_storage_prefix = scoped_prefix(settings.object_storage_prefix, identity)
    settings.lambda_checkpoint_prefix = scoped_prefix(settings.lambda_checkpoint_prefix, identity)
    # Field validators rerun on every saved-settings round trip; fail on first boot.
    if len(settings.object_storage_prefix) > 200:
        raise ValueError('Object storage prefix is too long after organization scoping.')
    if len(settings.lambda_checkpoint_prefix) > 181:
        raise ValueError('Lambda checkpoint prefix is too long after organization scoping.')
    return settings


def require_pin(conn, identity):
    """Apply the startup pin rule to a database; True when an empty one may be pinned.

    Read-only, so maintenance tools that bypass OrganizationScope can share it.
    """
    tables = conn.table_names()
    row = (conn.execute('SELECT organization_id FROM organization_scope WHERE id=1').fetchone()
           if 'organization_scope' in tables else None)
    if row:
        if row['organization_id'] != identity:
            raise DatabaseError('This database belongs to a different organization. Restore its pinned MOYAI_ORGANIZATION_ID or use a separate database.')
        return False
    if not identity:
        return False
    # Automatically changing infrastructure names underneath existing
    # workflows, checkpoints or credentials would strand a legacy
    # deployment. Fresh organization deployment setup is safe; legacy
    # adoption needs a separate, operator-reviewed migration.
    for table in POPULATED_TABLES:
        if table in tables and conn.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone():
            raise DatabaseError('This existing deployment has no organization pin. Create a fresh organization deployment; namespace migration is required before adopting an existing database.')
    return True


class OrganizationScope:
    def __init__(self, store, settings):
        if settings.moyai_organization_id and settings.temporal_enabled and settings.temporal_namespace == 'default':
            # Task queues alone do not isolate workflow history or namespace credentials.
            raise DatabaseError("Set TEMPORAL_NAMESPACE to this organization's own provisioned Temporal namespace; organization deployments cannot use the shared 'default' namespace.")
        self.store, self.settings = store, settings
        if store.schema_updates:
            initialize_schema(store)
        self.bind()
        store.organization_id = settings.moyai_organization_id

    def bind(self):
        identity = self.settings.moyai_organization_id
        with self.store.connect() as conn:
            conn.begin_write()
            if require_pin(conn, identity):
                conn.execute('INSERT INTO organization_scope(id,organization_id,created_at) VALUES(1,?,?)', (identity, now()))
