"""One immutable organization per deployment and its database.

Explicit organization IDs isolate default infrastructure namespaces. This is a
deployment guard, not a request-selected tenant or a shared control plane.
Legacy deployments with no ID retain their existing configuration.
"""
import json

from .database import DatabaseError
from .db import now


NAMESPACE_FIELDS = ('temporal_namespace', 'temporal_task_queue', 'object_storage_prefix',
                    'lambda_checkpoint_prefix', 'modal_app_name', 'modal_volume_name', 'substrate_atespace')


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
    for field in ('temporal_namespace', 'temporal_task_queue'):
        setattr(settings, field, scoped_name(getattr(settings, field), identity, 200))
    for field in ('modal_app_name', 'modal_volume_name'):
        setattr(settings, field, scoped_name(getattr(settings, field), identity, 64))
    settings.substrate_atespace = scoped_name(settings.substrate_atespace, identity, 63)
    settings.object_storage_prefix = scoped_prefix(settings.object_storage_prefix, identity)
    settings.lambda_checkpoint_prefix = scoped_prefix(settings.lambda_checkpoint_prefix, identity)
    if len(settings.lambda_checkpoint_prefix) > 181:
        raise ValueError('Lambda checkpoint prefix is too long after organization scoping.')
    return settings


class OrganizationScope:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        if store.schema_updates:
            initialize_schema(store)
        self.bind()
        store.organization_scope = self
        store.organization_id = settings.moyai_organization_id

    def bind(self):
        identity = self.settings.moyai_organization_id
        with self.store.connect() as conn:
            conn.begin_write()
            row = conn.execute('SELECT organization_id FROM organization_scope WHERE id=1').fetchone()
            if row:
                if row['organization_id'] != identity:
                    raise DatabaseError('This database belongs to a different organization. Restore its pinned MOYAI_ORGANIZATION_ID or use a separate database.')
                return
            if not identity:
                return
            # Automatically changing infrastructure names underneath existing
            # workflows, checkpoints or credentials would strand a legacy
            # deployment. Fresh organization deployment setup is safe; legacy
            # adoption needs a separate, operator-reviewed migration.
            tables = conn.table_names()
            for table in ('runs', 'users', 'connections', 'automations', 'provider_secrets',
                          'memory_notes', 'skills', 'user_roles', 'enterprise_roles',
                          'scim_users', 'scim_groups', 'security_profiles'):
                if table in tables and conn.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone():
                    raise DatabaseError('This existing deployment has no organization pin. Create a fresh organization deployment; namespace migration is required before adopting an existing database.')
            conn.execute('INSERT INTO organization_scope(id,organization_id,created_at) VALUES(1,?,?)', (identity, now()))

    def metadata(self):
        return {'id': self.settings.moyai_organization_id,
                'deployment_mode': 'dedicated',
                'namespaces': {field: getattr(self.settings, field) for field in NAMESPACE_FIELDS}}


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS organization_scope (
        id INTEGER PRIMARY KEY CHECK(id=1),organization_id TEXT NOT NULL,created_at TEXT NOT NULL)''')
