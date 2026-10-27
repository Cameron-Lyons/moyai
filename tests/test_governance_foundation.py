"""Revision 23 upgrades the governance branch's older storage without data loss."""
from app.db import Store
from app.schema_migrations import initialize_components


def test_governance_upgrade_preserves_old_rows_and_mandatory_ceiling(tmp_path):
    store = Store(tmp_path)
    try:
        with store.connect() as conn:
            conn.executescript("""
                CREATE TABLE scim_tokens(id TEXT PRIMARY KEY,label TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,
                    prefix TEXT NOT NULL,created_at TEXT NOT NULL,revoked_at TEXT NOT NULL DEFAULT '');
                CREATE TABLE scim_users(id TEXT PRIMARY KEY,external_id TEXT NOT NULL DEFAULT '',user_name TEXT NOT NULL,
                    profile TEXT NOT NULL,active INTEGER NOT NULL,deleted_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL);
                CREATE TABLE security_profile_defaults(id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,
                    default_profile_id TEXT NOT NULL DEFAULT '',floor_profile_id TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL,updated_at TEXT NOT NULL);
                CREATE TABLE governance_audit_events(id TEXT PRIMARY KEY,action TEXT NOT NULL,actor TEXT NOT NULL,
                    resource_type TEXT NOT NULL,resource_id TEXT NOT NULL,created_at TEXT NOT NULL);
                INSERT INTO scim_tokens VALUES('token','Directory','hash','prefix','now','');
                INSERT INTO scim_users VALUES('inactive','','worker@example.com','{}',0,'','now','now',2);
                INSERT INTO scim_users VALUES('active','','active@example.com','{}',1,'','now','now',1);
                INSERT INTO security_profile_defaults VALUES(1,3,'default','ceiling','owner','now');
                INSERT INTO governance_audit_events VALUES('event','security_profile.updated','owner','security_profile','profile','now');
            """)
        initialize_components(store)
        assert store.rows('SELECT user_name,access_epoch FROM scim_users ORDER BY id') == [
            {'user_name': 'active@example.com', 'access_epoch': 0},
            {'user_name': 'worker@example.com', 'access_epoch': 1}]
        assert store.rows('SELECT mandatory_profile_id,revision FROM security_profile_defaults') == [
            {'mandatory_profile_id': 'ceiling', 'revision': 3}]
        assert store.rows('SELECT token_hash,created_by,last_used_at FROM scim_tokens') == [
            {'token_hash': 'hash', 'created_by': '', 'last_used_at': ''}]
        assert store.rows('SELECT id,details FROM governance_audit_events') == [{'id': 'event', 'details': '{}'}]
        # Reapplying must neither restore an obsolete floor nor revive grants.
        store.execute("UPDATE security_profile_defaults SET mandatory_profile_id='updated'")
        initialize_components(store)
        assert store.rows('SELECT mandatory_profile_id FROM security_profile_defaults') == [{'mandatory_profile_id': 'updated'}]
        assert store.rows("SELECT access_epoch FROM scim_users WHERE id='inactive'") == [{'access_epoch': 1}]
    finally:
        store.close()
