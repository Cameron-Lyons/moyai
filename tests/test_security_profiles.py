import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from modal.exception import AlreadyExistsError
from pydantic import ValidationError

from app.db import Store
from app.security_profiles import SecurityProfiles, ProfilePolicy, SaveProfile, intersect
from app.sandboxes.substrate import SubstrateProvider, egress_host_allowed
from app.sandboxes.proto import ateapi_pb2 as pb


@pytest.fixture
def profiles(tmp_path):
    store = Store(tmp_path)
    return SecurityProfiles(store, SimpleNamespace(public_url='https://broker.example.com'))


def profile(profiles, identity, **policy):
    return profiles.save(identity, SaveProfile(name=identity, policy=ProfilePolicy(**policy)), 'admin')


def session(profiles, **fields):
    run = profiles.store.create_run('Test policy', '', 'modal', ['github', 'slack'], chat_enabled=True)
    if fields:
        profiles.store.execute('UPDATE runs SET ' + ','.join(key + '=?' for key in fields) + ' WHERE id=?', (*fields.values(), run['id']))
    return profiles.store.run(run['id'])


def test_revision_pin_floor_and_descendant_cannot_expand(profiles):
    parent_profile = profile(profiles, 'parent', connected_apps=['github'], git_access='read')
    profile(profiles, 'broad')
    parent = profiles.bind_session(session(profiles), 'parent')
    profiles.save('parent', {'name': 'parent', 'revision': parent_profile['revision'], 'policy': {}}, 'admin')
    assert profiles.effective(parent)['git_access'] == 'read'
    assert parent['security_profile_revision'] == 1
    child = profiles.bind_session(session(profiles, parent_run_id=parent['id']), 'broad')
    assert profiles.allowed_tool(child, 'github_checkout', 'github')
    assert not profiles.allowed_tool(child, 'github_create_pull_request', 'github', True)
    assert not profiles.allowed_tool(child, 'slack_send', 'slack', True)
    profile(profiles, 'floor', tools=['github_checkout'])
    profiles.save_defaults({'floor_profile_id': 'floor'})
    assert not profiles.allowed_tool(child, 'github_pull_request', 'github')
    assert profiles.allowed_tool(child, 'github_checkout', 'github')
    revisions = profiles.store.rows('SELECT * FROM security_profile_revisions WHERE profile_id=? ORDER BY revision', ('parent',))
    assert len(revisions) == 2 and json.loads(revisions[0]['policy'])['git_access'] == 'read'


def test_default_is_pinned_and_selection_disabling_keeps_snapshot(profiles):
    profile(profiles, 'default', connected_apps=[])
    profiles.save_defaults({'default_profile_id': 'default'})
    first = profiles.bind_session(session(profiles))
    profiles.save_defaults({'revision': 1})
    profiles.delete('default')
    assert profiles.effective(first)['connected_apps'] == []
    with pytest.raises(HTTPException, match='disabled'):
        profiles.binding('default')
    assert profiles.bind_session(first)['security_policy'] == first['security_policy']


def test_restricted_provider_is_rejected_before_launch_and_restores_pin(profiles):
    profile(profiles, 'restricted', network_domains=['api.example.com'])
    for provider in ('modal', 'lambda'):
        with pytest.raises(HTTPException) as error:
            profiles.binding('restricted', provider=provider)
        assert error.value.status_code == 409
    run = profiles.bind_session(session(profiles, sandbox_provider='substrate'), 'restricted')
    assert profiles.network_hosts(run) == ['api.example.com', 'broker.example.com']
    profiles.store.update_run(run['id'], snapshot_id='substrate:space:template:checkpoint')
    assert profiles.network_hosts(profiles.bind_session(profiles.store.run(run['id']))) == ['api.example.com', 'broker.example.com']
    with pytest.raises(HTTPException):
        profiles.require_url(run, 'https://forbidden.example.com/data')
    profiles.require_url(run, 'https://api.example.com/data')


def test_restricted_session_rejects_global_ceiling_that_blocks_broker(profiles):
    profile(profiles, 'restricted', network_domains=['api.example.com'])
    run = profiles.bind_session(session(profiles, sandbox_provider='substrate'), 'restricted')
    profiles.settings.substrate_egress_hosts = 'api.example.com'
    with pytest.raises(HTTPException) as error:
        profiles.network_hosts(run)
    assert error.value.status_code == 409 and 'broker hostname' in error.value.detail


def test_floor_network_changes_require_releasing_existing_machines(profiles):
    profile(profiles, 'restricted', network_domains=[])
    run = session(profiles, sandbox_id='sb-live')
    with pytest.raises(HTTPException) as error:
        profiles.save_defaults({'floor_profile_id': 'restricted'})
    assert error.value.status_code == 409
    profiles.store.update_run(run['id'], sandbox_id='')
    profiles.save_defaults({'floor_profile_id': 'restricted'})
    assert profiles.effective(run)['network_domains'] == []


def test_policy_rejects_urls_ips_wildcards_and_unknown_apps():
    for host in ('https://github.com', '192.0.2.1', '*.example.com', 'bad..example.com', 'good.example.com:443'):
        with pytest.raises(ValidationError):
            ProfilePolicy(network_domains=[host])
    with pytest.raises(ValidationError):
        ProfilePolicy(connected_apps=['unknown'])
    assert ProfilePolicy(network_domains=['API.Example.COM.']).network_domains == ['api.example.com']
    assert intersect({'network_domains': ['a.example', 'b.example']}, {'network_domains': ['b.example']})['network_domains'] == ['b.example']


def test_policy_lineage_missing_or_corrupt_is_fail_closed(profiles):
    run = session(profiles, security_policy='invalid')
    with pytest.raises(HTTPException):
        profiles.effective(run)
    profiles.store.execute("UPDATE runs SET security_policy='{}',parent_run_id='missing' WHERE id=?", (run['id'],))
    with pytest.raises(HTTPException):
        profiles.effective(run)


def test_side_chat_inherits_original_session_security(profiles):
    profile(profiles, 'restricted', connected_apps=[], git_access='none')
    parent = profiles.bind_session(session(profiles), 'restricted')
    child = profiles.bind_session(session(profiles, side_chat_of=parent['id']))
    assert not profiles.allowed_tool(child, 'github_checkout', 'github')


def test_native_global_host_ceiling_is_not_loosened_by_nested_wildcard():
    assert egress_host_allowed('api.example.com', '*.example.com')
    assert not egress_host_allowed('nested.api.example.com', '*.example.com')
    assert not egress_host_allowed('example.com', '*.example.com')


def test_existing_substrate_policy_is_replaced_before_resume():
    settings = SimpleNamespace(substrate_egress_hosts='*')
    provider = SubstrateProvider(settings)
    provider.security_egress_hosts = ['api.example.com', 'broker.example.com']
    existing = pb.EgressPolicy(metadata=pb.ResourceMetadata(atespace='space', name='default', uid='uid', version=8))
    provider.rpc = AsyncMock(side_effect=[AlreadyExistsError('exists'), existing, existing, None])
    sandbox = SimpleNamespace(ref={'atespace': 'space', 'name': 'actor'}, request=AsyncMock())
    asyncio.run(provider.initialize(sandbox, timeout=120, apt_packages=()))
    calls = provider.rpc.call_args_list
    assert [call.args[0] for call in calls] == ['CreateActorEgressPolicy', 'GetActorEgressPolicy', 'UpdateActorEgressPolicy', 'ResumeActor']
    replaced = calls[2].args[1]['egress_policy']
    assert replaced['metadata']['version'] == 8
    assert replaced['rules'][0]['http']['hostnames'] == ['api.example.com', 'broker.example.com']
    assert replaced['rules'][1]['tls_passthrough']['hostnames'] == ['api.example.com', 'broker.example.com']


def test_substrate_policy_update_failure_never_resumes_or_activates():
    provider = SubstrateProvider(SimpleNamespace(substrate_egress_hosts='*'))
    provider.security_egress_hosts = []
    existing = pb.EgressPolicy(metadata=pb.ResourceMetadata(atespace='space', name='default', uid='uid', version=8))
    provider.rpc = AsyncMock(side_effect=[AlreadyExistsError('exists'), existing, RuntimeError('policy failed')])
    sandbox = SimpleNamespace(ref={'atespace': 'space', 'name': 'actor'}, request=AsyncMock())
    with pytest.raises(RuntimeError, match='policy failed'):
        asyncio.run(provider.initialize(sandbox, timeout=120, apt_packages=()))
    assert [call.args[0] for call in provider.rpc.call_args_list] == ['CreateActorEgressPolicy', 'GetActorEgressPolicy', 'UpdateActorEgressPolicy']
    assert provider.rpc.call_args_list[2].args[1]['egress_policy']['rules'] == []
    sandbox.request.assert_not_called()


def test_connector_enforces_policy_even_when_tool_invoked_directly(profiles):
    from app.connectors import Connectors
    from app.connector_errors import ConnectorError
    from app.config import Settings
    connectors = Connectors(profiles.store, SimpleNamespace(), Settings(_env_file=None))
    profiles.store.execute("INSERT INTO connections(provider,encrypted,label,updated_at) VALUES('linear','unused','Test','now')")
    profile(profiles, 'disabled-apps', connected_apps=[])
    run = profiles.bind_session(session(profiles), 'disabled-apps')
    assert connectors.allowed('linear_search')
    assert not connectors.allowed('linear_search', run)
    connectors.request = AsyncMock()
    with pytest.raises(ConnectorError):
        asyncio.run(connectors.call('linear_search', {'query': 'ticket'}, run=run))
    connectors.request.assert_not_called()


def test_read_only_git_policy_prevents_direct_github_publish(profiles):
    from app.connectors import Connectors
    from app.config import Settings
    connectors = Connectors(profiles.store, SimpleNamespace(), Settings(_env_file=None))
    profile(profiles, 'git-read', git_access='read')
    run = profiles.bind_session(session(profiles), 'git-read')
    connectors.github.installation_token = AsyncMock()
    with pytest.raises(HTTPException) as error:
        asyncio.run(connectors.github.call(run, 'github_create_pull_request', {}))
    assert error.value.status_code == 403
    connectors.github.installation_token.assert_not_called()
