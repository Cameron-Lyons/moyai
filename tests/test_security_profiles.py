"""Security profile policies, intersection laws and the revisioned canonical service.

Runs on SQLite and with --postgres-backend.
"""
import json
import random
import threading
from dataclasses import dataclass

import pytest
from app import security_profiles
from app.db import Store
from app.security_profiles import (
    STALE,
    UNRESTRICTED,
    CorruptPolicy,
    DefaultsUnavailable,
    InvalidPolicy,
    OrganizationPolicyUnavailable,
    ProfileInUse,
    ProfileNotFound,
    ProfilePolicy,
    ProfileUnavailable,
    SaveProfile,
    SecurityProfiles,
    StaleRevision,
    domain_allows,
    dump_policy,
    effective,
    intersect,
    load_policy,
    normalize_domain,
    policy_catalog,
    validated,
)
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError


@dataclass(frozen=True)
class Actor:
    id: str
    email: str


ADMIN = Actor('google:1', 'Admin@Example.com')


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def profiles(store):
    return SecurityProfiles(store)


def events(store):
    return [{**row, 'details': json.loads(row['details'])} for row in store.rows(
        'SELECT action,actor,resource_type,resource_id,details FROM governance_audit_events ORDER BY created_at,id')]


def body(name='Restricted', revision=0, enabled=True, **policy):
    return {'name': name, 'revision': revision, 'enabled': enabled, 'policy': policy}


# Policy validation


def test_domains_are_lowercase_sorted_deduplicated_and_reduced():
    policy = ProfilePolicy(network_domains=[' API.Example.com. ', 'api.example.com', 'example.com', '*.Example.com',
                                            'x.y.example.com', '*.b.example.com', 'other.org'])
    # '*.example.com' covers its apex and every subdomain depth, as Modal matches it.
    assert policy.network_domains == ('*.example.com', 'other.org')
    assert ProfilePolicy(network_domains=[]).network_domains == ()
    assert ProfilePolicy().network_domains is None


@pytest.mark.parametrize(('value', 'expected'), [
    ('straße.de', 'xn--strae-oqa.de'),  # IDNA 2003 would silently rewrite this to strasse.de.
    ('faß.de', 'xn--fa-hia.de'),
    ('βόλος.com', 'xn--nxasmm1c.com'),  # Final sigma is kept (IDNA 2003: xn--nxasmq6b.com).
    ('Bücher.Example', 'xn--bcher-kva.example'),
    ('*.Bücher.example', '*.xn--bcher-kva.example'),
    ('ＥＸＡＭＰＬＥ．ｃｏｍ', 'example.com'),  # UTS #46 maps full-width forms.
    ('xn--strae-oqa.de', 'xn--strae-oqa.de'),
    ('r3---sn-abc.googlevideo.com', 'r3---sn-abc.googlevideo.com'),  # Valid LDH even though IDNA2008 forbids '--'.
    ('a-b.example.co.uk', 'a-b.example.co.uk'),
])
def test_hostnames_use_idna2008_uts46_non_transitional_a_labels(value, expected):
    assert normalize_domain(value) == expected


DOMAIN_MESSAGES = {
    'Use DNS hostnames, not IP addresses.', 'Use hostnames without ports.',
    'Use hostnames without a scheme such as https://.', 'Use hostnames without paths.',
    'Use hostnames without user names.', 'Use valid DNS hostnames such as api.example.com.',
    'Use a full hostname such as api.example.com.', 'Use a wildcard under a domain, such as *.example.com.',
    'Use one *. prefix only, such as *.example.com.', 'Enter a hostname for each network domain.',
}


@pytest.mark.parametrize(('value', 'message'), [
    ('127.0.0.1', 'not IP addresses'), ('169.254.169.254', 'not IP addresses'), ('127.1', 'not IP addresses'),
    ('10.1', 'not IP addresses'), ('1.2.3', 'not IP addresses'), ('2130706433', 'not IP addresses'),
    ('2852039166', 'not IP addresses'), ('0177.0.0.1', 'not IP addresses'), ('0x7f.1', 'not IP addresses'),
    ('0x7f000001', 'not IP addresses'), ('example.123', 'not IP addresses'), ('１２７．０．０．１', 'not IP addresses'),
    ('*.10.0.0.1', 'not IP addresses'), ('::1', 'not IP addresses'), ('2001:db8::1', 'not IP addresses'),
    ('[2001:db8::1]', 'not IP addresses'), ('[::1]:443', 'not IP addresses'), ('fe80::1%eth0', 'not IP addresses'),
    ('::ffff:127.0.0.1', 'not IP addresses'),
    ('example.com:443', 'without ports'), ('*.example.com:8443', 'without ports'),
    ('https://example.com', 'without a scheme'), ('example.com/path', 'without paths'),
    ('example.com?q=1', 'without paths'), ('example.com#x', 'without paths'), ('user@example.com', 'user names'),
    ('a..example.com', 'valid DNS hostnames'), ('.example.com', 'valid DNS hostnames'),
    ('example.com..', 'valid DNS hostnames'), ('-a.example.com', 'valid DNS hostnames'),
    ('a-.example.com', 'valid DNS hostnames'), ('ex_ample.com', 'valid DNS hostnames'),
    ('exa mple.com', 'valid DNS hostnames'), ('a' * 64 + '.com', 'valid DNS hostnames'),
    ('.'.join(['a' * 63] * 4) + '.com', 'valid DNS hostnames'), ('a‍b.com', 'valid DNS hostnames'),
    ('xn---bbk.com', 'valid DNS hostnames'), ('xn--zz.com', 'valid DNS hostnames'),
    ('ex：443.com', 'valid DNS hostnames'), ('＊.example.com', 'valid DNS hostnames'),
    ('*', 'one *. prefix'), ('localhost', 'full hostname'), ('*.com', 'wildcard under a domain'),
    ('a.*.example.com', 'one *. prefix'), ('*.*.example.com', 'one *. prefix'), ('**.example.com', 'one *. prefix'),
    ('*example.com', 'one *. prefix'), ('', 'Enter a hostname'), ('   ', 'Enter a hostname'),
])
def test_invalid_domains_are_rejected_without_echoing_input(value, message):
    with pytest.raises(RequestValidationError) as caught:
        validated(SaveProfile, body(network_domains=[value]))
    [error] = caught.value.errors()
    assert message in error['msg'] and 'input' not in error
    assert error['loc'] == ('policy', 'network_domains')
    assert error['msg'] in DOMAIN_MESSAGES  # Fixed sentences only; the input is never echoed.


def test_domain_wildcards_follow_modal_matching():
    assert domain_allows(None, 'anything.test')
    assert not domain_allows((), 'example.com')
    allowlist = ProfilePolicy(network_domains=['*.example.com', 'api.other.org']).network_domains
    for host in ('example.com', 'a.example.com', 'a.b.example.com', 'api.other.org'):
        assert domain_allows(allowlist, host)
    for host in ('evilexample.com', 'other.org', 'x.api.other.org', 'example.com.evil.test'):
        assert not domain_allows(allowlist, host)


def test_domain_and_tool_counts_are_bounded_before_deduplication():
    assert len(ProfilePolicy(network_domains=[f'h{index}.example.org' for index in range(200)]).network_domains) == 200
    with pytest.raises(ValidationError):
        ProfilePolicy(network_domains=['example.org'] * 201)
    assert ProfilePolicy(tools=['read_file'] * 500).tools == ('read_file',)
    with pytest.raises(ValidationError):
        ProfilePolicy(tools=['read_file'] * 501)


@pytest.mark.parametrize('name', ['Bash', '1tool', 'read-file', 'read file', '', '_private', 'a' * 129, 'tool\x00'])
def test_tool_names_must_be_lowercase_identifiers(name):
    with pytest.raises(ValidationError):
        ProfilePolicy(tools=[name])


def test_tools_apps_and_git_access_are_canonical_and_closed():
    policy = ProfilePolicy(tools=[' write_file', 'a' * 128, 'read_file', 'read_file'],
                           connected_apps=['slack', 'github', 'slack'], git_access='read')
    assert policy.tools == ('a' * 128, 'read_file', 'write_file')
    assert policy.connected_apps == ('github', 'slack')
    assert ProfilePolicy(tools=[], connected_apps=[]).model_dump() == {
        'connected_apps': (), 'tools': (), 'git_access': 'write', 'network_domains': None}
    for invalid in ({'connected_apps': ['jira']}, {'git_access': 'admin'}, {'git_access': None},
                    {'tools': 'read_file'}, {'network_domains': 'example.com'}, {'unknown': True},
                    {'connected_apps': ['github'] * 17}, {'tools': [1]}):
        with pytest.raises(ValidationError):
            ProfilePolicy.model_validate(invalid)


@pytest.mark.parametrize('text', [
    'null', '[]', '0', 'false', '""', '{}', 'not json', None,
    '{"connected_apps":null,"tools":null,"git_access":"write"}',
    '{"connected_apps":null,"tools":null,"git_access":"write","network_domains":null,"extra":1}',
    '{"connected_apps":null,"tools":null,"git_access":"root","network_domains":null}',
    '{"connected_apps":null,"tools":null,"git_access":"write","network_domains":["127.0.0.1"]}',
])
def test_stored_policies_must_be_complete_valid_objects(text):
    with pytest.raises(InvalidPolicy):
        load_policy(text)  # type: ignore[arg-type]


def test_policy_json_round_trips_canonically():
    policy = ProfilePolicy(network_domains=['b.example', '*.a.example'], tools=['x'], git_access='none')
    text = dump_policy(policy)
    assert text == ('{"connected_apps":null,"git_access":"none","network_domains":["*.a.example","b.example"],'
                    '"tools":["x"]}')
    assert load_policy(text) == policy and hash(load_policy(text)) == hash(policy)
    assert dump_policy({'tools': ['x', 'x']}) == '{"connected_apps":null,"git_access":"write","network_domains":null,"tools":["x"]}'


# Intersection


@pytest.mark.parametrize(('first', 'second', 'expected'), [
    (['*.a.com'], ['x.a.com'], ['x.a.com']),
    (['*.a.com'], ['a.com'], ['a.com']),
    (['*.a.com'], ['*.x.a.com'], ['*.x.a.com']),
    (['*.a.com'], ['deep.x.a.com', 'evila.com', 'a.org'], ['deep.x.a.com']),
    (['*.a.com', 'b.com'], ['*.b.com', 'x.a.com'], ['b.com', 'x.a.com']),
    (['a.com'], ['x.a.com'], []),
    (['*.a.com'], ['*.b.com'], []),
    (['a.com'], [], []),
    (['a.com', '*.c.com'], None, ['*.c.com', 'a.com']),
])
def test_domain_intersection_is_wildcard_aware(first, second, expected):
    result = intersect({'network_domains': first}, {'network_domains': second})
    assert result.network_domains == tuple(expected)


def test_lists_narrow_git_takes_the_minimum_and_null_is_identity():
    result = intersect({'tools': ['a', 'b'], 'connected_apps': ['github', 'slack'], 'git_access': 'read'},
                       None, {'tools': ['b', 'c'], 'git_access': 'write'}, ProfilePolicy(connected_apps=['slack']))
    assert result == ProfilePolicy(tools=['b'], connected_apps=['slack'], git_access='read')
    assert intersect() == UNRESTRICTED == intersect(None, {}, UNRESTRICTED)
    assert intersect({'git_access': 'none'}, {'git_access': 'read'}).git_access == 'none'
    assert intersect({'tools': []}, {'tools': ['a']}).tools == ()
    assert effective({'tools': ['a', 'b']}, {'tools': ['b']}).tools == ('b',)
    assert effective(None, None) == UNRESTRICTED


@pytest.mark.parametrize('value', ['null', '[]', 0, False, '', ['tools'], 1.5])
def test_intersection_refuses_non_policy_values(value):
    # A corrupt falsy document must never read as an unrestricted policy.
    with pytest.raises(TypeError):
        intersect(value)


BASES = ('a.com', 'x.a.com', 'y.x.a.com', 'b.a.com', 'b.com', 'a.org', 'xn--bcher-kva.example')
ENTRIES = BASES + tuple('*.' + base for base in BASES)
HOSTS = BASES + tuple('z.' + base for base in BASES) + ('evila.com', 'q.y.x.a.com', 'com', 'a.net', 'a.com.org')
TOOLS = ('read_file', 'write_file', 'shell', 'create_pull_request', 'browser_open')


def random_policy(rng):
    def subset(values):
        return None if rng.random() < 0.3 else rng.sample(values, rng.randint(0, len(values)))
    return ProfilePolicy(network_domains=subset(ENTRIES), tools=subset(TOOLS),
                         connected_apps=subset(['github', 'linear', 'slack', 'notion']),
                         git_access=rng.choice(['write', 'read', 'none']))


def allows(policy, field, value):
    values = getattr(policy, field)
    return values is None or value in values


@pytest.mark.parametrize('seed', range(60))
def test_intersection_laws(seed):
    rng = random.Random(seed)
    first, second, third = (random_policy(rng) for _ in range(3))
    both = intersect(first, second)
    assert both == intersect(second, first)  # Commutative.
    assert intersect(first, first) == intersect(first) == first  # Idempotent on canonical policies.
    assert intersect(both, third) == intersect(first, intersect(second, third))  # Associative.
    assert ProfilePolicy.model_validate(both.model_dump()) == both  # Results stay canonical.
    assert load_policy(dump_policy(both)) == both
    for host in HOSTS:  # Never widens, and never narrows beyond what both allow.
        expected = domain_allows(first.network_domains, host) and domain_allows(second.network_domains, host)
        assert domain_allows(both.network_domains, host) is expected
    for tool in TOOLS:
        assert allows(both, 'tools', tool) is (allows(first, 'tools', tool) and allows(second, 'tools', tool))
    for app in ('github', 'linear', 'slack', 'notion'):
        assert allows(both, 'connected_apps', app) is (
            allows(first, 'connected_apps', app) and allows(second, 'connected_apps', app))
    levels = security_profiles.GIT_LEVELS
    assert levels[both.git_access] == min(levels[first.git_access], levels[second.git_access])


# Service


def test_create_update_and_revisions_record_metadata_only_audit_events(store, profiles):
    created = profiles.save(body(network_domains=['secret-host.example'], tools=['read_file']), ADMIN)
    assert created['revision'] == 1 and created['enabled'] is True and created['updated_by'] == 'admin@example.com'
    assert security_profiles.PROFILE_ID.fullmatch(created['id'])
    assert created['policy'] == {'connected_apps': None, 'tools': ['read_file'], 'git_access': 'write',
                                 'network_domains': ['secret-host.example']}
    assert profiles.get(created['id']) == created
    updated = profiles.save(body('Locked', revision=1, git_access='none'), ADMIN, profile_id=created['id'])
    assert updated['revision'] == 2 and updated['name'] == 'Locked' and updated['policy']['git_access'] == 'none'
    assert [(row['revision'], json.loads(row['policy'])['git_access']) for row in store.rows(
        'SELECT revision,policy FROM security_profile_revisions WHERE profile_id=? ORDER BY revision',
        (created['id'],))] == [(1, 'write'), (2, 'none')]
    assert events(store) == [
        {'action': 'security_profile.created', 'actor': 'admin@example.com', 'resource_type': 'security_profile',
         'resource_id': created['id'], 'details': {'name': 'Restricted', 'revision': 1, 'enabled': True}},
        {'action': 'security_profile.updated', 'actor': 'admin@example.com', 'resource_type': 'security_profile',
         'resource_id': created['id'], 'details': {'name': 'Locked', 'revision': 2, 'enabled': True}},
    ]
    assert 'secret-host' not in json.dumps(events(store))


def test_stale_unknown_and_unchanged_saves_write_nothing(store, profiles):
    created = profiles.save(body(tools=['read_file']), ADMIN)
    for revision in (0, 2):
        with pytest.raises(StaleRevision) as caught:
            profiles.save(body('Renamed', revision=revision), ADMIN, profile_id=created['id'])
        assert (caught.value.status_code, caught.value.detail) == (409, STALE)
    with pytest.raises(StaleRevision):
        profiles.save(body(revision=1), ADMIN)  # Creation is revision 0 only.
    with pytest.raises(ProfileNotFound) as missing:
        profiles.save(body(revision=1), ADMIN, profile_id='f' * 32)
    assert missing.value.status_code == 404
    with pytest.raises(ProfileNotFound):
        profiles.get('not-a-profile-id')
    # The same values in another spelling are unchanged: no revision, no event.
    same = profiles.save(body(revision=1, tools=['read_file', 'read_file']), ADMIN, profile_id=created['id'])
    assert same == created
    assert len(events(store)) == 1
    assert store.rows('SELECT COUNT(*) AS total FROM security_profile_revisions')[0]['total'] == 1


def test_profile_count_is_bounded(store, profiles, monkeypatch):
    monkeypatch.setattr(security_profiles, 'MAX_PROFILES', 1)
    profiles.save(body(), ADMIN)
    with pytest.raises(security_profiles.ProfileLimit):
        profiles.save(body('Second'), ADMIN)
    assert len(events(store)) == 1


def test_disable_is_revisioned_idempotent_and_blocked_for_defaults(store, profiles):
    default = profiles.save(body('Default'), ADMIN)
    mandatory = profiles.save(body('Mandatory'), ADMIN)
    spare = profiles.save(body('Spare'), ADMIN)
    profiles.save_defaults({'default_profile_id': default['id'], 'mandatory_profile_id': mandatory['id'],
                            'revision': 0}, ADMIN)
    before = len(events(store))
    for profile in (default, mandatory):
        with pytest.raises(ProfileInUse) as caught:
            profiles.disable(profile['id'], 1, ADMIN)
        assert caught.value.detail == 'This policy is an organization default. Change the defaults first.'
        with pytest.raises(ProfileInUse):
            profiles.save(body(profile['name'], revision=1, enabled=False), ADMIN, profile_id=profile['id'])
    with pytest.raises(StaleRevision):
        profiles.disable(spare['id'], 0, ADMIN)
    with pytest.raises(ProfileNotFound):
        profiles.disable('0' * 32, 1, ADMIN)
    assert len(events(store)) == before
    disabled = profiles.disable(spare['id'], 1, ADMIN)
    assert (disabled['enabled'], disabled['revision']) == (False, 2)
    assert profiles.disable(spare['id'], 2, ADMIN) == disabled  # Already disabled: no new revision.
    assert events(store)[-1]['action'] == 'security_profile.disabled'
    assert len(events(store)) == before + 1
    reenabled = profiles.save(body('Spare', revision=2), ADMIN, profile_id=spare['id'])
    assert (reenabled['enabled'], reenabled['revision']) == (True, 3)


def test_defaults_require_enabled_profiles_and_current_revision(store, profiles):
    assert profiles.defaults() == {'default_profile_id': '', 'mandatory_profile_id': '', 'revision': 0,
                                   'updated_at': None, 'updated_by': ''}
    first = profiles.save(body('First'), ADMIN)
    second = profiles.save(body('Second'), ADMIN)
    profiles.disable(second['id'], 1, ADMIN)
    for selection in ({'default_profile_id': 'a' * 32}, {'mandatory_profile_id': second['id']}):
        with pytest.raises(DefaultsUnavailable) as caught:
            profiles.save_defaults({**selection, 'revision': 0}, ADMIN)
        assert caught.value.detail == 'Choose an enabled security policy.'
    with pytest.raises(RequestValidationError):
        profiles.save_defaults({'default_profile_id': 'NOT-HEX', 'revision': 0}, ADMIN)
    before = len(events(store))
    saved = profiles.save_defaults({'default_profile_id': first['id'], 'mandatory_profile_id': first['id'],
                                    'revision': 0}, ADMIN)
    assert saved['revision'] == 1 and saved['updated_by'] == 'admin@example.com' and saved['updated_at']
    assert profiles.defaults() == saved
    with pytest.raises(StaleRevision):
        profiles.save_defaults({'revision': 0}, ADMIN)
    unchanged = profiles.save_defaults({'default_profile_id': first['id'], 'mandatory_profile_id': first['id'],
                                        'revision': 1}, ADMIN)
    assert unchanged == saved
    cleared = profiles.save_defaults({'revision': 1}, ADMIN)
    assert (cleared['default_profile_id'], cleared['mandatory_profile_id'], cleared['revision']) == ('', '', 2)
    assert [event['details'] for event in events(store)[before:]] == [
        {'default_profile_id': first['id'], 'mandatory_profile_id': first['id'], 'mandatory_profile_revision': 1,
         'revision': 1, 'previous_default_profile_id': '', 'previous_mandatory_profile_id': ''},
        {'default_profile_id': '', 'mandatory_profile_id': '', 'mandatory_profile_revision': 0,
         'revision': 2, 'previous_default_profile_id': first['id'], 'previous_mandatory_profile_id': first['id']},
    ]
    assert {event['action'] for event in events(store)[before:]} == {'security_defaults.updated'}


def test_catalogs_show_enabled_profiles_and_admin_listing_shows_all(store, profiles):
    zeta = profiles.save(body('zeta', network_domains=['*.example.com']), ADMIN)
    alpha = profiles.save(body('Alpha'), ADMIN)
    hidden = profiles.save(body('beta'), ADMIN)
    profiles.disable(hidden['id'], 1, ADMIN)
    profiles.save_defaults({'default_profile_id': zeta['id'], 'mandatory_profile_id': alpha['id'],
                            'revision': 0}, ADMIN)
    assert profiles.catalog() == {
        'profiles': [{'id': alpha['id'], 'name': 'Alpha', 'policy': alpha['policy']},
                     {'id': zeta['id'], 'name': 'zeta', 'policy': zeta['policy']}],
        'default_profile_id': zeta['id'], 'mandatory': {'id': alpha['id'], 'name': 'Alpha'}}
    listing = profiles.admin_listing(tools=['read_file', {'id': 'create_pull_request', 'label': 'Open a PR'},
                                            'Bad-Name', 'read_file', {'id': 'browser_open', 'group': 'Web'}])
    assert [profile['name'] for profile in listing['profiles']] == ['Alpha', 'beta', 'zeta']
    assert listing['profiles'][1]['enabled'] is False and listing['defaults']['revision'] == 1
    assert listing['catalog'] == {
        'connected_apps': [{'id': 'github', 'label': 'GitHub'}, {'id': 'linear', 'label': 'Linear'},
                           {'id': 'slack', 'label': 'Slack'}, {'id': 'notion', 'label': 'Notion'}],
        'tools': [{'id': 'create_pull_request', 'label': 'Open a PR', 'group': 'GitHub'},
                  {'id': 'browser_open', 'label': 'Browser open', 'group': 'Web'},
                  {'id': 'read_file', 'label': 'Read file', 'group': 'Workspace'}]}
    assert policy_catalog()['connected_apps'] == listing['catalog']['connected_apps']


def test_new_sessions_bind_the_selection_narrowed_by_the_mandatory_profile(store, profiles):
    assert profiles.resolve_for_new_session() == ('', 0, UNRESTRICTED)
    assert profiles.mandatory() is None
    default = profiles.save(body('Default', tools=['read_file', 'shell'], network_domains=['*.example.com']), ADMIN)
    chosen = profiles.save(body('Chosen', git_access='read'), ADMIN)
    mandatory = profiles.save(body('Floor', tools=['read_file'], connected_apps=['github'],
                                   network_domains=['api.example.com', 'other.org']), ADMIN)
    profiles.save_defaults({'default_profile_id': default['id'], 'revision': 0}, ADMIN)
    binding = profiles.resolve_for_new_session('')
    assert binding == (default['id'], 1, ProfilePolicy(tools=['read_file', 'shell'], network_domains=['*.example.com']))
    profiles.save_defaults({'default_profile_id': default['id'], 'mandatory_profile_id': mandatory['id'],
                            'revision': 1}, ADMIN)
    profile_id, revision, policy = profiles.resolve_for_new_session()
    assert (profile_id, revision) == (default['id'], 1)
    assert policy == ProfilePolicy(tools=['read_file'], connected_apps=['github'], network_domains=['api.example.com'])
    chosen_binding = profiles.resolve_for_new_session(chosen['id'])
    assert chosen_binding.profile_id == chosen['id'] and chosen_binding.policy == ProfilePolicy(
        tools=['read_file'], connected_apps=['github'], git_access='read',
        network_domains=['api.example.com', 'other.org'])
    floor = profiles.mandatory()
    assert floor == (mandatory['id'], 1, load_policy(dump_policy(ProfilePolicy.model_validate(mandatory['policy']))))
    # Loosening the mandatory profile later never widens a pinned binding.
    loosened = profiles.save(body('Floor', revision=1), ADMIN, profile_id=mandatory['id'])
    assert profiles.mandatory() == (mandatory['id'], loosened['revision'], UNRESTRICTED)
    assert effective(chosen_binding.policy, profiles.mandatory().policy) == chosen_binding.policy


def test_unavailable_selections_fail_closed(store, profiles):
    disabled = profiles.save(body('Old'), ADMIN)
    profiles.disable(disabled['id'], 1, ADMIN)
    for requested in (disabled['id'], 'e' * 32, 'not-hex', 'E' * 32):
        with pytest.raises(ProfileUnavailable) as caught:
            profiles.resolve_for_new_session(requested)
        assert caught.value.detail == 'This security policy is no longer available. Choose another policy.'
    with pytest.raises(TypeError):
        profiles.resolve_for_new_session(None)  # type: ignore[arg-type]
    default = profiles.save(body('Default'), ADMIN)
    profiles.save_defaults({'default_profile_id': default['id'], 'mandatory_profile_id': default['id'],
                            'revision': 0}, ADMIN)
    # Out-of-band edits that bypass the service must not fall back to unrestricted.
    store.execute('UPDATE security_profiles SET enabled=0 WHERE id=?', (default['id'],))
    with pytest.raises(OrganizationPolicyUnavailable):
        profiles.resolve_for_new_session()
    assert profiles.mandatory().profile_id == default['id']  # A disabled mandatory profile still restricts.
    store.execute("UPDATE security_profile_defaults SET mandatory_profile_id=? WHERE id=1", ('d' * 32,))
    with pytest.raises(OrganizationPolicyUnavailable):
        profiles.mandatory()
    store.execute("UPDATE security_profile_defaults SET default_profile_id='',mandatory_profile_id='' WHERE id=1")
    for text in ('null', '{}', '[]'):
        store.execute('UPDATE security_profiles SET enabled=1,policy=? WHERE id=?', (text, default['id']))
        with pytest.raises(CorruptPolicy):
            profiles.resolve_for_new_session(default['id'])
        with pytest.raises(CorruptPolicy):
            profiles.get(default['id'])


def test_failed_audit_rolls_back_the_change(store, profiles, monkeypatch):
    created = profiles.save(body(), ADMIN)

    def fail(*_args, **_kwargs):
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(security_profiles, 'record_event_in', fail)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        profiles.save(body('Second'), ADMIN)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        profiles.save(body('Renamed', revision=1), ADMIN, profile_id=created['id'])
    with pytest.raises(RuntimeError, match='audit unavailable'):
        profiles.save_defaults({'default_profile_id': created['id'], 'revision': 0}, ADMIN)
    assert store.rows('SELECT name,revision FROM security_profiles') == [{'name': 'Restricted', 'revision': 1}]
    assert store.rows('SELECT COUNT(*) AS total FROM security_profile_revisions')[0]['total'] == 1
    assert store.rows('SELECT COUNT(*) AS total FROM security_profile_defaults')[0]['total'] == 0
    assert len(events(store)) == 1


def test_actor_and_body_validation_happen_before_any_write(store, profiles):
    service = Actor('cloudflare:abc', '')
    assert profiles.save(body(), service)['updated_by'] == 'cloudflare:abc'
    for actor in (object(), Actor('', ''), Actor('x' * 513, ''), 'admin@example.com'):
        with pytest.raises(TypeError):
            profiles.save(body('Nobody'), actor)
    with pytest.raises(RequestValidationError) as caught:
        profiles.save({'name': 'x', 'policy': {'network_domains': ['10.0.0.1']}, 'surprise': 1}, ADMIN)
    errors = caught.value.errors()
    assert {error['type'] for error in errors} == {'network_domain', 'extra_forbidden'}
    assert all('input' not in error and '10.0.0.1' not in error['msg'] for error in errors)
    for invalid in ({'name': ''}, {'name': 'a' * 81}, {'name': 'bad\nname'}, {'name': 'x', 'enabled': 'yes'},
                    {'name': 'x', 'revision': True}, {'name': 'x', 'revision': -1}):
        with pytest.raises(RequestValidationError):
            profiles.save(invalid, ADMIN)
    with pytest.raises(TypeError):
        profiles.disable(profiles.catalog()['profiles'][0]['id'], '1', ADMIN)  # type: ignore[arg-type]
    assert len(events(store)) == 1


def test_concurrent_default_edits_serialize_on_the_writer_lock(store, profiles):
    first = profiles.save(body('First'), ADMIN)
    barrier, results = threading.Barrier(4), []

    def edit():
        barrier.wait()
        try:
            results.append(profiles.save_defaults({'default_profile_id': first['id'], 'revision': 0}, ADMIN))
        except StaleRevision as error:
            results.append(error)
    threads = [threading.Thread(target=edit) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, StaleRevision) for result in results) == 3
    assert [event['action'] for event in events(store)].count('security_defaults.updated') == 1


def test_writers_recheck_security_manage_inside_the_transaction(store, tmp_path):
    from app.config import Settings
    from app.enterprise_roles import GovernanceActor, GovernanceForbidden, RoleAssignment, RoleCreate
    from app.user_roles import UserRoles
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    roles = UserRoles(store, settings)
    profiles = SecurityProfiles(store, roles=roles.enterprise)
    owner = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin', kind='individual')
    officer = GovernanceActor(id='google:sec', email='Sec@Example.com', kind='individual')

    def profile_events():
        return [event for event in events(store) if event['resource_type'].startswith('security_')]
    with pytest.raises(GovernanceForbidden):
        profiles.save(body(), officer)
    roles.enterprise.create(RoleCreate(id='security', name='Security', permissions=['security.manage']), owner)
    roles.enterprise.assign(RoleAssignment(email='sec@example.com', role_id='security', revision=0), owner)
    created = profiles.save(body(), officer)
    assert created['updated_by'] == 'sec@example.com'
    settings.password_login_enabled, settings.workspace_password = True, 'test-only-shared-admin-password'
    shared = GovernanceActor(id='shared:password:admin', builtin_role='admin')
    defaults = profiles.save_defaults({'default_profile_id': created['id'], 'revision': 0}, shared)
    assert defaults['updated_by'] == 'Shared password admin'
    # Revoked after the route checked it: every writer refuses and records nothing.
    roles.enterprise.assign(RoleAssignment(email='sec@example.com', role_id='member', revision=1), owner)
    before = profile_events()
    for write in (lambda: profiles.save(body('Other'), officer),
                  lambda: profiles.save(body('Renamed', revision=1), officer, profile_id=created['id']),
                  lambda: profiles.disable(created['id'], 1, officer),
                  lambda: profiles.save_defaults({'revision': 1}, officer)):
        with pytest.raises(GovernanceForbidden):
            write()
    assert profile_events() == before and profiles.get(created['id'])['name'] == 'Restricted'
