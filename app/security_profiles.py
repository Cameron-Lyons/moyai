"""Session security profiles and the organization default and mandatory profile.

A policy narrows what a session may use: connected_apps (managed connectors),
tools (tool names offered to the agent), git_access, network_domains (a
hostname allowlist), repositories (permanent GitHub repository IDs) and models
(the workspace's model choice IDs, matched exactly). For each list, null is
unrestricted, [] allows nothing and a list allows only its entries. intersect()
never widens: lists meet by intersection, git access takes the minimum and null
is the identity.

Repository limits name permanent IDs, never owner/name text, and apply to public
repositories too. Stored documents have two shapes: a policy without repository
or model limits keeps the four-key document earlier releases wrote and read,
byte for byte, and any such limit writes all six keys. Earlier releases therefore
refuse (fail closed on) exactly the documents that use the new limits.

network_domains is validated, stored and intersected, but no installed provider
enforces egress, so ProductGovernance.require_provider refuses every non-null
value at admission. Domains are exact hostnames or '*.' plus a hostname, with
Modal's TLS SNI semantics on port 443: '*.example.com' covers example.com and
every subdomain depth, and an exact entry covers only itself. Intersection and
redundancy removal follow those semantics exactly. Hostnames are lowercase
A-labels. Unicode input is converted with UTS #46 non-transitional (IDNA2008)
mapping, the form clients send in SNI, never the stdlib IDNA 2003 codec, which
rewrites 'straße.de' to 'strasse.de'. IP literals in any spelling, ports,
schemes, paths, user names, single-label names and single-label wildcards such
as '*.com' are rejected.

Profiles are revisioned and never deleted. Disabling one keeps its revisions,
so native session bindings (moyai_product_session_policies) stay auditable. This
module keeps no legacy run lineage. A new session binds its profile intersected
with the mandatory profile of that moment, so a later loosening of the mandatory
profile never widens an existing session. Execution intersects the binding with
the current mandatory profile again (effective()).

Writers take the canonical exclusive writer lock and record exactly one
governance audit event in the same transaction (profile id, name, revision and
enabled state; never policy bodies). Routes enforce security.manage, and
SecurityProfiles(store, roles=...) rechecks it inside each writer. Actors are
GovernanceActor values (or anything enterprise_roles.actor_label accepts); the
audit label is the same text the other governance writers record: the email,
the shared sign-in name, or the id.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from typing import Annotated, Literal, NamedTuple
from uuid import uuid4

import idna
from fastapi import HTTPException
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic_core import PydanticCustomError

from .enterprise_roles import STALE, actor_label, validated
from .governance_audit import initialize_schema as initialize_audit
from .governance_audit import record_event_in, timestamp
from .permissions import GITHUB_PUBLICATION_TOOLS, TOOL_PERMISSIONS
from .schema_initializers import initialize_security_profiles as initialize_schema

CONNECTED_APPS = {'github': 'GitHub', 'linear': 'Linear', 'slack': 'Slack', 'notion': 'Notion'}
GIT_LEVELS = {'none': 0, 'read': 1, 'write': 2}
LEGACY_POLICY_FIELDS = frozenset({'connected_apps', 'tools', 'git_access', 'network_domains'})
SCOPE_FIELDS = frozenset({'repositories', 'models'})
POLICY_FIELDS = LEGACY_POLICY_FIELDS | SCOPE_FIELDS
PROFILE_ID = re.compile(r'[0-9a-f]{32}')
PROFILE_ID_PATTERN = r'^([0-9a-f]{32})?$'
TOOL_NAME = re.compile(r'[a-z][a-z0-9_]{0,127}')
# The 120-character limit matches the automation definition's model field.
MODEL_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,119}')
MAX_DOMAINS = 200
MAX_TOOLS = 500
MAX_REPOSITORIES = 1000
MAX_MODELS = 64
MAX_PROFILES = 500

_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
# WHATWG URL parsing and inet_aton read a name whose last label is a number as
# IPv4 (127.1, 2130706433, 0x7f.1, 0177.0.0.1). No top-level domain is numeric.
_NUMERIC_LABEL = re.compile(r'[0-9]+|0x[0-9a-f]*')
_INVALID_HOST = 'Use valid DNS hostnames such as api.example.com.'
_IP_HOST = 'Use DNS hostnames, not IP addresses.'


class ProfileError(HTTPException):
    """A refused security-profile operation. The detail is one fixed sentence."""
    status = 409
    message = 'This security policy change was refused.'

    def __init__(self, detail: str | None = None):
        super().__init__(self.status, detail or self.message)


class StaleRevision(ProfileError):
    message = STALE


class ProfileNotFound(ProfileError):
    status, message = 404, 'Security policy not found.'


class ProfileInUse(ProfileError):
    message = 'This policy is an organization default. Change the defaults first.'


class DefaultsUnavailable(ProfileError):
    message = 'Choose an enabled security policy.'


class ProfileUnavailable(ProfileError):
    message = 'This security policy is no longer available. Choose another policy.'


class OrganizationPolicyUnavailable(ProfileError):
    message = 'An organization security policy is unavailable. Ask an administrator to update the defaults.'


class ProfileLimit(ProfileError):
    message = f'At most {MAX_PROFILES} security policies are supported. Edit or re-enable an existing policy.'


class CorruptPolicy(ProfileError):
    message = 'A saved security policy is invalid. Restore it from a backup.'


class PolicyFieldsOmitted(ProfileError):
    message = 'This policy has repository or model limits this editor did not send. Reload and try again.'


class UnknownPolicyEntry(ProfileError):
    status, message = 422, 'Choose repositories and models available to this workspace.'


class InvalidPolicy(ValueError):
    """Stored policy text is not a complete, valid policy document."""


def _domain_error(message):
    return PydanticCustomError('network_domain', message)


def _ip_literal(value):
    if '[' in value or ']' in value or value.count(':') > 1:
        return True  # Bracketed or bare IPv6, with or without a port or zone.
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _a_labels(name):
    if not name.isascii():
        try:
            name = idna.encode(name, uts46=True, std3_rules=True, transitional=False).decode('ascii')
        except (UnicodeError, ValueError):
            raise _domain_error(_INVALID_HOST) from None
    name = name.lower()
    labels = name.split('.')
    # Plain LDH labels are valid DNS names even where IDNA2008 forbids '--' in
    # positions 3-4 (for example r3---sn-x.googlevideo.com); A-labels must be
    # canonical Punycode so a fake 'xn--' spelling cannot alias another name.
    if len(name) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        raise _domain_error(_INVALID_HOST)
    for label in labels:
        if label.startswith('xn--'):
            try:
                idna.ulabel(label)
            except (UnicodeError, ValueError):
                raise _domain_error(_INVALID_HOST) from None
    return name


def normalize_domain(value: str) -> str:
    """Return the canonical allowlist entry for one hostname or '*.' wildcard.

    Raises PydanticCustomError (a ValueError) with a fixed sentence that never
    echoes the input.
    """
    value = value.strip()
    if not value:
        raise _domain_error('Enter a hostname for each network domain.')
    if len(value) > 255:
        raise _domain_error(_INVALID_HOST)
    if '://' in value:
        raise _domain_error('Use hostnames without a scheme such as https://.')
    if any(character in value for character in '/?#\\'):
        raise _domain_error('Use hostnames without paths.')
    if '@' in value:
        raise _domain_error('Use hostnames without user names.')
    if _ip_literal(value):
        raise _domain_error(_IP_HOST)
    if ':' in value:
        raise _domain_error('Use hostnames without ports.')
    wildcard = value.startswith('*.')
    base = value[2:] if wildcard else value
    if '*' in base:
        raise _domain_error('Use one *. prefix only, such as *.example.com.')
    host = _a_labels(base.removesuffix('.'))  # Drop one FQDN root dot.
    if _ip_literal(host) or _NUMERIC_LABEL.fullmatch(host.rpartition('.')[2]):
        raise _domain_error(_IP_HOST)
    if '.' not in host:
        raise _domain_error('Use a wildcard under a domain, such as *.example.com.' if wildcard
                            else 'Use a full hostname such as api.example.com.')
    return '*.' + host if wildcard else host


def _base(entry):
    return entry.removeprefix('*.')


def _under(host, base):
    return host == base or host.endswith('.' + base)


def _covers(wildcard, entry):
    """Whether a distinct wildcard matches every host the entry matches."""
    return wildcard != entry and wildcard.startswith('*.') and _under(_base(entry), _base(wildcard))


def reduce_domains(entries: Iterable[str]) -> tuple[str, ...]:
    """Sorted, deduplicated entries without any entry another wildcard covers."""
    entries = set(entries)
    wildcards = [entry for entry in entries if entry.startswith('*.')]
    return tuple(sorted(entry for entry in entries if not any(_covers(other, entry) for other in wildcards)))


def _meet(first, second):
    """The single entry matching exactly the hosts both entries match, or None."""
    if first.startswith('*.') and second.startswith('*.'):
        if _under(_base(first), _base(second)):
            return first
        return second if _under(_base(second), _base(first)) else None
    if first.startswith('*.'):
        first, second = second, first
    if second.startswith('*.'):
        return first if _under(first, _base(second)) else None
    return first if first == second else None


def intersect_domains(first: Iterable[str], second: Iterable[str]) -> tuple[str, ...]:
    """Normalized entries matching exactly the hosts both normalized allowlists match."""
    second = tuple(second)
    return reduce_domains(entry for one in first for other in second if (entry := _meet(one, other)))


def _no_controls(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PydanticCustomError('name', 'Use a name without control characters.')
    return value


AppName = Literal['github', 'linear', 'slack', 'notion']
# Strict: a bool, float or numeric string is not a repository ID.
RepositoryId = Annotated[int, Field(gt=0, le=2**53 - 1, strict=True)]


class ProfilePolicy(BaseModel):
    """One policy: null is unrestricted, [] allows nothing, a list allows only its entries.

    Values are canonical after validation (sorted, deduplicated tuples; domains
    normalized and reduced), so equal policies compare and serialize equally.
    """
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True, frozen=True)
    connected_apps: Annotated[tuple[AppName, ...], Field(max_length=16)] | None = None
    tools: Annotated[tuple[str, ...], Field(max_length=MAX_TOOLS)] | None = None
    git_access: Literal['write', 'read', 'none'] = 'write'
    network_domains: Annotated[tuple[str, ...], Field(max_length=MAX_DOMAINS)] | None = None
    repositories: Annotated[tuple[RepositoryId, ...], Field(max_length=MAX_REPOSITORIES)] | None = None
    models: Annotated[tuple[str, ...], Field(max_length=MAX_MODELS)] | None = None

    @field_validator('connected_apps', 'repositories')
    @classmethod
    def _sorted(cls, values):
        return None if values is None else tuple(sorted(set(values)))

    @field_validator('tools')
    @classmethod
    def _tools(cls, values):
        if values is None:
            return None
        if not all(TOOL_NAME.fullmatch(value) for value in values):
            raise PydanticCustomError('tool_name', 'Use tool names of lowercase letters, digits and underscores.')
        return tuple(sorted(set(values)))

    @field_validator('network_domains')
    @classmethod
    def _domains(cls, values):
        return None if values is None else reduce_domains(normalize_domain(value) for value in values)

    @field_validator('models')
    @classmethod
    def _models(cls, values):
        if values is None:
            return None
        if not all(MODEL_ID.fullmatch(value) for value in values):
            raise PydanticCustomError('model_id', 'Use model IDs from the workspace model list.')
        return tuple(sorted(set(values)))


def _policy(value):
    if isinstance(value, ProfilePolicy):
        return value
    if isinstance(value, Mapping):
        return ProfilePolicy.model_validate(value)
    raise TypeError('Security policies must be ProfilePolicy values, mappings or None.')


def intersect(*policies: ProfilePolicy | Mapping | None) -> ProfilePolicy:
    """The narrowest policy every argument allows; None arguments are unrestricted.

    Commutative, associative and idempotent. Mappings are validated (partial
    mappings take unrestricted defaults); other values raise TypeError, so a
    corrupt falsy document can never pass as an unrestricted policy.
    """
    apps = tools = domains = repositories = models = None
    git = 'write'

    def meet(current, values):
        return values if current is None else tuple(sorted(set(current) & set(values)))

    for value in policies:
        if value is None:
            continue
        policy = _policy(value)
        if policy.connected_apps is not None:
            apps = meet(apps, policy.connected_apps)
        if policy.tools is not None:
            tools = meet(tools, policy.tools)
        if policy.network_domains is not None:
            domains = policy.network_domains if domains is None else intersect_domains(domains, policy.network_domains)
        if policy.repositories is not None:
            repositories = meet(repositories, policy.repositories)
        if policy.models is not None:
            models = meet(models, policy.models)
        if GIT_LEVELS[policy.git_access] < GIT_LEVELS[git]:
            git = policy.git_access
    # Every component is already canonical, so skip re-normalizing domains.
    # model_construct defaults an omitted field to None (unrestricted), so every
    # field is passed explicitly.
    return ProfilePolicy.model_construct(connected_apps=apps, tools=tools, git_access=git, network_domains=domains,
                                         repositories=repositories, models=models)


def effective(session_policy: ProfilePolicy | Mapping | None,
              mandatory_policy: ProfilePolicy | Mapping | None) -> ProfilePolicy:
    """Execution policy: a session's bound policy narrowed by the current mandatory one."""
    return intersect(session_policy, mandatory_policy)


def dump_policy(policy: ProfilePolicy | Mapping) -> str:
    """Canonical compact JSON for storage, bindings and comparisons.

    Without repository or model limits this is the four-key document earlier
    releases wrote; either limit writes all six keys.
    """
    document = _policy(policy).model_dump(mode='json')
    if document['repositories'] is None and document['models'] is None:
        del document['repositories'], document['models']
    return json.dumps(document, sort_keys=True, separators=(',', ':'))


def load_policy(text: str) -> ProfilePolicy:
    """Parse stored policy JSON: an object holding exactly the four legacy fields or all six.

    A four-key document has no repository or model limits. Raises InvalidPolicy
    otherwise, including for 'null', '[]', '{}' and partial objects, so a
    truncated or foreign document never reads as unrestricted.
    """
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        raise InvalidPolicy('The security policy is not valid JSON.') from None
    if not isinstance(document, dict) or frozenset(document) not in (LEGACY_POLICY_FIELDS, POLICY_FIELDS):
        raise InvalidPolicy('The security policy must hold exactly its four original fields or all six.')
    try:
        return ProfilePolicy.model_validate(document)
    except ValidationError:
        raise InvalidPolicy('The security policy is invalid.') from None


def _stored(text):
    try:
        return load_policy(text)
    except InvalidPolicy:
        raise CorruptPolicy() from None


class SaveProfile(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: Annotated[str, Field(min_length=1, max_length=80), AfterValidator(_no_controls)]
    enabled: bool = Field(default=True, strict=True)
    policy: ProfilePolicy = Field(default_factory=ProfilePolicy)
    revision: int = Field(default=0, ge=0, strict=True)


class ProfileDefaults(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    default_profile_id: str = Field(default='', pattern=PROFILE_ID_PATTERN)
    mandatory_profile_id: str = Field(default='', pattern=PROFILE_ID_PATTERN)
    revision: int = Field(default=0, ge=0, strict=True)


class SessionBinding(NamedTuple):
    """What a new session pins: the selected profile ('' and 0 for none) and its policy."""
    profile_id: str
    revision: int
    policy: ProfilePolicy


class MandatoryProfile(NamedTuple):
    profile_id: str
    revision: int
    policy: ProfilePolicy


def _tool_label(name):
    return name.replace('_', ' ').capitalize()


_TOOL_GROUPS = (
    ('credentials_', 'Credentials'), ('automation_', 'Automations'), ('browser_', 'Browser'),
    ('github_', 'GitHub'), ('linear_', 'Linear'), ('notion_', 'Notion'), ('slack_', 'Slack'),
)
_NAMED_GROUPS = {**dict.fromkeys(GITHUB_PUBLICATION_TOOLS, 'GitHub'), 'load_capability': 'Skills'}


def _tool_group(name):
    if name in _NAMED_GROUPS:
        return _NAMED_GROUPS[name]
    if 'memory' in name:
        return 'Memory'
    return next((group for prefix, group in _TOOL_GROUPS if name.startswith(prefix)), 'Workspace')


def policy_catalog(repositories: Iterable[Mapping] = (), models: Iterable[Mapping] = ()) -> dict:
    """Choices for the policy editor: connected apps, the app.permissions.TOOL_PERMISSIONS names,
    and the caller's repository and model choices ({'id', 'label'} each, in display order).

    Names a policy cannot hold are skipped. Tools are ordered by group, then id.
    """
    entries = [{'id': name, 'label': _tool_label(name), 'group': _tool_group(name)}
               for name in TOOL_PERMISSIONS if TOOL_NAME.fullmatch(name)]
    return {'connected_apps': [{'id': key, 'label': label} for key, label in CONNECTED_APPS.items()],
            'tools': sorted(entries, key=lambda entry: (entry['group'], entry['id'])),
            'repositories': [{'id': entry['id'], 'label': entry['label']} for entry in repositories],
            'models': [{'id': entry['id'], 'label': entry['label']} for entry in models]}


_COLUMNS = 'id,name,enabled,revision,policy,updated_by,updated_at'


def _view(row, policy=None):
    policy = _stored(row['policy']) if policy is None else policy
    return {'id': row['id'], 'name': row['name'], 'enabled': bool(row['enabled']), 'revision': row['revision'],
            'policy': policy.model_dump(mode='json'), 'updated_at': row['updated_at'],
            'updated_by': row['updated_by']}


def _ordered(rows):
    # Python ordering: PostgreSQL collations would otherwise differ from SQLite.
    return sorted(rows, key=lambda row: (row['name'].casefold(), row['name'], row['id']))


class SecurityProfiles:
    """Synchronous canonical service; async callers run it in a worker thread.

    roles: an EnterpriseRoles over the same store. When given, every write
    re-resolves the actor inside its writer transaction and requires
    security.manage, as enterprise_roles does, so a demotion or SCIM
    deactivation that commits after the route's check still refuses the write;
    the label is then the resolved authority's (the same text actor_label gives).
    """

    def __init__(self, store, *, roles=None):
        self.store, self.roles = store, roles
        if store.schema_updates:
            initialize_schema(store)
            initialize_audit(store)

    def _authorized_in(self, conn, actor, label: str) -> str:
        return label if self.roles is None else self.roles.authorize_in(conn, actor, 'security.manage').label

    @staticmethod
    def _row_in(conn, profile_id):
        if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
            return None
        return conn.execute(f'SELECT {_COLUMNS} FROM security_profiles WHERE id=?', (profile_id,)).fetchone()

    @staticmethod
    def defaults_in(conn) -> dict:
        row = conn.execute('''SELECT revision,default_profile_id,mandatory_profile_id,updated_by,updated_at
            FROM security_profile_defaults WHERE id=1''').fetchone()
        if row is None:
            return {'default_profile_id': '', 'mandatory_profile_id': '', 'revision': 0,
                    'updated_at': None, 'updated_by': ''}
        return {'default_profile_id': row['default_profile_id'], 'mandatory_profile_id': row['mandatory_profile_id'],
                'revision': row['revision'], 'updated_at': row['updated_at'], 'updated_by': row['updated_by']}

    def _selected_in(self, conn):
        defaults = self.defaults_in(conn)
        return {defaults['default_profile_id'], defaults['mandatory_profile_id']} - {''}

    def catalog(self) -> dict:
        """Enabled profiles a person may choose for a new session, plus the defaults."""
        with self.store.connect() as conn:
            conn.begin_read()
            defaults = self.defaults_in(conn)
            rows = [dict(row) for row in conn.execute(f'SELECT {_COLUMNS} FROM security_profiles WHERE enabled=1')]
            mandatory = self._row_in(conn, defaults['mandatory_profile_id'])
        return {'profiles': [{'id': row['id'], 'name': row['name'],
                              'policy': _stored(row['policy']).model_dump(mode='json')} for row in _ordered(rows)],
                'default_profile_id': defaults['default_profile_id'],
                'mandatory': {'id': mandatory['id'], 'name': mandatory['name']} if mandatory else None}

    def admin_listing(self, repositories: Iterable[Mapping] = (), models: Iterable[Mapping] = ()) -> dict:
        """Every profile including disabled ones, the defaults and the editor catalog (see policy_catalog)."""
        with self.store.connect() as conn:
            conn.begin_read()
            defaults = self.defaults_in(conn)
            rows = [dict(row) for row in conn.execute(f'SELECT {_COLUMNS} FROM security_profiles')]
        return {'profiles': [_view(row) for row in _ordered(rows)], 'defaults': defaults,
                'catalog': policy_catalog(repositories, models)}

    @staticmethod
    def _revise_in(conn, row, *, name, enabled, policy, label, action):
        revision, stamp, text = row['revision'] + 1, timestamp(), dump_policy(policy)
        if conn.execute('''UPDATE security_profiles SET name=?,enabled=?,revision=?,policy=?,updated_by=?,updated_at=?
                WHERE id=? AND revision=?''', (name, enabled, revision, text, label, stamp, row['id'],
                                               row['revision'])).rowcount != 1:
            raise StaleRevision()
        conn.execute('INSERT INTO security_profile_revisions(profile_id,revision,policy,created_by,created_at) '
                     'VALUES(?,?,?,?,?)', (row['id'], revision, text, label, stamp))
        record_event_in(conn, action, label, 'security_profile', row['id'],
                        {'name': name, 'revision': revision, 'enabled': enabled})
        return {'id': row['id'], 'name': name, 'enabled': enabled, 'revision': revision,
                'policy': policy.model_dump(mode='json'), 'updated_at': stamp, 'updated_by': label}

    @staticmethod
    def _require_known(policy, current, known_repositories, known_models):
        """Refuse newly added repositories or models outside the supplied choices (None skips the check).

        Entries the profile already holds stay valid after they leave a catalog.
        """
        for name, known in (('repositories', known_repositories), ('models', known_models)):
            added = set(getattr(policy, name) or ()) - set(getattr(current, name) or ())
            if known is not None and not added <= set(known):
                raise UnknownPolicyEntry()

    def save(self, body: SaveProfile | Mapping, actor, *, profile_id: str = '',
             known_repositories: Iterable[int] | None = None, known_models: Iterable[str] | None = None) -> dict:
        """Create (no profile_id; revision 0) or update a profile at its current revision.

        An unchanged save returns the profile without a new revision or event.
        A profile selected as the default or mandatory profile cannot be disabled.
        An update must send repositories and models whenever the stored policy
        limits them; an editor or script that predates them would otherwise
        clear the limits. Newly added repositories and models must belong to
        known_repositories and known_models when those are given.
        """
        body, label = validated(SaveProfile, body), actor_label(actor)
        with self.store.connect() as conn:
            conn.begin_write()
            label = self._authorized_in(conn, actor, label)
            if profile_id:
                row = self._row_in(conn, profile_id)
                if row is None:
                    raise ProfileNotFound()
                if row['revision'] != body.revision:
                    raise StaleRevision()
                if not body.enabled and profile_id in self._selected_in(conn):
                    raise ProfileInUse()
                current = _stored(row['policy'])
                if any(getattr(current, name) is not None for name in SCOPE_FIELDS - body.policy.model_fields_set):
                    raise PolicyFieldsOmitted()
                self._require_known(body.policy, current, known_repositories, known_models)
                if (row['name'], bool(row['enabled']), current) == (body.name, body.enabled, body.policy):
                    return _view(row, current)
                return self._revise_in(conn, row, name=body.name, enabled=body.enabled, policy=body.policy,
                                       label=label, action='security_profile.updated')
            if body.revision != 0:
                raise StaleRevision()
            self._require_known(body.policy, ProfilePolicy(), known_repositories, known_models)
            if conn.execute('SELECT COUNT(*) AS total FROM security_profiles').fetchone()['total'] >= MAX_PROFILES:
                raise ProfileLimit()
            identity, stamp, text = uuid4().hex, timestamp(), dump_policy(body.policy)
            conn.execute(f'INSERT INTO security_profiles({_COLUMNS}) VALUES(?,?,?,?,?,?,?)',
                         (identity, body.name, body.enabled, 1, text, label, stamp))
            conn.execute('INSERT INTO security_profile_revisions(profile_id,revision,policy,created_by,created_at) '
                         'VALUES(?,?,?,?,?)', (identity, 1, text, label, stamp))
            record_event_in(conn, 'security_profile.created', label, 'security_profile', identity,
                            {'name': body.name, 'revision': 1, 'enabled': body.enabled})
            return {'id': identity, 'name': body.name, 'enabled': body.enabled, 'revision': 1,
                    'policy': body.policy.model_dump(mode='json'), 'updated_at': stamp, 'updated_by': label}

    def disable(self, profile_id: str, revision: int, actor) -> dict:
        """Disable a profile at its current revision; disabling a disabled one is a no-op."""
        if type(revision) is not int:
            raise TypeError('Profile revisions are integers.')
        label = actor_label(actor)
        with self.store.connect() as conn:
            conn.begin_write()
            label = self._authorized_in(conn, actor, label)
            row = self._row_in(conn, profile_id)
            if row is None:
                raise ProfileNotFound()
            if row['revision'] != revision:
                raise StaleRevision()
            if profile_id in self._selected_in(conn):
                raise ProfileInUse()
            policy = _stored(row['policy'])
            if not row['enabled']:
                return _view(row, policy)
            return self._revise_in(conn, row, name=row['name'], enabled=False, policy=policy, label=label,
                                   action='security_profile.disabled')

    def save_defaults(self, body: ProfileDefaults | Mapping, actor) -> dict:
        """Select the organization default and mandatory profiles ('' clears either).

        Both must name enabled profiles. An unchanged selection returns the
        current defaults without a new revision or event.
        """
        body, label = validated(ProfileDefaults, body), actor_label(actor)
        with self.store.connect() as conn:
            conn.begin_write()
            label = self._authorized_in(conn, actor, label)
            current = self.defaults_in(conn)
            if current['revision'] != body.revision:
                raise StaleRevision()
            rows = {identity: self._row_in(conn, identity)
                    for identity in (body.default_profile_id, body.mandatory_profile_id) if identity}
            if any(row is None or not row['enabled'] for row in rows.values()):
                raise DefaultsUnavailable()
            selection = (body.default_profile_id, body.mandatory_profile_id)
            if selection == (current['default_profile_id'], current['mandatory_profile_id']):
                return current
            revision, stamp = body.revision + 1, timestamp()
            conn.execute('''INSERT INTO security_profile_defaults
                (id,revision,default_profile_id,mandatory_profile_id,updated_by,updated_at) VALUES(1,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,default_profile_id=excluded.default_profile_id,
                mandatory_profile_id=excluded.mandatory_profile_id,updated_by=excluded.updated_by,
                updated_at=excluded.updated_at''', (revision, *selection, label, stamp))
            mandatory = rows.get(body.mandatory_profile_id)
            record_event_in(conn, 'security_defaults.updated', label, 'security_defaults', 'organization', {
                'default_profile_id': body.default_profile_id, 'mandatory_profile_id': body.mandatory_profile_id,
                'mandatory_profile_revision': mandatory['revision'] if mandatory else 0, 'revision': revision,
                'previous_default_profile_id': current['default_profile_id'],
                'previous_mandatory_profile_id': current['mandatory_profile_id']})
            return {'default_profile_id': body.default_profile_id, 'mandatory_profile_id': body.mandatory_profile_id,
                    'revision': revision, 'updated_at': stamp, 'updated_by': label}

    def mandatory_in(self, conn, defaults: dict | None = None) -> MandatoryProfile | None:
        """The current mandatory profile, or None. A dangling selection fails closed."""
        if defaults is None:
            # One round trip for governed transactions that only need the floor.
            row = conn.execute('''SELECT d.mandatory_profile_id AS mandatory_id, p.id AS profile_id,
                    p.revision AS revision, p.policy AS policy
                FROM security_profile_defaults d LEFT JOIN security_profiles p ON p.id = d.mandatory_profile_id
                WHERE d.id=1''').fetchone()
            if row is None or not row['mandatory_id']:
                return None
            identity = row['mandatory_id']
            if row['profile_id'] is None or not PROFILE_ID.fullmatch(identity):
                raise OrganizationPolicyUnavailable()
            return MandatoryProfile(identity, row['revision'], _stored(row['policy']))
        identity = defaults['mandatory_profile_id']
        if not identity:
            return None
        row = self._row_in(conn, identity)
        if row is None:
            raise OrganizationPolicyUnavailable()
        # Applied even if disabled out of band: the selection still restricts.
        return MandatoryProfile(identity, row['revision'], _stored(row['policy']))

    def resolve_for_new_session_in(self, conn, requested_id: str = '') -> SessionBinding:
        """Resolve a new session's binding in the caller's canonical snapshot.

        '' selects the organization default, and no default binds no profile
        ('', 0). A requested profile that is missing, malformed or disabled
        raises ProfileUnavailable; a dangling organization selection raises
        OrganizationPolicyUnavailable. The bound policy already includes the
        current mandatory profile, so loosening it later never widens a session.
        """
        if not isinstance(requested_id, str):
            raise TypeError('Requested security profile ids are text.')
        defaults = self.defaults_in(conn)
        identity = requested_id or defaults['default_profile_id']
        selected = None
        if identity:
            selected = self._row_in(conn, identity)
            if selected is None or not selected['enabled']:
                raise ProfileUnavailable() if requested_id else OrganizationPolicyUnavailable()
        mandatory = self.mandatory_in(conn, defaults)
        policy = intersect(_stored(selected['policy']) if selected else None, mandatory.policy if mandatory else None)
        return SessionBinding(identity if selected else '', selected['revision'] if selected else 0, policy)
