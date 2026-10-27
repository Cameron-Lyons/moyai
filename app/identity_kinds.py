"""Account kinds and sign-in methods that identify one verified person.

Every individual check reads these constants, so a new organization sign-in
method cannot leave a privacy, permission or ambiguity check on an older
literal set. Shared password and local preview sign-ins and Slack accounting
identities are never individuals. Kinds name the users row that an enrollment
created; methods name the signed session. A person keeps their original kind
when a later method links to the same account.
"""

INDIVIDUAL_KINDS = frozenset({'google', 'cloudflare', 'oidc'})
INDIVIDUAL_METHODS = frozenset({'google', 'cloudflare', 'oidc'})
INDIVIDUAL_KINDS_SQL = '(' + ','.join(f"'{kind}'" for kind in sorted(INDIVIDUAL_KINDS)) + ')'
INDIVIDUAL_ID_PREFIXES = tuple(kind + ':' for kind in sorted(INDIVIDUAL_KINDS))
# Exact text: native read seams (product_connection_store.QUERIES) match it.
INDIVIDUAL_USERS_QUERY = 'SELECT id,email FROM users WHERE kind IN ' + INDIVIDUAL_KINDS_SQL
