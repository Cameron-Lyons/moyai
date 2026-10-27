"""The GitHub branch, stack and pull-request tool names are declared once in app.permissions."""
from app.permissions import (
    GITHUB_PUBLICATION_TOOLS,
    GITHUB_READ_TOOLS,
    GITHUB_WRITE_TOOLS,
    TOOL_PERMISSIONS,
    connector_tool,
    tool_permission,
)


def test_github_tool_lists_are_disjoint_and_drive_both_permissions_and_routing():
    tools = GITHUB_READ_TOOLS + GITHUB_WRITE_TOOLS
    # dict.fromkeys would let a later list silently overwrite a name listed twice.
    assert len(set(tools)) == len(tools)
    assert GITHUB_PUBLICATION_TOOLS == frozenset(tools)
    for name in tools:
        expected = 'connections.read' if name in GITHUB_READ_TOOLS else 'connections.write'
        assert TOOL_PERMISSIONS[name] == expected, name
        assert connector_tool(name) == ('github', name)
        assert tool_permission(f'github_0a1b2c3d_{name}') == expected, name
    # Registered under its prefixed name, so it routes as `checkout` rather than itself.
    assert 'github_checkout' not in GITHUB_PUBLICATION_TOOLS
    assert TOOL_PERMISSIONS['github_checkout'] == 'connections.read'
    assert connector_tool('github_checkout') == ('github', 'checkout')
