"""
`mcp_cage.guards` — Empirical CWE Wire-Level Argument Guards (`StandardArgGuards`),
Workspace Jail Confinement (`is_safe_workspace_path`), and Outbound SSRF / DNS
Entropy Validation (`validate_outbound_network_target`).
"""

from __future__ import annotations

from mcp_cage_core import (
    CLOUD_METADATA_HOSTS,
    DANGEROUS_URI_SCHEMES,
    DNS_CMD_HOST_RE,
    LOCAL_DIR_ONLY_KEYS,
    LOOPBACK_HOSTNAMES,
    POSIX_CMD_SUBST_RE,
    PROTECTED_DOTFILE_WRITE_PATTERNS,
    StandardArgGuards,
    URL_IN_TEXT_RE,
    WORKSPACE_PATH_KEYS,
    cli_flag_injection_guard,
    endpoint_repoint_guard,
    is_safe_workspace_path,
    iterative_fixed_point_unquote,
    make_endpoint_repoint_guard,
    make_ssrf_and_dns_guard,
    make_workspace_path_guard,
    mqtt_topic_wildcard_guard,
    path_command_substitution_guard,
    sql_safety_guard,
    url_path_segment_guard,
    validate_outbound_network_target,
)

__all__ = [
    "CLOUD_METADATA_HOSTS",
    "DANGEROUS_URI_SCHEMES",
    "DNS_CMD_HOST_RE",
    "LOCAL_DIR_ONLY_KEYS",
    "LOOPBACK_HOSTNAMES",
    "POSIX_CMD_SUBST_RE",
    "PROTECTED_DOTFILE_WRITE_PATTERNS",
    "StandardArgGuards",
    "URL_IN_TEXT_RE",
    "WORKSPACE_PATH_KEYS",
    "cli_flag_injection_guard",
    "endpoint_repoint_guard",
    "is_safe_workspace_path",
    "iterative_fixed_point_unquote",
    "make_endpoint_repoint_guard",
    "make_ssrf_and_dns_guard",
    "make_workspace_path_guard",
    "mqtt_topic_wildcard_guard",
    "path_command_substitution_guard",
    "sql_safety_guard",
    "url_path_segment_guard",
    "validate_outbound_network_target",
]
