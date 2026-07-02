#!/usr/bin/env python3
"""
CrowdStrike Falcon — Hosts & Endpoints Asset Inventory
=======================================================
Pulls a full inventory of all host and endpoint assets from Falcon using
every available API surface this key has access to:

  - Hosts           : managed devices, hidden devices, login history,
                      network address history, online state
  - Discover        : unmanaged/discovered hosts, accounts, applications,
                      logins (Shadow IT / asset discovery)
  - HostGroup       : host groups and group membership
  - ZeroTrustAssessment : ZTA scores per device
  - SensorUpdatePolicy  : sensor update policy membership
  - PreventionPolicy    : prevention policy membership
  - DeviceControlPolicies : USB / device control policy membership
  - ResponsePolicies    : response policy membership
  - FirewallPolicies    : firewall policy membership
  - SensorDownload      : available sensor versions + CCID
  - InstallationTokens  : provisioning tokens
  - SpotlightVulnerabilities : CVE exposure per host
  - SpotlightEvaluationLogic : Spotlight rule evaluation
  - DeviceContent       : content state per device

Output: JSON file (default: falcon_hosts_inventory_<timestamp>.json)

Usage:
    python3 hosts_inventory.py
    python3 hosts_inventory.py --output my_hosts.json
    python3 hosts_inventory.py --filter "platform_name:'Windows'"
    python3 hosts_inventory.py --section hosts,discover_hosts,discover_apps
    python3 hosts_inventory.py --login-history --network-history

Environment variables required:
    FALCON_CLIENT_ID
    FALCON_CLIENT_SECRET
    FALCON_CLOUD   (optional, default us-1)
"""
import os
import sys
import json
import argparse
import traceback
from datetime import datetime, timezone
from typing import Any

try:
    from falconpy import (
        OAuth2,
        Hosts,
        Discover,
        HostGroup,
        ZeroTrustAssessment,
        SensorUpdatePolicy,
        PreventionPolicy,
        DeviceControlPolicies,
        ResponsePolicies,
        FirewallPolicies,
        SensorDownload,
        InstallationTokens,
        SpotlightVulnerabilities,
        SpotlightEvaluationLogic,
        DeviceContent,
        KubernetesProtection,
        CloudSecurityAssets,
    )
except ImportError as exc:
    raise SystemExit(
        "FalconPy is required.  Install: pip install crowdstrike-falconpy"
    ) from exc


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------

def _paginate_combined(method, *, filter_str: str = "", limit: int = 200) -> list:
    """Paginate combined endpoints that return resources[] directly."""
    results = []
    offset = 0
    while True:
        kwargs: dict = {"limit": limit, "offset": offset}
        if filter_str:
            kwargs["filter"] = filter_str
        resp = method(**kwargs)
        if resp["status_code"] != 200:
            _log_errors(resp)
            break
        page = resp["body"].get("resources") or []
        results.extend(page)
        total = (resp["body"].get("meta") or {}).get("pagination", {}).get("total", 0)
        offset += len(page)
        if not page or offset >= total:
            break
    return results


def _paginate_query(query_method, *, filter_str: str = "", limit: int = 500,
                    max_offset: int = 0, extra_kwargs: dict = None) -> list:
    """Paginate query endpoints that return lists of IDs.

    max_offset: if > 0, stop paginating once offset reaches this value (e.g. Discover caps at 10000).
    """
    ids = []
    offset = 0
    while True:
        if max_offset and offset >= max_offset:
            break
        # respect per-API ceiling: don't let offset + limit exceed max_offset
        actual_limit = min(limit, max_offset - offset) if max_offset else limit
        kwargs: dict = {"limit": actual_limit, "offset": offset}
        if filter_str:
            kwargs["filter"] = filter_str
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        resp = query_method(**kwargs)
        if resp["status_code"] != 200:
            _log_errors(resp)
            break
        page = resp["body"].get("resources") or []
        ids.extend(page)
        total = (resp["body"].get("meta") or {}).get("pagination", {}).get("total", 0)
        offset += len(page)
        if not page or offset >= total:
            break
    return ids


def _fetch_details(get_method, ids: list, *, batch_size: int = 100) -> list:
    """Fetch full detail records for a list of IDs in batches."""
    results = []
    for i in range(0, len(ids), batch_size):
        chunk = ids[i : i + batch_size]
        resp = get_method(ids=chunk)
        if resp["status_code"] != 200:
            _log_errors(resp)
            continue
        results.extend(resp["body"].get("resources") or [])
    return results


def _safe_call(label: str, method, **kwargs) -> Any:
    """Call a single API method; return resources or raw body on success."""
    try:
        resp = method(**kwargs)
    except Exception as exc:  # noqa: BLE001
        print(f"  [EXCEPTION] {label}: {exc}")
        return None
    if resp["status_code"] not in (200, 201):
        _log_errors(resp, label=label)
        return None
    return resp["body"].get("resources", resp["body"])


def _log_errors(resp: dict, label: str = "") -> None:
    code = resp.get("status_code")
    errors = (resp.get("body") or {}).get("errors") or []
    for e in errors:
        print(f"  [API ERROR {code}] {label}: {e.get('code')} – {e.get('message')}")
    if not errors:
        print(f"  [HTTP {code}] {label}: non-200 response")


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

def _scroll_hosts(h: Hosts, filter_str: str, limit: int = 5000) -> list:
    """Use the scroll endpoint for token-based pagination (no integer offset)."""
    ids: list = []
    offset: str = ""          # empty string = first page
    while True:
        kwargs: dict = {"limit": limit}
        if filter_str:
            kwargs["filter"] = filter_str
        if offset:
            kwargs["offset"] = offset
        resp = h.query_devices_by_filter_scroll(**kwargs)
        if resp["status_code"] != 200:
            _log_errors(resp)
            break
        page = resp["body"].get("resources") or []
        ids.extend(page)
        # next offset is a string token in meta.pagination.offset
        offset = (resp["body"].get("meta") or {}).get("pagination", {}).get("offset", "")
        if not page or not offset:
            break
    return ids


# Mobile devices (Android, iOS) are excluded from all host collection.
_EXCLUDE_MOBILE = "product_type_desc:!'Mobile'"


def _apply_filter(base: str, extra: str = "") -> str:
    """Combine a base FQL filter with an optional user-provided filter."""
    parts = [p for p in (base, extra) if p]
    return "+".join(parts)


def collect_hosts(h: Hosts, filter_str: str) -> list:
    """All managed devices — full details. Mobile devices are excluded."""
    print("  → managed hosts (scroll + details) …")
    ids = _scroll_hosts(h, _apply_filter(_EXCLUDE_MOBILE, filter_str))
    if not ids:
        return []
    print(f"    {len(ids):,} device IDs found, fetching details …")
    return _fetch_details(h.get_device_details, ids)


def collect_hidden_hosts(h: Hosts) -> list:
    """Hidden / reduced functionality mode devices. Mobile devices are excluded."""
    print("  → hidden devices …")
    results: list = []
    offset: str = ""
    while True:
        kwargs: dict = {"limit": 100, "filter": _EXCLUDE_MOBILE}
        if offset:
            kwargs["offset"] = offset
        resp = h.query_hidden_devices_combined(**kwargs)
        if resp["status_code"] != 200:
            _log_errors(resp, "query_hidden_devices_combined")
            break
        page = resp["body"].get("resources") or []
        results.extend(page)
        offset = (resp["body"].get("meta") or {}).get("pagination", {}).get("offset", "")
        if not page or not offset:
            break
    return results


# Cloud / K8s provider values that indicate a cloud-hosted endpoint
_CLOUD_PROVIDERS = {
    "AWS_EC2_V2", "AWS_EC2", "AWS_EKS_FARGATE", "AWS_ECS_FARGATE",
    "AZURE", "AZURE_CONTAINER_APPS",
    "GCP",
}


def collect_cloud_hosts(h: Hosts, filter_str: str,
                        already_fetched: list = None) -> list:
    """Managed hosts running in a cloud provider (AWS, Azure, GCP, etc.)."""
    if already_fetched is not None:
        hosts = [d for d in already_fetched if d.get("service_provider") in _CLOUD_PROVIDERS]
        print(f"  → cloud hosts (in-memory filter): {len(hosts):,}")
        return hosts
    print("  → cloud hosts (API query) …")
    fql = "service_provider:!''"
    if filter_str:
        fql = f"{fql}+{filter_str}"
    ids = _scroll_hosts(h, fql)
    if not ids:
        return []
    print(f"    {len(ids):,} cloud host IDs, fetching details …")
    return _fetch_details(h.get_device_details, ids)


def collect_kubernetes_hosts(h: Hosts, filter_str: str,
                              already_fetched: list = None) -> list:
    """Managed hosts running inside a Kubernetes pod."""
    if already_fetched is not None:
        hosts = [d for d in already_fetched if d.get("pod_namespace")]
        print(f"  → kubernetes hosts (in-memory filter): {len(hosts):,}")
        return hosts
    print("  → kubernetes hosts (API query) …")
    fql = "pod_namespace:!''"
    if filter_str:
        fql = f"{fql}+{filter_str}"
    ids = _scroll_hosts(h, fql)
    if not ids:
        return []
    print(f"    {len(ids):,} kubernetes host IDs, fetching details …")
    return _fetch_details(h.get_device_details, ids)


def _summarize_cloud_hosts(hosts: list) -> dict:
    from collections import Counter
    if not hosts:
        return {"total": 0}
    providers  = Counter(h.get("service_provider", "Unknown") for h in hosts)
    accounts   = Counter(h.get("service_provider_account_id", "Unknown") for h in hosts)
    zones      = Counter(h.get("zone_group", "Unknown") for h in hosts)
    platforms  = Counter(h.get("platform_name", "Unknown") for h in hosts)
    return {
        "total":              len(hosts),
        "by_provider":        dict(providers.most_common()),
        "by_account":         dict(accounts.most_common()),
        "by_zone":            dict(zones.most_common()),
        "by_platform":        dict(platforms.most_common()),
    }


def _summarize_kubernetes_hosts(hosts: list) -> dict:
    from collections import Counter
    if not hosts:
        return {"total": 0}
    namespaces    = Counter(h.get("pod_namespace", "Unknown") for h in hosts)
    providers     = Counter(h.get("service_provider", "Unknown") for h in hosts)
    svc_accounts  = Counter(h.get("pod_service_account_name", "Unknown") for h in hosts)
    return {
        "total":                  len(hosts),
        "by_namespace":           dict(namespaces.most_common()),
        "by_provider":            dict(providers.most_common()),
        "by_service_account":     dict(svc_accounts.most_common()),
    }


def collect_online_state(h: Hosts, device_ids: list) -> list:
    """Online/offline state for all managed devices (batches of 100)."""
    if not device_ids:
        return []
    print(f"  → online state for {len(device_ids):,} devices …")
    results = []
    for i in range(0, len(device_ids), 100):
        chunk = device_ids[i : i + 100]
        resp = _safe_call("online_state", h.get_online_state, ids=chunk)
        if resp:
            results.extend(resp if isinstance(resp, list) else [resp])
    return results


def collect_login_history(h: Hosts, device_ids: list) -> list:
    """Recent interactive login sessions (max 10 devices per call)."""
    if not device_ids:
        return []
    print(f"  → login history for {min(len(device_ids), 100):,} devices (sample) …")
    results = []
    sample = device_ids[:100]  # cap at 100 for reasonable run time
    for i in range(0, len(sample), 10):
        chunk = sample[i : i + 10]
        resp = _safe_call("login_history", h.query_device_login_history_v2, ids=chunk)
        if resp:
            results.extend(resp if isinstance(resp, list) else [resp])
    return results


def collect_network_history(h: Hosts, device_ids: list) -> list:
    """IP / MAC address history per device."""
    if not device_ids:
        return []
    print(f"  → network address history for {min(len(device_ids), 500):,} devices (sample) …")
    results = []
    sample = device_ids[:500]  # cap to keep runtime reasonable
    for i in range(0, len(sample), 100):
        chunk = sample[i : i + 100]
        resp = _safe_call("network_history", h.query_network_address_history, ids=chunk)
        if resp:
            results.extend(resp if isinstance(resp, list) else [resp])
    return results


# ---------------------------------------------------------------------------
# Discover (Shadow IT / unmanaged asset discovery)
# ---------------------------------------------------------------------------

def collect_discover_hosts(d: Discover, filter_str: str) -> list:
    """Discovered (unmanaged) hosts."""
    print("  → Discover: hosts …")
    ids = _paginate_query(d.query_hosts, filter_str=filter_str, limit=100)
    if not ids:
        return []
    print(f"    {len(ids):,} discovered host IDs, fetching details …")
    return _fetch_details(d.get_hosts, ids)


def collect_discover_apps(d: Discover, filter_str: str) -> list:
    """Discovered applications (installed software across all hosts)."""
    print("  → Discover: applications …")
    ids = _paginate_query(d.query_applications, filter_str=filter_str, limit=100, max_offset=9900)
    if not ids:
        return []
    print(f"    {len(ids):,} application IDs, fetching details …")
    return _fetch_details(d.get_applications, ids)


def collect_discover_accounts(d: Discover, filter_str: str) -> list:
    """Discovered user accounts."""
    print("  → Discover: accounts …")
    ids = _paginate_query(d.query_accounts, filter_str=filter_str, limit=100)
    if not ids:
        return []
    print(f"    {len(ids):,} account IDs, fetching details …")
    return _fetch_details(d.get_accounts, ids)


def collect_discover_logins(d: Discover, filter_str: str) -> list:
    """Discovered login events."""
    print("  → Discover: login events …")
    ids = _paginate_query(d.query_logins, filter_str=filter_str, limit=100, max_offset=9900)
    if not ids:
        return []
    print(f"    {len(ids):,} login event IDs, fetching details …")
    return _fetch_details(d.get_logins, ids)


def _paginate_combined_after(method, *, filter_str: str = "", limit: int = 500,
                              facets: list = None) -> list:
    """Paginate Discover combined endpoints that use an 'after' cursor token."""
    results = []
    after: str = ""
    while True:
        kwargs: dict = {"limit": limit}
        if filter_str:
            kwargs["filter"] = filter_str
        if after:
            kwargs["after"] = after
        if facets:
            kwargs["facet"] = facets
        resp = method(**kwargs)
        if resp["status_code"] != 200:
            _log_errors(resp)
            break
        page = resp["body"].get("resources") or []
        results.extend(page)
        after = (resp["body"].get("meta") or {}).get("pagination", {}).get("after", "")
        if not page or not after:
            break
    return results


def collect_coverage_gaps(d: Discover, filter_str: str) -> dict:
    """Assets that can accept a sensor (unmanaged) or can't (unsupported)."""
    results: dict = {}
    for entity_type in ("unmanaged", "unsupported"):
        print(f"  → coverage gaps: {entity_type} …")
        base = f"entity_type:'{entity_type}'"
        fql = f"{base}+{filter_str}" if filter_str else base
        ids = _paginate_query(d.query_hosts, filter_str=fql, limit=100, max_offset=9900)
        records = _fetch_details(d.get_hosts, ids) if ids else []
        print(f"    {len(records):,} {entity_type} assets")
        results[entity_type] = records
    return results


def _summarize_coverage_gaps(gaps: dict, managed_count: int) -> dict:
    """Coverage rate and breakdowns across entity types."""
    from collections import Counter

    unmanaged   = gaps.get("unmanaged", [])
    unsupported = gaps.get("unsupported", [])

    # Manageable universe = sensor-equipped + can-take-sensor
    manageable  = managed_count + len(unmanaged)
    coverage_pct = round(managed_count / manageable * 100, 1) if manageable else 0.0

    def _breakdown(hosts: list) -> dict:
        if not hosts:
            return {"total": 0}
        platforms     = Counter(h.get("platform_name", "Unknown") for h in hosts)
        product_types = Counter(h.get("product_type_desc", "Unknown") for h in hosts)
        confidence    = Counter(str(h.get("confidence", "Unknown")) for h in hosts)
        discoverers   = Counter()
        for h in hosts:
            for pt in (h.get("discoverer_product_type_descs") or []):
                discoverers[pt] += 1
        triage = Counter(
            (h.get("triage") or {}).get("action", "none") for h in hosts
        )
        return {
            "total":                len(hosts),
            "by_platform":          dict(platforms.most_common()),
            "by_product_type":      dict(product_types.most_common()),
            "by_confidence":        dict(confidence.most_common()),
            "by_discoverer_type":   dict(discoverers.most_common()),
            "by_triage_action":     dict(triage.most_common()),
        }

    return {
        "managed_count":         managed_count,
        "unmanaged_count":       len(unmanaged),
        "unsupported_count":     len(unsupported),
        "manageable_total":      manageable,
        "sensor_coverage_pct":   coverage_pct,
        "gap": _breakdown(unmanaged),
        "unsupported": _breakdown(unsupported),
    }


# ---------------------------------------------------------------------------
# Host Groups
# ---------------------------------------------------------------------------

def collect_host_groups(hg: HostGroup) -> list:
    """All host groups with member counts."""
    print("  → host groups …")
    return _paginate_combined(hg.query_combined_host_groups)


def collect_group_members(hg: HostGroup, groups: list) -> dict:
    """Members for each group (id → list of device records)."""
    if not groups:
        return {}
    print(f"  → group members for {len(groups)} groups …")
    membership: dict = {}
    for group in groups:
        gid = group.get("id", "")
        if not gid:
            continue
        members = _paginate_combined(hg.query_combined_group_members,
                                     filter_str=f"group_id:'{gid}'")
        membership[gid] = {
            "group_name": group.get("name", ""),
            "member_count": len(members),
            "members": members,
        }
    return membership


# ---------------------------------------------------------------------------
# Zero Trust Assessment
# ---------------------------------------------------------------------------

def collect_zta(zta: ZeroTrustAssessment, filter_str: str) -> list:
    """ZTA scores for all devices."""
    print("  → Zero Trust Assessment scores …")
    return _paginate_combined(zta.query_combined_assessments, filter_str=filter_str)


# ---------------------------------------------------------------------------
# Policies (read-only inventory — what policies exist & who is assigned)
# ---------------------------------------------------------------------------

def _collect_policy_inventory(svc, label: str) -> dict:
    """Generic policy inventory: list policies + their combined member counts."""
    print(f"  → {label} policies …")
    policies = _paginate_combined(svc.query_combined_policies)
    return {
        "policies": policies,
        "total": len(policies),
    }


def collect_sensor_update_policies(sup: SensorUpdatePolicy) -> dict:
    print("  → sensor update policies + kernels …")
    policies = _paginate_combined(sup.query_combined_policies)
    builds   = _safe_call("sup_builds",  sup.query_combined_builds)   or []
    kernels  = _paginate_combined(sup.query_combined_kernels)
    return {
        "policies": policies,
        "available_builds":   builds if isinstance(builds, list) else [builds],
        "supported_kernels":  kernels,
        "total_policies":     len(policies),
    }


def collect_prevention_policies(pp: PreventionPolicy) -> dict:
    return _collect_policy_inventory(pp, "prevention")


def collect_device_control_policies(dcp: DeviceControlPolicies) -> dict:
    print("  → device control policies …")
    policies     = _paginate_combined(dcp.query_combined_policies)
    default_pol  = _safe_call("dcp_default_policy",   dcp.get_default_policies)
    default_sett = _safe_call("dcp_default_settings",  dcp.get_default_settings)
    return {
        "policies":         policies,
        "default_policy":   default_pol,
        "default_settings": default_sett,
        "total":            len(policies),
    }


def collect_response_policies(rp: ResponsePolicies) -> dict:
    return _collect_policy_inventory(rp, "response")


def collect_firewall_policies(fp: FirewallPolicies) -> dict:
    return _collect_policy_inventory(fp, "firewall")


# ---------------------------------------------------------------------------
# Sensor Download
# ---------------------------------------------------------------------------

def collect_sensor_versions(sd: SensorDownload) -> dict:
    print("  → available sensor versions …")
    ccid     = _safe_call("ccid",    sd.get_sensor_installer_ccid)
    versions = _paginate_combined(sd.get_combined_sensor_installers_by_query)
    return {
        "ccid":               ccid,
        "available_versions": versions,
        "total_versions":     len(versions),
    }


# ---------------------------------------------------------------------------
# Installation Tokens
# ---------------------------------------------------------------------------

def collect_installation_tokens(it: InstallationTokens) -> dict:
    print("  → installation tokens …")
    ids    = _paginate_query(it.tokens_query)
    tokens = _fetch_details(it.tokens_read, ids, batch_size=100) if ids else []
    audit  = _paginate_query(it.audit_events_query)
    return {
        "tokens":       tokens,
        "audit_events": audit,   # IDs only; detail fetch would be noisy
        "total_tokens": len(tokens),
    }


# ---------------------------------------------------------------------------
# Spotlight Vulnerabilities
# ---------------------------------------------------------------------------

def collect_spotlight_vulns(sv: SpotlightVulnerabilities,
                             sel: SpotlightEvaluationLogic,
                             filter_str: str) -> dict:
    """CVE exposure per host. Requires Spotlight scope."""
    vuln_filter = filter_str if filter_str else "status:'open'"
    print(f"  → Spotlight vulnerabilities (filter: {vuln_filter}) …")
    vulns = _paginate_combined(sv.query_vulnerabilities_combined,
                               filter_str=vuln_filter, limit=400)
    print(f"  → Spotlight evaluation logic …")
    logic_ids = _paginate_query(sel.query_evaluation_logic, limit=500)
    logic = _fetch_details(sel.get_evaluation_logic, logic_ids, batch_size=100) if logic_ids else []
    return {
        "vulnerabilities":     vulns,
        "evaluation_logic":    logic,
        "total_vulns":         len(vulns),
    }


# ---------------------------------------------------------------------------
# Device Content
# ---------------------------------------------------------------------------

def collect_device_content(dc: DeviceContent, filter_str: str) -> list:
    """Content state per device (detection content versions)."""
    print("  → device content states …")
    ids = _paginate_query(dc.query_states, filter_str=filter_str)
    if not ids:
        return []
    return _fetch_details(dc.get_states, ids)


# ---------------------------------------------------------------------------
# Summary statistics derived from collected data
# ---------------------------------------------------------------------------

_CONTAINER_PROVIDERS = {"AWS_EKS_FARGATE", "AZURE_CONTAINER_APPS", "AWS_ECS_FARGATE"}


# ---------------------------------------------------------------------------
# Kubernetes Protection — nodes, clusters, container coverage
# ---------------------------------------------------------------------------

def collect_k8s_nodes(k: KubernetesProtection) -> dict:
    """Collect K8s nodes, clusters, and container coverage summary from
    the KubernetesProtection API.

    Returns a dict with:
        nodes           – list of node records (container_count, pod_count,
                          linux_sensor_coverage, aids, cluster, cloud, …)
        clusters        – list of cluster records
        coverage        – container sensor coverage summary
        summary         – aggregated counts
    """
    print("  → K8s nodes …")
    nodes = _paginate_combined(k.read_nodes_combined, limit=200)
    print(f"    {len(nodes):,} nodes")

    print("  → K8s clusters …")
    clusters = _paginate_combined(k.read_clusters_combined_v2, limit=200)
    print(f"    {len(clusters):,} clusters")

    # Coverage / aggregate stats from lightweight count endpoints
    def _safe(fn):
        try:
            r = fn()
            if r["status_code"] == 200:
                return (r["body"].get("resources") or [])
            return []
        except Exception:
            return []

    coverage_raw      = _safe(k.read_sensor_coverage)
    managed_raw       = _safe(k.group_managed_containers)
    pod_count_raw     = _safe(k.read_pod_counts)
    container_cnt_raw = _safe(k.read_container_counts)
    cluster_cnt_raw   = _safe(k.read_cluster_count)
    node_cnt_raw      = _safe(k.read_node_count)
    by_cloud_raw      = _safe(k.read_node_counts_by_cloud)
    by_runtime_raw    = _safe(k.read_nodes_by_container_engine_version)

    # Parse sensor coverage
    sensor_coverage: dict = {}
    for item in coverage_raw:
        if item.get("name") == "containers-sensor-coverage":
            buckets = {b["label"]: b["count"] for b in (item.get("buckets") or [])}
            num   = buckets.get("numerator", 0)
            denom = buckets.get("denominator", 0)
            sensor_coverage = {
                "covered_containers":   num,
                "total_containers":     denom,
                "coverage_pct":         round(num / denom * 100, 1) if denom else 0,
            }

    # Parse managed vs unmanaged container counts
    managed_containers = {}
    for item in managed_raw:
        if item.get("name") == "count_by_managed":
            for b in (item.get("buckets") or []):
                managed_containers[b["label"]] = b["count"]

    # Parse node counts by cloud
    by_cloud: dict = {}
    for item in by_cloud_raw:
        if item.get("name") == "count_by_value":
            by_cloud = {b["label"]: b["count"] for b in (item.get("buckets") or [])}

    # Parse container runtime versions
    by_runtime: dict = {}
    for item in by_runtime_raw:
        if item.get("name") == "count_by_value":
            by_runtime = {b["label"]: b["count"] for b in (item.get("buckets") or [])}

    summary = {
        "cluster_count":    (cluster_cnt_raw[0].get("count") if cluster_cnt_raw else len(clusters)),
        "node_count":       (node_cnt_raw[0].get("count") if node_cnt_raw else len(nodes)),
        "pod_count":        (pod_count_raw[0].get("count") if pod_count_raw else 0),
        "container_count":  (container_cnt_raw[0].get("count") if container_cnt_raw else 0),
        "sensor_coverage":  sensor_coverage,
        "managed_containers":   managed_containers,
        "nodes_by_cloud":       by_cloud,
        "nodes_by_runtime":     by_runtime,
    }

    print(f"    containers: {summary['container_count']:,}  "
          f"coverage: {sensor_coverage.get('coverage_pct', 0):.1f}%")

    return {
        "nodes":    nodes,
        "clusters": clusters,
        "summary":  summary,
    }


# ---------------------------------------------------------------------------
# Cloud Security Assets (CSPM) — sensor coverage for cloud resource types
# ---------------------------------------------------------------------------

# Asset types to query via CloudSecurityAssets API.
# k8s_cloud key marks K8s cluster rows and maps to the SP_TO_CLOUD cloud key.
_CSA_ASSET_TYPES = [
    {"name": "AWS EC2",
     "fql":  "resource_type:'AWS::EC2::Instance'+active:true"},
    {"name": "AWS ECS Tasks",
     "fql":  "resource_type:'AWS::ECS::Task'+active:true"},
    {"name": "Azure Virtual Machines",
     "fql":  "cloud_provider:'azure'+resource_type:'Microsoft.Compute/virtualMachines'+active:true"},
    {"name": "GCP Compute Instances",
     "fql":  "cloud_provider:'gcp'+resource_type:'compute.googleapis.com/Instance'+active:true"},
    {"name": "K8s Clusters AWS",
     "fql":  "cloud_provider:'aws'+resource_type:'AWS::EKS::Cluster'+active:true",
     "k8s_cloud": "aws"},
    {"name": "K8s Clusters Azure",
     "fql":  "cloud_provider:'azure'+resource_type:'Microsoft.ContainerService/managedClusters'+active:true",
     "k8s_cloud": "azure"},
    {"name": "K8s Clusters GCP",
     "fql":  "cloud_provider:'gcp'+resource_type:'container.googleapis.com/Cluster'+active:true",
     "k8s_cloud": "gcp"},
]

_CSA_SENSOR_FQL = "+managed_by:'Sensor'"

# Maps KAC host service_provider → cloud key.
# Null/empty service_provider is Azure ARO.
_CSA_SP_TO_CLOUD = {
    "AWS_EC2_V2": "aws",
    "AZURE":      "azure",
    "GCP":        "gcp",
    "":           "azure",
}

_FALCON_IMAGE_HINTS = ["falcon-container", "falcon-sensor", "falconutil"]
_FALCON_ENV_VARS    = {"CS_FARGATE_MODE", "FALCONCTL_OPT", "CrowdStrike_CID", "CrowdStrike_CCid"}
_FALCON_VOLUMES     = {"/tmp/CrowdStrike"}


def _csa_total(resp: dict) -> int:
    """Extract pagination.total from a CloudSecurityAssets query response."""
    return (
        (resp.get("body") or {})
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )


def _csa_get_all_ids(csa: CloudSecurityAssets, fql: str) -> list:
    """Paginate all asset IDs matching an FQL filter via query_assets."""
    ids = []
    offset = 0
    while True:
        resp = csa.query_assets(filter=fql, limit=500, offset=offset)
        if resp["status_code"] != 200:
            _log_errors(resp, label=f"csa query_assets({fql[:60]})")
            break
        body  = resp.get("body") or {}
        batch = body.get("resources") or []
        ids.extend(batch)
        total  = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if not batch or offset >= total:
            break
    return ids


def _csa_is_falcon_patched(config_raw: str) -> bool:
    """Return True if an ECS task definition config contains Falcon sensor indicators."""
    if not config_raw:
        return False
    try:
        config = json.loads(config_raw)
    except (json.JSONDecodeError, TypeError):
        return False
    for container in config.get("containerDefinitions") or []:
        image = (container.get("image") or "").lower()
        name  = (container.get("name")  or "").lower()
        if any(hint in image for hint in _FALCON_IMAGE_HINTS):
            return True
        if any(hint in name for hint in ["falcon", "crowdstrike"]):
            return True
        env_vars = {e.get("name") for e in (container.get("environment") or [])}
        if env_vars & _FALCON_ENV_VARS:
            return True
        mounts = [m.get("containerPath", "") for m in (container.get("mountPoints") or [])]
        if any(any(fv in m for fv in _FALCON_VOLUMES) for m in mounts):
            return True
    return False


def _csa_get_asset_counts(csa: CloudSecurityAssets, asset_type: dict) -> dict:
    """Two fast count queries: total and with-sensor (managed_by:'Sensor')."""
    fql    = asset_type["fql"]
    errors = []

    resp_total = csa.query_assets(filter=fql, limit=1)
    if resp_total["status_code"] != 200:
        errors.append({"op": "total", "status": resp_total["status_code"],
                        "errors": (resp_total.get("body") or {}).get("errors")})
        return {"name": asset_type["name"], "total_count": 0, "with_sensors": 0,
                "without_sensors": 0, "coverage_rate": 0.0, "estimated": False, "errors": errors}

    total = _csa_total(resp_total)

    resp_sensor = csa.query_assets(filter=fql + _CSA_SENSOR_FQL, limit=1)
    if resp_sensor["status_code"] != 200:
        errors.append({"op": "sensor", "status": resp_sensor["status_code"],
                        "errors": (resp_sensor.get("body") or {}).get("errors")})
        with_sensors = 0
    else:
        with_sensors = _csa_total(resp_sensor)

    without  = total - with_sensors
    coverage = round(with_sensors / total * 100, 1) if total > 0 else 0.0
    return {"name": asset_type["name"], "total_count": total, "with_sensors": with_sensors,
            "without_sensors": without, "coverage_rate": coverage, "estimated": False, "errors": errors}


def _csa_get_ecs_task_def_counts(csa: CloudSecurityAssets) -> dict:
    """Count patched/unpatched ECS task definitions by inspecting container config."""
    ids         = _csa_get_all_ids(csa, "resource_type:'AWS::ECS::TaskDefinition'")
    total_count = len(ids)
    if not total_count:
        return {"name": "AWS ECS Task Definitions", "total_count": 0, "with_sensors": 0,
                "without_sensors": 0, "coverage_rate": 0.0, "estimated": False, "errors": []}

    patched    = 0
    api_errors = []
    for i in range(0, len(ids), 100):
        resp = csa.get_assets(ids=ids[i:i + 100])
        if resp["status_code"] != 200:
            api_errors.append({"op": "get_assets", "status": resp["status_code"],
                                "errors": (resp.get("body") or {}).get("errors")})
            continue
        for r in (resp.get("body") or {}).get("resources") or []:
            if _csa_is_falcon_patched(r.get("configuration", "")):
                patched += 1

    without  = total_count - patched
    coverage = round(patched / total_count * 100, 1) if total_count > 0 else 0.0
    return {"name": "AWS ECS Task Definitions", "total_count": total_count, "with_sensors": patched,
            "without_sensors": without, "coverage_rate": coverage, "estimated": False, "errors": api_errors}


def _csa_k8s_cluster_sensor_counts(h: Hosts) -> dict:
    """Per-cloud count of K8s clusters that have ≥1 sensor-equipped worker node.

    Uses the KAC workaround: each KAC deployment registers a host with
    product_type_desc='Kubernetes Cluster'. Worker nodes sharing its
    k8s_cluster_id UUID indicate the cluster has sensor coverage.
    """
    resp = h.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=100
    )
    if resp["status_code"] != 200:
        return {"aws": 0, "azure": 0, "gcp": 0}

    kac_ids = (resp.get("body") or {}).get("resources") or []
    if not kac_ids:
        return {"aws": 0, "azure": 0, "gcp": 0}

    det = h.get_device_details(ids=kac_ids)
    kac_resources = (det.get("body") or {}).get("resources") or []

    # Deduplicate by k8s_cluster_id per cloud — a cluster with multiple KAC host
    # records (e.g. duplicate device registrations) must only be counted once.
    seen: set = set()
    counts = {"aws": 0, "azure": 0, "gcp": 0}
    for kac_host in kac_resources:
        sp           = kac_host.get("service_provider") or ""
        cloud        = _CSA_SP_TO_CLOUD.get(sp)
        cluster_uuid = kac_host.get("k8s_cluster_id")
        if not cloud or not cluster_uuid:
            continue
        dedup_key = (cloud, cluster_uuid)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        r = h.query_devices_by_filter(filter=f"k8s_cluster_id:'{cluster_uuid}'", limit=1)
        if r["status_code"] == 200 and _csa_total(r) > 0:
            counts[cloud] += 1
    return counts


def _csa_k8s_cluster_row(csa: CloudSecurityAssets, asset_type: dict, with_sensors: int) -> dict:
    """Build a K8s cluster coverage row using CSA for total and pre-computed sensor count."""
    resp_total = csa.query_assets(filter=asset_type["fql"], limit=1)
    errors = []
    if resp_total["status_code"] != 200:
        errors.append({"op": "total", "status": resp_total["status_code"],
                        "errors": (resp_total.get("body") or {}).get("errors")})
        total = 0
    else:
        total = _csa_total(resp_total)

    # CSA has no records but KAC found clusters — use KAC count as fallback total
    if total == 0 and with_sensors > 0:
        total = with_sensors

    without  = max(0, total - with_sensors)
    effective = min(with_sensors, total)
    coverage = round(effective / total * 100, 1) if total > 0 else 0.0
    return {"name": asset_type["name"], "total_count": total,
            "with_sensors": effective, "without_sensors": without,
            "coverage_rate": coverage, "estimated": False, "errors": errors}


def _csa_k8s_kac_counts(csa: CloudSecurityAssets, h: Hosts) -> dict:
    """Aggregate K8s cluster row: total from CSA, KAC count from Hosts API."""
    from collections import Counter as _Counter
    errors     = []
    csa_totals = {}

    for at in _CSA_ASSET_TYPES:
        cloud_key = at.get("k8s_cloud")
        if not cloud_key:
            continue
        resp = csa.query_assets(filter=at["fql"], limit=1)
        if resp["status_code"] == 200:
            csa_totals[cloud_key] = _csa_total(resp)
        else:
            csa_totals[cloud_key] = 0
            errors.append({"op": "k8s_total", "filter": at["fql"],
                            "status": resp["status_code"],
                            "errors": (resp.get("body") or {}).get("errors")})

    resp_kac = h.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=100
    )
    if resp_kac["status_code"] == 200:
        kac_ids = (resp_kac.get("body") or {}).get("resources") or []
        if kac_ids:
            det = h.get_device_details(ids=kac_ids)
            seen_ids: set = set()
            for host in (det.get("body") or {}).get("resources") or []:
                cid = host.get("k8s_cluster_id")
                if cid:
                    seen_ids.add(cid)
            kac_count = len(seen_ids)
        else:
            kac_count = 0
    else:
        kac_count = 0
        if sum(csa_totals.values()) > 0:
            errors.append({"op": "kac_hosts_query", "status": resp_kac["status_code"],
                            "errors": (resp_kac.get("body") or {}).get("errors")})

    # For clouds where CSA returns 0, use per-cloud KAC counts as fallback total
    csa_missing = {k for k, v in csa_totals.items() if v == 0}
    if csa_missing and kac_count > 0:
        resp_ids = h.query_devices_by_filter(
            filter="product_type_desc:'Kubernetes Cluster'", limit=100
        )
        kac_ids = (resp_ids.get("body") or {}).get("resources") or []
        if kac_ids:
            det = h.get_device_details(ids=kac_ids)
            sp_counts = _Counter()
            for host in (det.get("body") or {}).get("resources") or []:
                sp    = host.get("service_provider") or ""
                cloud = _CSA_SP_TO_CLOUD.get(sp)
                if cloud in csa_missing:
                    sp_counts[cloud] += 1
            for cloud, count in sp_counts.items():
                csa_totals[cloud] = count

    total    = sum(csa_totals.values())
    without  = max(0, total - kac_count)
    coverage = round(kac_count / total * 100, 1) if total > 0 else 0.0
    return {"name": "K8s Clusters with KAC", "total_count": total, "with_sensors": kac_count,
            "without_sensors": without, "coverage_rate": coverage, "estimated": False, "errors": errors}


def _csa_get_managed_assets(csa: CloudSecurityAssets, fql: str, cap: int = 500) -> dict:
    """Return up to cap assets that have a Falcon sensor for a given FQL filter."""
    ids   = _csa_get_all_ids(csa, fql + _CSA_SENSOR_FQL)
    total = len(ids)
    fetch_ids = ids[:cap]
    assets = []
    for i in range(0, len(fetch_ids), 100):
        resp = csa.get_assets(ids=fetch_ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        r.get("status"),
            })
    return {"assets": assets, "total": total, "shown": len(assets)}


def _csa_get_unprotected_assets(csa: CloudSecurityAssets, fql: str, cap: int = 500) -> dict:
    """Return up to cap assets without sensors for a given FQL filter."""
    all_ids    = _csa_get_all_ids(csa, fql)
    sensor_ids = set(_csa_get_all_ids(csa, fql + _CSA_SENSOR_FQL))
    without    = [i for i in all_ids if i not in sensor_ids]
    total      = len(without)
    fetch_ids  = without[:cap]
    assets     = []
    for i in range(0, len(fetch_ids), 100):
        resp = csa.get_assets(ids=fetch_ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        r.get("status"),
            })
    return {"assets": assets, "total": total, "shown": len(assets)}


def _csa_get_unpatched_task_defs(csa: CloudSecurityAssets, cap: int = 500) -> dict:
    """Return identifying fields for ECS task definitions without Falcon sidecar."""
    ids      = _csa_get_all_ids(csa, "resource_type:'AWS::ECS::TaskDefinition'")
    unpatched = []
    for i in range(0, len(ids), 100):
        resp = csa.get_assets(ids=ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            if not _csa_is_falcon_patched(r.get("configuration", "")):
                unpatched.append({
                    "resource_id":   r.get("resource_id"),
                    "resource_name": r.get("resource_name"),
                    "account_id":    r.get("account_id"),
                    "region":        r.get("region"),
                    "status":        None,
                })
    total = len(unpatched)
    return {"assets": unpatched[:cap], "total": total, "shown": min(total, cap)}


def _csa_k8s_cluster_name(asset: dict) -> str:
    """Normalise a CSA cluster asset to a bare cluster name for KAC hostname matching.

    AWS EKS clusters often have resource_name=None; their resource_id is the plain
    cluster name (e.g. 'bp-test-falcon-eks').  Azure resource_ids are full ARM paths;
    resource_name is populated.  Splitting on '/' and taking the last segment handles
    both cases and also matches the Hosts API ARN-format hostnames.
    """
    raw = asset.get("resource_name") or asset.get("resource_id") or ""
    return raw.split("/")[-1].lower()


def _csa_k8s_kac_names(h: Hosts, k8s_cloud: str) -> set:
    """Return lowercase cluster names that have a KAC-registered host for this cloud."""
    resp_h = h.query_devices_by_filter(
        filter="product_type_desc:'Kubernetes Cluster'", limit=100
    )
    kac_names: set = set()
    if resp_h["status_code"] == 200:
        kac_ids = (resp_h.get("body") or {}).get("resources") or []
        if kac_ids:
            det = h.get_device_details(ids=kac_ids)
            for host in (det.get("body") or {}).get("resources") or []:
                sp = host.get("service_provider") or ""
                if _CSA_SP_TO_CLOUD.get(sp) != k8s_cloud:
                    continue
                hn   = host.get("hostname") or ""
                name = hn.split("/")[-1].lower() if "/" in hn else hn.lower()
                kac_names.add(name)
    return kac_names


def _csa_get_k8s_cluster_assets(csa: CloudSecurityAssets, h: Hosts,
                                 fql: str, k8s_cloud: str) -> dict:
    """Return CSA cluster entities that do NOT have KAC, via hostname correlation."""
    ids    = _csa_get_all_ids(csa, fql)
    assets = []
    for i in range(0, len(ids), 100):
        resp = csa.get_assets(ids=ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        None,
            })

    kac_names = _csa_k8s_kac_names(h, k8s_cloud)
    unprotected = [
        a for a in assets
        if _csa_k8s_cluster_name(a) not in kac_names
    ]
    total = len(unprotected)
    return {"assets": unprotected, "total": total, "shown": total}


def _csa_get_k8s_managed_assets(csa: CloudSecurityAssets, h: Hosts,
                                  fql: str, k8s_cloud: str) -> dict:
    """Return CSA cluster entities that DO have KAC, via hostname correlation."""
    ids    = _csa_get_all_ids(csa, fql)
    assets = []
    for i in range(0, len(ids), 100):
        resp = csa.get_assets(ids=ids[i:i + 100])
        for r in (resp.get("body") or {}).get("resources") or []:
            assets.append({
                "resource_id":   r.get("resource_id"),
                "resource_name": r.get("resource_name"),
                "account_id":    r.get("account_id"),
                "region":        r.get("region"),
                "status":        None,
            })

    kac_names = _csa_k8s_kac_names(h, k8s_cloud)
    managed = [
        a for a in assets
        if _csa_k8s_cluster_name(a) in kac_names
    ]
    total = len(managed)
    return {"assets": managed, "total": total, "shown": total}


def collect_csa_coverage(csa: CloudSecurityAssets, h: Hosts) -> dict:
    """Collect sensor coverage for cloud resource types visible in Falcon CSPM.

    Mirrors the CBRE asset coverage dashboard logic, using the CloudSecurityAssets
    API for resource counts and the Hosts API for K8s cluster sensor detection.

    Returns a dict with:
        total_assets  – sum of all non-K8s-KAC asset counts
        rows          – coverage row per asset type (9 rows)
        details       – per-type unprotected asset lists (up to 500 each)
    """
    print("  → cloud asset coverage (CSPM) …")

    # Pre-fetch K8s cluster sensor counts once (one Hosts API call per KAC cluster)
    k8s_sensor_counts = _csa_k8s_cluster_sensor_counts(h)

    rows         = []
    total_assets = 0

    for at in _CSA_ASSET_TYPES:
        cloud_key = at.get("k8s_cloud")
        if cloud_key:
            row = _csa_k8s_cluster_row(csa, at, k8s_sensor_counts.get(cloud_key, 0))
        else:
            row = _csa_get_asset_counts(csa, at)
        rows.append(row)
        total_assets += row["total_count"]

    # ECS Task Definitions: insert after ECS Tasks (index 2)
    ecs_td_row = _csa_get_ecs_task_def_counts(csa)
    rows.insert(2, ecs_td_row)
    total_assets += ecs_td_row["total_count"]

    # K8s with KAC aggregate row — do NOT add to total (clusters already counted above)
    kac_row = _csa_k8s_kac_counts(csa, h)
    rows.append(kac_row)

    print(f"    {len(rows)} asset types  |  {total_assets:,} total cloud assets")

    # Pre-fetch unprotected asset details (up to 500 per type)
    print("  → unprotected cloud asset details …")
    details: dict = {}
    type_map = {at["name"]: at for at in _CSA_ASSET_TYPES}

    for row in rows:
        name = row["name"]
        if name == "K8s Clusters with KAC":
            continue  # aggregate row — no per-asset drilldown
        if row.get("without_sensors", 0) == 0:
            details[name] = {"assets": [], "total": 0, "shown": 0}
            continue

        at       = type_map.get(name)
        k8s_cloud = at.get("k8s_cloud") if at else None

        if name == "AWS ECS Task Definitions":
            details[name] = _csa_get_unpatched_task_defs(csa)
        elif k8s_cloud and at:
            raw = _csa_get_k8s_cluster_assets(csa, h, at["fql"], k8s_cloud)
            # Use the row's authoritative without_sensors count so the drilldown total
            # matches the table.  Name-matching can over-count unmanaged when some KAC
            # cluster hostnames differ from their CSA resource_id; trim the asset list
            # to the authoritative count so neither the total nor the list over-reports.
            auth_without = row.get("without_sensors", raw["total"])
            trimmed = raw["assets"][:auth_without]
            details[name] = {"assets": trimmed, "total": auth_without, "shown": len(trimmed)}
        elif at:
            details[name] = _csa_get_unprotected_assets(csa, at["fql"])
        else:
            details[name] = {"assets": [], "total": 0, "shown": 0}

        shown = details[name].get("shown", 0)
        total = details[name].get("total", 0)
        print(f"    {name}: {shown:,} shown of {total:,} unprotected")

    # Pre-fetch managed asset details (up to 500 per type)
    print("  → managed cloud asset details …")
    managed_details: dict = {}
    for row in rows:
        name = row["name"]
        if name == "K8s Clusters with KAC":
            continue
        at        = type_map.get(name)
        k8s_cloud = at.get("k8s_cloud") if at else None
        if not at:
            managed_details[name] = {"assets": [], "total": 0, "shown": 0}
            continue
        if row.get("with_sensors", 0) == 0:
            managed_details[name] = {"assets": [], "total": 0, "shown": 0}
            continue
        if k8s_cloud:
            raw = _csa_get_k8s_managed_assets(csa, h, at["fql"], k8s_cloud)
            # Use the row's authoritative with_sensors count for the total so the
            # drilldown summary matches the table.  The assets list contains only the
            # clusters that could be identified by name; unresolvable ones are noted
            # in the report's methodology note.
            auth_with = row.get("with_sensors", raw["total"])
            managed_details[name] = {"assets": raw["assets"], "total": auth_with, "shown": raw["shown"]}
        else:
            managed_details[name] = _csa_get_managed_assets(csa, at["fql"])
        shown = managed_details[name].get("shown", 0)
        total = managed_details[name].get("total", 0)
        print(f"    {name}: {shown:,} shown of {total:,} managed")

    return {"total_assets": total_assets, "rows": rows, "details": details,
            "managed_details": managed_details}


def _host_container_status(h: dict) -> str:
    """Classify whether a managed host is a container, a K8s node, or neither.

    Returns one of:
        'container'  – the host IS a container / pod itself
        'k8s_node'   – a node that schedules / runs containers (K8s worker/cluster)
        'none'       – no container involvement detected
    """
    pt   = h.get("product_type_desc", "")
    dt   = h.get("deployment_type", "")
    sp   = h.get("service_provider", "")
    tags = " ".join(h.get("tags") or []).lower()
    pod_ns = h.get("pod_namespace", "")

    if pt == "Pod" or sp in _CONTAINER_PROVIDERS:
        return "container"
    if (pt == "Kubernetes Cluster"
            or dt == "DaemonSet"
            or pod_ns
            or "k8s-worker" in tags
            or "k8s-master" in tags
            or "cluster/" in tags):
        return "k8s_node"
    return "none"


def _summarize_hosts(hosts: list) -> dict:
    """Build summary breakdowns from the full host list."""
    if not hosts:
        return {}
    from collections import Counter

    platforms      = Counter(h.get("platform_name", "Unknown") for h in hosts)
    os_versions    = Counter(h.get("os_version", "Unknown") for h in hosts)
    statuses       = Counter(h.get("status", "Unknown") for h in hosts)
    rfm            = Counter(h.get("reduced_functionality_mode", "no") for h in hosts)
    sensor_ver     = Counter(h.get("agent_version", "Unknown") for h in hosts)
    providers      = Counter(h.get("service_provider", "on-prem") for h in hosts)
    product_types  = Counter(h.get("product_type_desc", "Unknown") for h in hosts)
    containment    = Counter(h.get("filesystem_containment_status", "normal") for h in hosts)
    container_stat = Counter(_host_container_status(h) for h in hosts)

    return {
        "total":                len(hosts),
        "by_platform":          dict(platforms.most_common()),
        "by_status":            dict(statuses.most_common()),
        "by_product_type":      dict(product_types.most_common()),
        "by_os_version":        dict(os_versions.most_common(20)),
        "by_sensor_version":    dict(sensor_ver.most_common(20)),
        "by_cloud_provider":    dict(providers.most_common()),
        "reduced_functionality_mode": dict(rfm.most_common()),
        "containment_status":   dict(containment.most_common()),
        "by_container_status":  dict(container_stat.most_common()),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SECTIONS = [
    "hosts", "hidden_hosts", "online_state", "login_history", "network_history",
    "cloud_hosts", "kubernetes_hosts",
    "discover_hosts", "discover_apps", "discover_accounts", "discover_logins",
    "coverage_gaps",
    "k8s_nodes",
    "host_groups",
    "zta",
    "sensor_update_policies", "prevention_policies", "device_control_policies",
    "response_policies", "firewall_policies",
    "sensor_versions",
    "installation_tokens",
    "spotlight",
    "device_content",
    "csa_coverage",
]

DEFAULT_SECTIONS = ",".join([
    "hosts", "hidden_hosts", "online_state",
    "cloud_hosts", "kubernetes_hosts",
    "discover_hosts",
    "coverage_gaps",
    "k8s_nodes",
    "sensor_versions",
    "csa_coverage",
])


def build_auth(cloud: str) -> OAuth2:
    client_id     = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set.")

    base_url_map = {
        "us-1":     "https://api.crowdstrike.com",
        "us-2":     "https://api.us-2.crowdstrike.com",
        "eu-1":     "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    }
    base_url = base_url_map.get(cloud.lower(), "https://api.crowdstrike.com")

    auth = OAuth2(client_id=client_id, client_secret=client_secret, base_url=base_url)
    if auth.token_fail_reason:
        raise SystemExit(f"Authentication failed: {auth.token_fail_reason}")
    print(f"  Authenticated to {cloud} ({base_url})")
    return auth


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output",  default=None,
                        help="Output JSON file (default: auto-timestamped)")
    parser.add_argument("--filter",  default="",
                        help="FQL filter applied to all supporting endpoints")
    parser.add_argument("--cloud",   default=os.getenv("FALCON_CLOUD", "us-1"),
                        help="Falcon cloud region (default: us-1)")
    parser.add_argument("--section", default=DEFAULT_SECTIONS,
                        help=f"Comma-separated sections. Available: {', '.join(SECTIONS)}")
    parser.add_argument("--login-history", action="store_true",
                        help="Collect login history for a sample of hosts (slower)")
    parser.add_argument("--network-history", action="store_true",
                        help="Collect network address history for hosts (slower)")
    args = parser.parse_args()

    requested = {s.strip() for s in args.section.split(",")}
    unknown = requested - set(SECTIONS)
    if unknown:
        raise SystemExit(f"Unknown section(s): {unknown}\nAvailable: {', '.join(SECTIONS)}")

    # login/network history only if explicitly requested
    if args.login_history:
        requested.add("login_history")
    if args.network_history:
        requested.add("network_history")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_file = args.output or f"falcon_hosts_inventory_{ts}.json"

    print(f"\n{'='*60}")
    print("  CrowdStrike Falcon — Hosts & Endpoints Inventory")
    print(f"  Cloud: {args.cloud}  |  Timestamp: {ts}")
    print(f"  Sections: {len(requested)}")
    print(f"  Output: {output_file}")
    print(f"{'='*60}\n")

    # --- Auth ---
    print("[AUTH] Authenticating …")
    auth = build_auth(args.cloud)

    def svc(cls):
        return cls(auth_object=auth)

    # Instantiate all service classes
    h_svc   = svc(Hosts)
    d_svc   = svc(Discover)
    hg_svc  = svc(HostGroup)
    zta_svc = svc(ZeroTrustAssessment)
    sup_svc = svc(SensorUpdatePolicy)
    pp_svc  = svc(PreventionPolicy)
    dcp_svc = svc(DeviceControlPolicies)
    rp_svc  = svc(ResponsePolicies)
    fp_svc  = svc(FirewallPolicies)
    sd_svc  = svc(SensorDownload)
    it_svc  = svc(InstallationTokens)
    sv_svc  = svc(SpotlightVulnerabilities)
    sel_svc = svc(SpotlightEvaluationLogic)
    dc_svc  = svc(DeviceContent)
    k8s_svc = svc(KubernetesProtection)
    csa_svc = svc(CloudSecurityAssets)

    inventory: dict = {
        "_meta": {
            "generated_at": ts,
            "cloud":        args.cloud,
            "fql_filter":   args.filter,
            "sections":     sorted(requested),
        }
    }

    # -----------------------------------------------------------------------
    # [1] Hosts
    # -----------------------------------------------------------------------
    print("\n[1/9] Hosts API …")
    managed_hosts: list = []
    managed_ids:   list = []

    if "hosts" in requested:
        managed_hosts = collect_hosts(h_svc, args.filter)
        managed_ids   = [d["device_id"] for d in managed_hosts if "device_id" in d]
        inventory["hosts"] = managed_hosts
        inventory["host_summary"] = _summarize_hosts(managed_hosts)

    if "cloud_hosts" in requested:
        prefetched = managed_hosts if "hosts" in requested else None
        cloud = collect_cloud_hosts(h_svc, args.filter, already_fetched=prefetched)
        inventory["cloud_hosts"] = cloud
        inventory["cloud_summary"] = _summarize_cloud_hosts(cloud)

    if "kubernetes_hosts" in requested:
        prefetched = managed_hosts if "hosts" in requested else None
        k8s = collect_kubernetes_hosts(h_svc, args.filter, already_fetched=prefetched)
        inventory["kubernetes_hosts"] = k8s
        inventory["kubernetes_summary"] = _summarize_kubernetes_hosts(k8s)

    if "hidden_hosts" in requested:
        inventory["hidden_hosts"] = collect_hidden_hosts(h_svc)

    if "online_state" in requested:
        ids_for_state = managed_ids or _scroll_hosts(h_svc, args.filter)
        inventory["online_state"] = collect_online_state(h_svc, ids_for_state)

    if "login_history" in requested:
        ids_for_login = managed_ids or _scroll_hosts(h_svc, args.filter)
        inventory["login_history"] = collect_login_history(h_svc, ids_for_login)

    if "network_history" in requested:
        ids_for_net = managed_ids or _scroll_hosts(h_svc, args.filter)
        inventory["network_history"] = collect_network_history(h_svc, ids_for_net)

    # -----------------------------------------------------------------------
    # [2] Discover
    # -----------------------------------------------------------------------
    print("\n[2/9] Discover (Shadow IT / asset discovery) API …")

    if "discover_hosts" in requested:
        inventory["discover_hosts"] = collect_discover_hosts(d_svc, args.filter)

    if "discover_apps" in requested:
        inventory["discover_apps"] = collect_discover_apps(d_svc, args.filter)

    if "discover_accounts" in requested:
        inventory["discover_accounts"] = collect_discover_accounts(d_svc, args.filter)

    if "discover_logins" in requested:
        inventory["discover_logins"] = collect_discover_logins(d_svc, args.filter)

    if "coverage_gaps" in requested:
        gaps = collect_coverage_gaps(d_svc, args.filter)
        inventory["coverage_gaps"] = gaps
        inventory["coverage_summary"] = _summarize_coverage_gaps(gaps, len(managed_hosts))

    # -----------------------------------------------------------------------
    # [3] Kubernetes Protection — nodes, clusters, container coverage
    # -----------------------------------------------------------------------
    print("\n[3/9] Kubernetes Protection API …")

    if "k8s_nodes" in requested:
        k8s_data = collect_k8s_nodes(k8s_svc)
        inventory["k8s_nodes"] = k8s_data

        # Enrich managed hosts with container_count from node records
        # Join: node.agents[].aid  →  managed_host.device_id
        if managed_hosts and k8s_data.get("nodes"):
            aid_to_node = {}
            for node in k8s_data["nodes"]:
                for agent in (node.get("agents") or []):
                    aid = agent.get("aid")
                    if aid:
                        aid_to_node[aid] = node
            enriched = 0
            for host in managed_hosts:
                node = aid_to_node.get(host.get("device_id"))
                if node:
                    host["_k8s_container_count"] = node.get("container_count", 0)
                    host["_k8s_pod_count"]       = node.get("pod_count", 0)
                    host["_k8s_sensor_coverage"] = node.get("linux_sensor_coverage", False)
                    host["_k8s_cluster_name"]    = node.get("cluster_name", "")
                    host["_k8s_runtime"]         = node.get("container_runtime_version", "")
                    enriched += 1
            if enriched:
                print(f"  → enriched {enriched:,} managed hosts with container counts")
                # Refresh host summary to include updated container status
                inventory["host_summary"] = _summarize_hosts(managed_hosts)

    # -----------------------------------------------------------------------
    # [4] Cloud Security Assets (CSPM)
    # -----------------------------------------------------------------------
    print("\n[4/N] Cloud Security Assets API …")
    if "csa_coverage" in requested:
        inventory["csa_coverage"] = collect_csa_coverage(csa_svc, h_svc)

    # -----------------------------------------------------------------------
    # [5] Host Groups
    # -----------------------------------------------------------------------
    print("\n[3/9] Host Groups API …")
    groups: list = []

    if "host_groups" in requested:
        groups = collect_host_groups(hg_svc)
        membership = collect_group_members(hg_svc, groups)
        inventory["host_groups"] = {
            "groups": groups,
            "membership": membership,
        }

    # -----------------------------------------------------------------------
    # [5] Zero Trust Assessment
    # -----------------------------------------------------------------------
    print("\n[4/9] Zero Trust Assessment API …")
    if "zta" in requested:
        inventory["zero_trust_assessments"] = collect_zta(zta_svc, args.filter)

    # -----------------------------------------------------------------------
    # [6] Policies
    # -----------------------------------------------------------------------
    print("\n[5/9] Policy APIs …")
    if "sensor_update_policies"   in requested:
        inventory["sensor_update_policies"]    = collect_sensor_update_policies(sup_svc)
    if "prevention_policies"      in requested:
        inventory["prevention_policies"]       = collect_prevention_policies(pp_svc)
    if "device_control_policies"  in requested:
        inventory["device_control_policies"]   = collect_device_control_policies(dcp_svc)
    if "response_policies"        in requested:
        inventory["response_policies"]         = collect_response_policies(rp_svc)
    if "firewall_policies"        in requested:
        inventory["firewall_policies"]         = collect_firewall_policies(fp_svc)

    # -----------------------------------------------------------------------
    # [7] Sensor Download
    # -----------------------------------------------------------------------
    print("\n[6/9] Sensor Download API …")
    if "sensor_versions" in requested:
        inventory["sensor_versions"] = collect_sensor_versions(sd_svc)

    # -----------------------------------------------------------------------
    # [8] Installation Tokens
    # -----------------------------------------------------------------------
    print("\n[7/9] Installation Tokens API …")
    if "installation_tokens" in requested:
        inventory["installation_tokens"] = collect_installation_tokens(it_svc)

    # -----------------------------------------------------------------------
    # [9] Spotlight Vulnerabilities
    # -----------------------------------------------------------------------
    print("\n[8/9] Spotlight Vulnerabilities API …")
    if "spotlight" in requested:
        inventory["spotlight"] = collect_spotlight_vulns(sv_svc, sel_svc, args.filter)

    # -----------------------------------------------------------------------
    # [10] Device Content
    # -----------------------------------------------------------------------
    print("\n[9/9] Device Content API …")
    if "device_content" in requested:
        inventory["device_content"] = collect_device_content(dc_svc, args.filter)

    # -----------------------------------------------------------------------
    # Summary + output
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print("  INVENTORY SUMMARY")
    print(f"{'='*60}")

    def _count(val) -> str:
        if isinstance(val, list): return f"{len(val):,}"
        if isinstance(val, dict): return f"{len(val)} keys"
        return "—"

    for section, data in inventory.items():
        if section == "_meta":
            continue
        print(f"  {section:<35} {_count(data)}")

    print(f"\n  Writing output → {output_file}")
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2, default=str)

    size_kb = os.path.getsize(output_file) / 1024
    print(f"  Done — {size_kb:,.1f} KB written.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
