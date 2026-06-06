#!/usr/bin/env python3
"""
CrowdStrike Falcon — Kubernetes & Container Asset Inventory
===========================================================
Pulls a full inventory of all Kubernetes and container assets from Falcon
using every available API surface:

  - KubernetesProtection  : clusters, nodes, pods, containers, namespaces,
                            deployments, IOMs, cloud accounts (AWS/Azure)
  - ContainerImages       : image details, vulnerability counts, base images
  - ContainerVulnerabilities : CVE exposure per image
  - ContainerDetections   : runtime detections per container
  - ContainerPackages     : packages / SBOMs across images
  - ContainerImageCompliance : CIS/compliance rule results
  - KubernetesContainerCompliance : K8s-level compliance aggregates
  - FalconContainer       : registry scan results, image assessments

Output: JSON file  (default: falcon_k8s_inventory_<timestamp>.json)

Usage:
    python k8s_container_inventory.py
    python k8s_container_inventory.py --output my_inventory.json
    python k8s_container_inventory.py --section clusters,images,vulns
    python k8s_container_inventory.py --filter "cloud_name:'AWS'"

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
        KubernetesProtection,
        ContainerImages,
        ContainerVulnerabilities,
        ContainerDetections,
        ContainerPackages,
        ContainerImageCompliance,
        KubernetesContainerCompliance,
        FalconContainer,
    )
except ImportError as exc:
    raise SystemExit(
        "FalconPy is required.  Install: pip install crowdstrike-falconpy"
    ) from exc


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------

def _paginate_combined(method, *, filter_str: str = "", limit: int = 200) -> list:
    """Generic paginator for *_combined endpoints that return resources[] directly."""
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


def _paginate_query(query_method, *, filter_str: str = "", limit: int = 500) -> list:
    """Paginate query endpoints that return lists of IDs."""
    ids = []
    offset = 0
    while True:
        kwargs: dict = {"limit": limit, "offset": offset}
        if filter_str:
            kwargs["filter"] = filter_str
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


def _safe_call(label: str, method, **kwargs) -> Any:
    """Call a single API method, log errors, return body resources or raw body."""
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
# Section collectors
# ---------------------------------------------------------------------------

def collect_cluster_summary(kube: KubernetesProtection) -> dict:
    print("  → cluster counts by date / version / status …")
    return {
        "by_date_range": _safe_call("clusters_by_date_range", kube.read_clusters_by_date_range),
        "by_version":    _safe_call("clusters_by_version",    kube.read_clusters_by_version),
        "by_status":     _safe_call("clusters_by_status",     kube.read_clusters_by_status),
        "total_count":   _safe_call("cluster_count",          kube.read_cluster_count),
    }


def collect_clusters(kube: KubernetesProtection, filter_str: str) -> list:
    print("  → clusters (combined) …")
    return _paginate_combined(kube.read_clusters_combined, filter_str=filter_str)


def collect_nodes(kube: KubernetesProtection, filter_str: str) -> list:
    print("  → nodes (combined) …")
    return _paginate_combined(kube.read_nodes_combined, filter_str=filter_str)


def collect_node_summary(kube: KubernetesProtection) -> dict:
    print("  → node counts by cloud / engine version / date …")
    return {
        "by_cloud":            _safe_call("nodes_by_cloud",   kube.read_node_counts_by_cloud),
        "by_engine_version":   _safe_call("nodes_by_engine",  kube.read_nodes_by_container_engine_version),
        "by_date_range":       _safe_call("nodes_by_date",    kube.read_node_counts_by_date_range),
        "total_count":         _safe_call("node_count",       kube.read_node_count),
    }


def collect_namespaces(kube: KubernetesProtection) -> dict:
    print("  → namespace counts …")
    return {
        "total_count":  _safe_call("namespace_count",         kube.read_namespace_count),
        "by_date_range": _safe_call("namespaces_by_date",     kube.read_namespaces_by_date_range_count),
    }


def collect_pods(kube: KubernetesProtection, filter_str: str) -> list:
    print("  → pods (combined) …")
    return _paginate_combined(kube.read_pods_combined, filter_str=filter_str)


def collect_pod_summary(kube: KubernetesProtection) -> dict:
    print("  → pod counts …")
    return {
        "by_date_range": _safe_call("pods_by_date", kube.read_pod_counts_by_date_range),
        "total_count":   _safe_call("pod_count",    kube.read_pod_counts),
    }


def collect_containers(kube: KubernetesProtection, filter_str: str) -> list:
    print("  → containers (combined) …")
    return _paginate_combined(kube.read_containers_combined, filter_str=filter_str)


def collect_container_summary(kube: KubernetesProtection, filter_str: str) -> dict:
    print("  → container summary counts …")
    kwargs = {"filter": filter_str} if filter_str else {}
    return {
        "total_count":        _safe_call("container_count",      kube.read_container_counts, **kwargs),
        "by_date_range":      _safe_call("containers_by_date",   kube.read_containers_by_date_range),
        "by_registry":        _safe_call("containers_by_registry", kube.read_containers_by_registry, **kwargs),
        "by_runtime_version": _safe_call("containers_by_runtime", kube.find_containers_by_runtime_version, **kwargs),
        "managed_vs_unmanaged": _safe_call("managed_containers", kube.group_managed_containers, **kwargs),
        "vulnerable_count":   _safe_call("vulnerable_containers", kube.read_vulnerable_container_count, **kwargs),
        "zero_day_affected":  _safe_call("zeroday_containers",   kube.read_zero_day_affected_counts),
        "sensor_coverage":    _safe_call("sensor_coverage",      kube.read_sensor_coverage, **kwargs),
    }


def collect_running_images(kube: KubernetesProtection) -> list:
    print("  → running images …")
    return _paginate_combined(kube.read_running_images)


def collect_deployments(kube: KubernetesProtection, filter_str: str) -> list:
    print("  → deployments (combined) …")
    return _paginate_combined(kube.read_deployments_combined, filter_str=filter_str)


def collect_deployment_summary(kube: KubernetesProtection) -> dict:
    print("  → deployment summary …")
    return {
        "by_date_range": _safe_call("deployments_by_date", kube.read_deployment_counts_by_date_range),
        "total_count":   _safe_call("deployment_count",    kube.read_deployment_count),
    }


def collect_k8s_ioms(kube: KubernetesProtection) -> list:
    """Kubernetes Indicator of Misconfiguration (IOM) findings."""
    print("  → Kubernetes IOMs …")
    ids = _paginate_query(kube.search_ioms)
    if not ids:
        return []
    details = []
    for i in range(0, len(ids), 100):
        chunk = ids[i:i+100]
        result = _safe_call("iom_entities", kube.read_iom_entities, ids=chunk)
        if result:
            details.extend(result if isinstance(result, list) else [result])
    return details


def collect_k8s_iom_summary(kube: KubernetesProtection) -> dict:
    print("  → IOM summary counts …")
    return {
        "by_date_range": _safe_call("ioms_by_date",  kube.read_iom_count_by_date_range),
        "total_count":   _safe_call("iom_count",     kube.read_iom_count),
    }


def collect_enrichments(kube: KubernetesProtection,
                        clusters: list, containers: list,
                        pods: list, nodes: list) -> dict:
    """Pull enrichment data for a sample of each asset type (first 10)."""
    print("  → enrichments (clusters / containers / pods / nodes) …")

    def _enrich(label, method, ids, id_field):
        if not ids:
            return []
        sample = [a[id_field] for a in ids[:10] if id_field in a]
        if not sample:
            return []
        result = []
        for asset_id in sample:
            r = _safe_call(f"enrich_{label}", method, ids=[asset_id])
            if r:
                result.extend(r if isinstance(r, list) else [r])
        return result

    return {
        "clusters":   _enrich("cluster",   kube.read_cluster_enrichment,   clusters,   "cluster_id"),
        "containers": _enrich("container", kube.read_container_enrichment, containers, "container_id"),
        "pods":       _enrich("pod",       kube.read_pod_enrichment,       pods,        "pod_id"),
        "nodes":      _enrich("node",      kube.read_node_enrichment,      nodes,       "node_id"),
    }


def collect_cloud_accounts(kube: KubernetesProtection) -> dict:
    print("  → cloud accounts (AWS / Azure) …")
    aws_accounts   = _safe_call("k8s_aws_accounts",   kube.get_aws_accounts)   or []
    azure_accounts = _safe_call("k8s_azure_accounts", kube.list_azure_accounts) or []
    return {
        "aws":   aws_accounts if isinstance(aws_accounts, list) else [aws_accounts],
        "azure": azure_accounts if isinstance(azure_accounts, list) else [azure_accounts],
    }


def collect_cloud_clusters(kube: KubernetesProtection) -> Any:
    print("  → cloud clusters (managed) …")
    return _safe_call("cloud_clusters", kube.get_cloud_clusters)


# ---------------------------------------------------------------------------
# Container Images
# ---------------------------------------------------------------------------

def collect_images(ci: ContainerImages, kube: KubernetesProtection, filter_str: str) -> dict:
    print("  → container images …")
    kwargs = {"filter": filter_str} if filter_str else {}
    combined     = _paginate_combined(ci.get_combined_images, filter_str=filter_str)
    base_images  = _safe_call("base_images",        ci.get_combined_base_images, **kwargs) or []
    vuln_sorted  = _safe_call("images_by_vuln",     ci.get_combined_images_by_vulnerability_count, **kwargs) or []
    # These three methods live on KubernetesProtection, not ContainerImages
    by_state     = _safe_call("images_by_state",    kube.read_images_by_state)
    by_most_used = _safe_call("images_most_used",   kube.read_images_by_most_used, **kwargs)
    distinct_cnt = _safe_call("distinct_img_count", kube.read_distinct_image_count, **kwargs)
    return {
        "images":                        combined,
        "base_images":                   base_images if isinstance(base_images, list) else [base_images],
        "images_by_vulnerability_count": vuln_sorted if isinstance(vuln_sorted, list) else [vuln_sorted],
        "images_by_state":               by_state,
        "images_by_most_used":           by_most_used,
        "distinct_image_count":          distinct_cnt,
        "aggregate_count_by_state":      _safe_call("img_count_by_state",  ci.aggregate_count_by_state),
        "aggregate_count_by_base_os":    _safe_call("img_count_by_os",     ci.aggregate_count_by_base_os),
        "aggregate_count_total":         _safe_call("img_count",           ci.aggregate_count),
        "assessment_history":            _safe_call("img_assess_history",  ci.aggregate_assessment_history),
    }


# ---------------------------------------------------------------------------
# Container Vulnerabilities
# ---------------------------------------------------------------------------

def collect_vulnerabilities(cv: ContainerVulnerabilities, filter_str: str) -> dict:
    print("  → container vulnerabilities …")
    kwargs = {"filter": filter_str} if filter_str else {}
    return {
        "combined_vulnerabilities":  _paginate_combined(cv.read_combined_vulnerabilities, filter_str=filter_str),
        "count_total":               _safe_call("vuln_count",           cv.read_vulnerability_count, **kwargs),
        "by_active_exploited":       _safe_call("vuln_by_exploited",    cv.read_vulnerability_counts_by_active_exploited, **kwargs),
        "by_cps_rating":             _safe_call("vuln_by_cps",         cv.read_vulnerability_counts_by_cps_rating, **kwargs),
        "by_cvss_score":             _safe_call("vuln_by_cvss",        cv.read_vulnerability_counts_by_cvss_score, **kwargs),
        "by_severity":               _safe_call("vuln_by_severity",    cv.read_vulnerability_counts_by_severity, **kwargs),
        "by_image_count":            _safe_call("vulns_by_img_count",  cv.read_vulnerabilities_by_count, **kwargs),
        "by_pub_date":               _safe_call("vulns_by_pub_date",   cv.read_vulnerabilities_by_pub_date, **kwargs),
    }


# ---------------------------------------------------------------------------
# Container Detections
# ---------------------------------------------------------------------------

def collect_detections(cd: ContainerDetections, kube: KubernetesProtection, filter_str: str) -> dict:
    print("  → container detections …")
    kwargs = {"filter": filter_str} if filter_str else {}
    return {
        "runtime_detections":  _paginate_combined(cd.read_combined_detections, filter_str=filter_str),
        "count_total":         _safe_call("det_count",       cd.read_detections_count, **kwargs),
        "by_severity":         _safe_call("det_by_severity", cd.read_detection_counts_by_severity, **kwargs),
        "by_type":             _safe_call("det_by_type",     cd.read_detections_count_by_type, **kwargs),
        "by_date_range_kube":  _safe_call("det_by_date",     kube.read_detections_count_by_date, **kwargs),
    }


# ---------------------------------------------------------------------------
# Container Packages (SBOM)
# ---------------------------------------------------------------------------

def collect_packages(cp: ContainerPackages, filter_str: str) -> dict:
    print("  → container packages (SBOM) …")
    kwargs = {"filter": filter_str} if filter_str else {}
    return {
        "packages":          _paginate_combined(cp.read_combined, filter_str=filter_str),
        "by_image_count":    _safe_call("pkgs_by_img_count",   cp.read_packages_by_image_count, **kwargs),
        "zero_day_counts":   _safe_call("pkg_zero_day",        cp.read_zero_day_counts, **kwargs),
        "fixable_vuln_count": _safe_call("pkg_fixable_vulns", cp.read_fixable_vuln_count, **kwargs),
        "total_vuln_count":  _safe_call("pkg_vuln_count",     cp.read_vuln_count, **kwargs),
    }


# ---------------------------------------------------------------------------
# Container Image Compliance (CIS benchmarks)
# ---------------------------------------------------------------------------

def collect_image_compliance(cic: ContainerImageCompliance) -> dict:
    print("  → container image compliance …")
    return {
        "cluster_assessments":               _safe_call("cic_clusters",        cic.aggregate_cluster_assessments),
        "image_assessments":                 _safe_call("cic_images",          cic.aggregate_image_assessments),
        "rules_assessments":                 _safe_call("cic_rules",           cic.aggregate_rules_assessments),
        "failed_containers_by_rules":        _safe_call("cic_fail_containers", cic.aggregate_failed_containers_by_rules),
        "failed_containers_count_by_severity": _safe_call("cic_fail_cont_sev", cic.aggregate_failed_containers_count_by_severity),
        "failed_images_by_rules":            _safe_call("cic_fail_images",     cic.aggregate_failed_images_by_rules),
        "failed_images_count_by_severity":   _safe_call("cic_fail_img_sev",   cic.aggregate_failed_images_count_by_severity),
        "failed_rules_by_clusters":          _safe_call("cic_fail_rules_cls",  cic.aggregate_failed_rules_by_clusters),
        "failed_rules_by_image":             _safe_call("cic_fail_rules_img",  cic.aggregate_failed_rules_by_image),
        "failed_rules_count_by_severity":    _safe_call("cic_fail_rules_sev",  cic.aggregate_failed_rules_count_by_severity),
        "rules_by_status":                   _safe_call("cic_rules_status",    cic.aggregate_rules_by_status),
    }


# ---------------------------------------------------------------------------
# Kubernetes Container Compliance
# ---------------------------------------------------------------------------

def collect_k8s_compliance(kcc: KubernetesContainerCompliance) -> dict:
    print("  → Kubernetes container compliance …")
    return {
        "by_cluster":        _safe_call("kcc_by_cluster",    kcc.aggregate_assessments_by_cluster),
        "by_asset_type":     _safe_call("kcc_by_asset",      kcc.aggregate_compliance_by_asset_type),
        "by_cluster_type":   _safe_call("kcc_by_cls_type",   kcc.aggregate_compliance_by_cluster_type),
        "by_framework":      _safe_call("kcc_by_framework",  kcc.aggregate_compliance_by_framework),
        "failed_rules_by_clusters": _safe_call("kcc_fail_rules", kcc.aggregate_failed_rules_by_clusters),
        "assessments_by_rules":     _safe_call("kcc_rules",      kcc.aggregate_assessments_by_rules),
        "top_failed_images":        _safe_call("kcc_top_fail",   kcc.aggregate_top_failed_images),
    }


# ---------------------------------------------------------------------------
# FalconContainer (registry scanning)
# ---------------------------------------------------------------------------

def collect_falcon_container(fc: FalconContainer) -> dict:
    print("  → Falcon Container registry assessments …")
    registries = _safe_call("registries", fc.read_registry_entities) or []
    images      = _safe_call("fc_images", fc.get_combined_images) or []
    return {
        "registries":       registries if isinstance(registries, list) else [registries],
        "scanned_images":   images if isinstance(images, list) else [images],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SECTIONS = [
    "cluster_summary", "clusters", "nodes", "node_summary",
    "namespaces", "pods", "pod_summary", "containers",
    "container_summary", "running_images", "deployments",
    "deployment_summary", "ioms", "iom_summary", "enrichments",
    "cloud_accounts", "cloud_clusters",
    "images", "vulns", "detections", "packages",
    "image_compliance", "k8s_compliance", "falcon_container",
]


def build_auth(cloud: str) -> OAuth2:
    client_id     = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set.")

    base_url_map = {
        "us-1":  "https://api.crowdstrike.com",
        "us-2":  "https://api.us-2.crowdstrike.com",
        "eu-1":  "https://api.eu-1.crowdstrike.com",
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
                        help="Output JSON file path (default: auto-timestamped)")
    parser.add_argument("--filter",  default="",
                        help="FQL filter applied to all supporting endpoints")
    parser.add_argument("--cloud",   default=os.getenv("FALCON_CLOUD", "us-1"),
                        help="Falcon cloud region (default: us-1)")
    parser.add_argument("--section", default=",".join(SECTIONS),
                        help=f"Comma-separated sections to collect. Available: {', '.join(SECTIONS)}")
    args = parser.parse_args()

    requested = {s.strip() for s in args.section.split(",")}
    unknown = requested - set(SECTIONS)
    if unknown:
        raise SystemExit(f"Unknown section(s): {unknown}\nAvailable: {', '.join(SECTIONS)}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_file = args.output or f"falcon_k8s_inventory_{ts}.json"

    print(f"\n{'='*60}")
    print("  CrowdStrike Falcon — K8s & Container Asset Inventory")
    print(f"  Cloud: {args.cloud}  |  Timestamp: {ts}")
    print(f"  Output: {output_file}")
    print(f"{'='*60}\n")

    # --- Auth ---
    print("[1/9] Authenticating …")
    auth = build_auth(args.cloud)

    def svc(cls):
        return cls(auth_object=auth)

    # --- Instantiate service classes ---
    kube = svc(KubernetesProtection)
    ci   = svc(ContainerImages)
    cv   = svc(ContainerVulnerabilities)
    cd   = svc(ContainerDetections)
    cp   = svc(ContainerPackages)
    cic  = svc(ContainerImageCompliance)
    kcc  = svc(KubernetesContainerCompliance)
    fc   = svc(FalconContainer)

    inventory: dict = {
        "_meta": {
            "generated_at":  ts,
            "cloud":         args.cloud,
            "fql_filter":    args.filter,
            "sections":      sorted(requested),
        }
    }

    # -----------------------------------------------------------------------
    # Kubernetes Protection
    # -----------------------------------------------------------------------
    print("\n[2/9] Kubernetes Protection API …")

    clusters    = []
    nodes_list  = []
    pods_list   = []
    conts_list  = []

    if "cluster_summary"    in requested: inventory["cluster_summary"]    = collect_cluster_summary(kube)
    if "clusters"           in requested:
        clusters = collect_clusters(kube, args.filter)
        inventory["clusters"] = clusters
    if "nodes"              in requested:
        nodes_list = collect_nodes(kube, args.filter)
        inventory["nodes"] = nodes_list
    if "node_summary"       in requested: inventory["node_summary"]       = collect_node_summary(kube)
    if "namespaces"         in requested: inventory["namespaces"]         = collect_namespaces(kube)
    if "pods"               in requested:
        pods_list = collect_pods(kube, args.filter)
        inventory["pods"] = pods_list
    if "pod_summary"        in requested: inventory["pod_summary"]        = collect_pod_summary(kube)
    if "containers"         in requested:
        conts_list = collect_containers(kube, args.filter)
        inventory["containers"] = conts_list
    if "container_summary"  in requested: inventory["container_summary"]  = collect_container_summary(kube, args.filter)
    if "running_images"     in requested: inventory["running_images"]     = collect_running_images(kube)
    if "deployments"        in requested: inventory["deployments"]        = collect_deployments(kube, args.filter)
    if "deployment_summary" in requested: inventory["deployment_summary"] = collect_deployment_summary(kube)
    if "ioms"               in requested: inventory["ioms"]               = collect_k8s_ioms(kube)
    if "iom_summary"        in requested: inventory["iom_summary"]        = collect_k8s_iom_summary(kube)
    if "enrichments"        in requested:
        inventory["enrichments"] = collect_enrichments(kube, clusters, conts_list, pods_list, nodes_list)
    if "cloud_accounts"     in requested: inventory["cloud_accounts"]     = collect_cloud_accounts(kube)
    if "cloud_clusters"     in requested: inventory["cloud_clusters"]     = collect_cloud_clusters(kube)

    # -----------------------------------------------------------------------
    # Container Images
    # -----------------------------------------------------------------------
    print("\n[3/9] Container Images API …")
    if "images" in requested:
        inventory["images"] = collect_images(ci, kube, args.filter)

    # -----------------------------------------------------------------------
    # Container Vulnerabilities
    # -----------------------------------------------------------------------
    print("\n[4/9] Container Vulnerabilities API …")
    if "vulns" in requested:
        inventory["vulnerabilities"] = collect_vulnerabilities(cv, args.filter)

    # -----------------------------------------------------------------------
    # Container Detections
    # -----------------------------------------------------------------------
    print("\n[5/9] Container Detections API …")
    if "detections" in requested:
        inventory["detections"] = collect_detections(cd, kube, args.filter)

    # -----------------------------------------------------------------------
    # Container Packages (SBOM)
    # -----------------------------------------------------------------------
    print("\n[6/9] Container Packages (SBOM) API …")
    if "packages" in requested:
        inventory["packages"] = collect_packages(cp, args.filter)

    # -----------------------------------------------------------------------
    # Container Image Compliance
    # -----------------------------------------------------------------------
    print("\n[7/9] Container Image Compliance API …")
    if "image_compliance" in requested:
        inventory["image_compliance"] = collect_image_compliance(cic)

    # -----------------------------------------------------------------------
    # Kubernetes Container Compliance
    # -----------------------------------------------------------------------
    print("\n[8/9] Kubernetes Container Compliance API …")
    if "k8s_compliance" in requested:
        inventory["k8s_compliance"] = collect_k8s_compliance(kcc)

    # -----------------------------------------------------------------------
    # FalconContainer (registry scanning)
    # -----------------------------------------------------------------------
    print("\n[9/9] Falcon Container Registry API …")
    if "falcon_container" in requested:
        inventory["falcon_container"] = collect_falcon_container(fc)

    # -----------------------------------------------------------------------
    # Summary + write output
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print("  INVENTORY SUMMARY")
    print(f"{'='*60}")

    def _count(val) -> str:
        if isinstance(val, list):    return str(len(val))
        if isinstance(val, dict):    return f"{len(val)} keys"
        return "—"

    for section, data in inventory.items():
        if section == "_meta":
            continue
        print(f"  {section:<30} {_count(data)}")

    print(f"\n  Writing output to: {output_file}")
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
