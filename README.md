# CrowdStrike Falcon Asset Inventory

Python scripts that pull a complete asset inventory from the CrowdStrike Falcon platform and render it as a self-contained HTML report. No dashboards, no UI — just structured JSON and a portable report file you can open anywhere.

---

## What It Produces

**`hosts_inventory.py`** collects:
- All managed hosts with platform, OS, sensor version, online state, and last check-in
- Hidden / Reduced Functionality Mode (RFM) devices
- Cloud hosts (AWS, Azure, GCP) with account and region breakdown
- Kubernetes pods running the Falcon sensor
- Discover assets — unmanaged devices, coverage gaps, unsupported IoT/network gear
- K8s cluster inventory including KAC and IAR deployment status per cluster

**`k8s_container_inventory.py`** collects (requires additional scopes):
- Kubernetes clusters, nodes, pods, namespaces, deployments
- Container images, vulnerability counts, SBOM packages
- Runtime detections, IOM findings, compliance results

**`generate_report.py`** takes the hosts inventory JSON and produces a single `.html` file with:
- Executive summary with sensor coverage gauges
- Sensor coverage analysis and unmanaged asset gap
- Managed host breakdown by platform, OS, product type, online status
- Cloud and Kubernetes coverage
- Container security coverage with KAC / IAR per-cluster status
- Unsupported asset inventory
- Prioritized recommendations
- Appendix with every unmanaged asset

---

## Requirements

**Python 3.8+** and one third-party package:

```bash
pip install crowdstrike-falconpy
```

`generate_report.py` uses only the Python standard library — no additional installs needed.

---

## API Client Setup

Create an API client in **Falcon console → Support & Resources → API Clients & Keys**.

### Required scopes for `hosts_inventory.py`

| Scope | Permission |
|---|---|
| Hosts | Read |
| Discover | Read |
| Kubernetes Protection | Read |

### Optional scopes (script skips gracefully if missing)

| Scope | Used for |
|---|---|
| Cloud Security Assets | Cloud asset inventory |
| CSPM Registration | Cloud account registration |
| Host Groups | Group membership |
| Zero Trust Assessment | ZTA scores |
| Sensor Update Policy | Policy membership |
| Prevention Policy | Policy membership |
| Device Control Policies | Policy membership |
| Response Policies | Policy membership |
| Firewall Policies | Policy membership |
| Sensor Download | Available sensor builds |
| Installation Tokens | Provisioning tokens |
| Spotlight Vulnerabilities | CVE exposure per host |
| Spotlight Evaluation Logic | Spotlight rule data |
| Device Content | Content state per device |

### Additional scopes for `k8s_container_inventory.py`

| Scope | Permission |
|---|---|
| Kubernetes Protection | Read |
| Container Images | Read |
| Container Vulnerabilities | Read |
| Container Detections | Read |
| Container Packages | Read |
| Container Image Compliance | Read |
| Kubernetes Container Compliance | Read |
| Falcon Container | Read |

403 responses are treated as "scope not available" — the script logs the skip and continues. No section will crash the run.

---

## Usage

### 1. Set credentials

```bash
export FALCON_CLIENT_ID=your_client_id
export FALCON_CLIENT_SECRET=your_client_secret
export FALCON_CLOUD=us-1        # optional — us-1, us-2, eu-1, us-gov-1
```

### 2. Run the inventory

```bash
python3 hosts_inventory.py
```

Outputs `falcon_hosts_inventory_<timestamp>.json` in the current directory. Runtime depends on fleet size — expect 5–15 minutes for thousands of hosts.

### 3. Generate the report

```bash
python3 generate_report.py falcon_hosts_inventory_<timestamp>.json
```

Outputs `falcon_asset_report_<timestamp>.html`. Open in any browser — no server required.

---

## Options

### `hosts_inventory.py`

```
--output FILE       Write JSON to FILE instead of auto-timestamped filename
--filter FQL        FQL filter applied to all supporting endpoints
                    Example: --filter "platform_name:'Windows'"
--cloud REGION      Falcon cloud region (default: us-1)
--section LIST      Comma-separated list of sections to collect
--login-history     Collect login history for hosts (slower)
--network-history   Collect network address history for hosts (slower)
```

**Available sections** (default sections marked with *):

```
hosts*                  All managed hosts
hidden_hosts*           Hidden / RFM devices
online_state*           Online/offline state per host
cloud_hosts*            Managed hosts in cloud providers
kubernetes_hosts*       Managed hosts running as K8s pods
discover_hosts*         All Discover assets (all entity types)
coverage_gaps*          Unmanaged + unsupported asset breakdown
k8s_nodes*              K8s clusters, nodes, KAC/IAR coverage
sensor_versions*        Available sensor builds
login_history           Per-host login history (slow)
network_history         Per-host network address history (slow)
discover_apps           Discovered applications
discover_accounts       Discovered accounts
discover_logins         Discover login events
host_groups             Host group membership
zta                     Zero Trust Assessment scores
sensor_update_policies  Sensor update policy membership
prevention_policies     Prevention policy membership
device_control_policies Device control policy membership
response_policies       Response policy membership
firewall_policies       Firewall policy membership
installation_tokens     Provisioning tokens
spotlight               CVE exposure per host
device_content          Content state per device
```

### `k8s_container_inventory.py`

```
--output FILE       Write JSON to FILE instead of auto-timestamped filename
--filter FQL        FQL filter applied to supporting endpoints
--cloud REGION      Falcon cloud region (default: us-1)
--section LIST      Comma-separated list of sections to collect
```

**Available sections:**

```
cluster_summary, clusters, nodes, node_summary,
namespaces, pods, pod_summary, containers, container_summary,
running_images, deployments, deployment_summary,
ioms, iom_summary, enrichments,
cloud_accounts, cloud_clusters,
images, vulns, detections, packages,
image_compliance, k8s_compliance, falcon_container
```

### `generate_report.py`

```bash
python3 generate_report.py                              # picks latest inventory JSON in current dir
python3 generate_report.py inventory.json               # specific input file
python3 generate_report.py inventory.json report.html   # specific input + output
```

---

## Output Files

| File | Description |
|---|---|
| `falcon_hosts_inventory_<ts>.json` | Raw inventory data, all sections |
| `falcon_asset_report_<ts>.html` | Self-contained HTML report (~850 KB) |
| `falcon_k8s_inventory_<ts>.json` | Raw K8s/container inventory |

The JSON files are the source of truth. The HTML report is generated from the hosts inventory JSON and can be regenerated at any time without re-querying the API.

---

## Notes

- Mobile devices (`product_type_desc:'Mobile'`) are excluded from managed and hidden host counts by default.
- The Discover API caps results at 10,000 per query (offset + limit ≤ 10,000). Environments with more than 10,000 unmanaged assets will be truncated at that limit.
- KAC/IAR cluster coverage data comes from the `agent_coverage` field on cluster records returned by `KubernetesProtection`. Clusters with no `agent_coverage` data have neither deployed.
