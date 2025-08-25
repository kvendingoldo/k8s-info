import argparse
import importlib.resources
import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict

from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from .utils import parse_memory_k8s
from .reporting import render_html_report, render_pdf_report

# Constants
HTML_TEMPLATE_RESOURCE = "html_template.html"
HTML_TEMPLATE_PACKAGE = "k8s_info.resources"


def get_timestamp_info() -> Dict[str, str]:
    """Get detailed timestamp information for the report."""
    now = datetime.now()
    return {
        "iso_format": now.isoformat(),
        "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "timezone": now.strftime("%Z"),
        "unix_timestamp": str(int(now.timestamp()))
    }


def check_auth_context() -> Dict[str, str]:
    """Check and return current authentication context information."""
    logger = logging.getLogger("k8s-info")
    auth_info = {}

    try:
        # Try to get current user info
        v1 = client.CoreV1Api()
        auth_info["api_server"] = v1.api_client.configuration.host

        # Try to get current user from the API
        try:
            user_info = v1.api_client.call_api(
                "/apis/authentication.k8s.io/v1/userinfo",
                "GET",
                response_type="object"
            )
            if user_info and len(user_info) > 0:
                auth_info["current_user"] = user_info[0].get(
                    "username", "unknown")
                auth_info["user_groups"] = user_info[0].get("groups", [])
            else:
                auth_info["current_user"] = "unknown"
        except Exception as e:
            auth_info["current_user"] = "could_not_determine"
            auth_info["auth_error"] = str(e)

    except Exception as e:
        auth_info["error"] = str(e)

    return auth_info


def test_resource_access(api_version: str, resource: str, kind: str) -> Dict[str, Any]:
    """Test if we can access a specific resource before trying to count it."""
    logger = logging.getLogger("k8s-info")
    result = {
        "accessible": False,
        "error": None,
        "resource_info": None
    }

    try:
        dyn_client = DynamicClient(client.ApiClient())

        # Try to get the resource definition first
        try:
            resource_obj = dyn_client.resources.get(
                api_version=api_version,
                resource=resource
            )
            result["resource_info"] = {
                "api_version": resource_obj.api_version,
                "kind": resource_obj.kind,
                "namespaced": getattr(resource_obj, 'namespaced', None)
            }

            # Try a simple list operation with limit=1 to test access
            items = resource_obj.list(limit=1)
            result["accessible"] = True
            logger.debug(f"Resource {kind} ({api_version}) is accessible")

        except Exception as e:
            result["error"] = str(e)
            logger.debug(
                f"Resource {kind} ({api_version}) not accessible: {e}")

    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"Error testing resource {kind} ({api_version}): {e}")

    return result


def sort_versions(versions: list) -> list:
    """Sort version numbers properly, handling both numeric and semantic versions."""
    def version_key(version):
        try:
            # Try to parse as numeric version first
            return [int(x) for x in version.split('.')]
        except (ValueError, AttributeError):
            # If not numeric, use string comparison
            return version

    try:
        return sorted(versions, key=version_key)
    except Exception:
        # Fallback to string sorting if all else fails
        return sorted(versions)


def try_common_crds_directly(dyn_client: DynamicClient) -> Dict[str, int]:
    """Try to access common CRDs directly even when API discovery fails."""
    logger = logging.getLogger("k8s-info")
    logger.info("Trying to access common CRDs directly...")

    common_crds = {
        # Strimzi Kafka resources
        ("kafka.strimzi.io/v1beta2", "kafkas"): "Kafka",
        ("kafka.strimzi.io/v1beta2", "kafkaconnects"): "KafkaConnect",
        ("kafka.strimzi.io/v1beta2", "kafkaconnectors"): "KafkaConnector",
        ("kafka.strimzi.io/v1beta2", "kafkamirrormakers"): "KafkaMirrorMaker",
        ("kafka.strimzi.io/v1beta2", "kafkamirrormaker2s"): "KafkaMirrorMaker2",
        ("kafka.strimzi.io/v1beta2", "kafkarebalances"): "KafkaRebalance",
        ("kafka.strimzi.io/v1beta2", "kafkausers"): "KafkaUser",
        ("kafka.strimzi.io/v1beta2", "kafkatopics"): "KafkaTopic",
        ("kafka.strimzi.io/v1beta2", "kafkausers"): "KafkaUser",

        # Prometheus/Alertmanager resources
        ("monitoring.coreos.com/v1", "alertmanagers"): "Alertmanager",
        ("monitoring.coreos.com/v1", "podmonitors"): "PodMonitor",
        ("monitoring.coreos.com/v1", "prometheuses"): "Prometheus",
        ("monitoring.coreos.com/v1", "prometheusrules"): "PrometheusRule",
        ("monitoring.coreos.com/v1", "servicemonitors"): "ServiceMonitor",
        ("monitoring.coreos.com/v1", "thanosrulers"): "ThanosRuler",

        # Grafana resources
        ("monitoring.grafana.com/v1alpha1", "alertmanagerconfigs"): "AlertmanagerConfig",
        ("monitoring.grafana.com/v1alpha1", "grafanaagents"): "GrafanaAgent",
        ("monitoring.grafana.com/v1alpha1", "integrations"): "Integration",
        ("monitoring.grafana.com/v1alpha1", "logforwarders"): "LogForwarder",
        ("monitoring.grafana.com/v1alpha1", "podlogs"): "PodLogs",
        ("monitoring.grafana.com/v1alpha1", "scrapers"): "Scraper",

        # Istio resources
        ("networking.istio.io/v1beta1", "virtualservices"): "VirtualService",
        ("networking.istio.io/v1beta1", "destinationrules"): "DestinationRule",
        ("networking.istio.io/v1beta1", "gateways"): "Gateway",
        ("networking.istio.io/v1beta1", "sidecars"): "Sidecar",

        # Cert-manager resources
        ("cert-manager.io/v1", "certificates"): "Certificate",
        ("cert-manager.io/v1", "certificaterequests"): "CertificateRequest",
        ("cert-manager.io/v1", "clusterissuers"): "ClusterIssuer",
        ("cert-manager.io/v1", "issuers"): "Issuer",
        ("cert-manager.io/v1", "orders"): "Order",

        # ArgoCD resources
        ("argoproj.io/v1alpha1", "applications"): "Application",
        ("argoproj.io/v1alpha1", "applicationsets"): "ApplicationSet",
        ("argoproj.io/v1alpha1", "argocds"): "ArgoCD",
        ("argoproj.io/v1alpha1", "clusters"): "Cluster",
        ("argoproj.io/v1alpha1", "repositories"): "Repository",

        # Flux resources
        ("helm.toolkit.fluxcd.io/v2beta1", "helmreleases"): "HelmRelease",
        ("source.toolkit.fluxcd.io/v1beta2", "gitrepositories"): "GitRepository",
        ("source.toolkit.fluxcd.io/v1beta2", "helmrepositories"): "HelmRepository",
        ("source.toolkit.fluxcd.io/v1beta2", "buckets"): "Bucket",
        ("source.toolkit.fluxcd.io/v1beta2", "ocirepositories"): "OCIRepository",
    }

    direct_crd_counts = {}

    for (api_version, resource_plural), kind in common_crds.items():
        try:
            logger.debug(
                f"Trying to access {kind} ({api_version}) directly...")
            resource = dyn_client.resources.get(
                api_version=api_version, resource=resource_plural)

            if hasattr(resource, 'list'):
                items = resource.list().items
                direct_crd_counts[f"{kind}.{api_version}"] = len(items)
                logger.info(
                    f"Successfully counted {len(items)} {kind} ({api_version})")
            else:
                logger.debug(
                    f"Resource {kind} ({api_version}) has no 'list' method")

        except Exception as e:
            error_msg = str(e)
            if "403" in error_msg or "Forbidden" in error_msg:
                logger.debug(
                    f"Access forbidden for {kind} ({api_version}): {e}")
            elif "no attribute 'resource'" in error_msg.lower():
                logger.debug(
                    f"DynamicClient issue for {kind} ({api_version}): {e}")
            else:
                logger.debug(f"Could not access {kind} ({api_version}): {e}")

    return direct_crd_counts


def count_common_resources() -> Dict[str, Any]:
    """Count common Kubernetes resources using the standard client APIs."""
    logger = logging.getLogger("k8s-info")
    logger.info("Counting common Kubernetes resources...")

    common_counts = {}

    try:
        # Core V1 API resources
        v1 = client.CoreV1Api()

        # Count Pods
        try:
            pods = v1.list_pod_for_all_namespaces()
            common_counts["pods"] = len(pods.items)
            logger.info(f"Found {len(pods.items)} pods")
        except Exception as e:
            logger.warning(f"Could not count pods: {e}")
            common_counts["pods_error"] = str(e)

        # Count Services
        try:
            services = v1.list_service_for_all_namespaces()
            common_counts["services"] = len(services.items)
            logger.info(f"Found {len(services.items)} services")
        except Exception as e:
            logger.warning(f"Could not count services: {e}")
            common_counts["services_error"] = str(e)

        # Count ConfigMaps
        try:
            configmaps = v1.list_config_map_for_all_namespaces()
            common_counts["configmaps"] = len(configmaps.items)
            logger.info(f"Found {len(configmaps.items)} configmaps")
        except Exception as e:
            logger.warning(f"Could not count configmaps: {e}")
            common_counts["configmaps_error"] = str(e)

        # Count Secrets
        try:
            secrets = v1.list_secret_for_all_namespaces()
            common_counts["secrets"] = len(secrets.items)
            logger.info(f"Found {len(secrets.items)} secrets")
        except Exception as e:
            logger.warning(f"Could not count secrets: {e}")
            common_counts["secrets_error"] = str(e)

        # Count PersistentVolumeClaims
        try:
            pvcs = v1.list_persistent_volume_claim_for_all_namespaces()
            common_counts["persistentvolumeclaims"] = len(pvcs.items)
            logger.info(f"Found {len(pvcs.items)} persistent volume claims")
        except Exception as e:
            logger.warning(f"Could not count persistent volume claims: {e}")
            common_counts["persistentvolumeclaims_error"] = str(e)

        # Count Namespaces
        try:
            namespaces = v1.list_namespace()
            common_counts["namespaces"] = len(namespaces.items)
            logger.info(f"Found {len(namespaces.items)} namespaces")
        except Exception as e:
            logger.warning(f"Could not count namespaces: {e}")
            common_counts["namespaces_error"] = str(e)

        # Count Nodes
        try:
            nodes = v1.list_node()
            common_counts["nodes"] = len(nodes.items)
            logger.info(f"Found {len(nodes.items)} nodes")
        except Exception as e:
            logger.warning(f"Could not count nodes: {e}")
            common_counts["nodes_error"] = str(e)

        # Count Events
        try:
            events = v1.list_event_for_all_namespaces()
            common_counts["events"] = len(events.items)
            logger.info(f"Found {len(events.items)} events")
        except Exception as e:
            logger.warning(f"Could not count events: {e}")
            common_counts["events_error"] = str(e)

    except Exception as e:
        logger.error(f"Error setting up Core V1 API: {e}")
        common_counts["core_api_error"] = str(e)

    try:
        # Apps V1 API resources
        apps_v1 = client.AppsV1Api()

        # Count Deployments
        try:
            deployments = apps_v1.list_deployment_for_all_namespaces()
            common_counts["deployments"] = len(deployments.items)
            logger.info(f"Found {len(deployments.items)} deployments")
        except Exception as e:
            logger.warning(f"Could not count deployments: {e}")
            common_counts["deployments_error"] = str(e)

        # Count StatefulSets
        try:
            statefulsets = apps_v1.list_stateful_set_for_all_namespaces()
            common_counts["statefulsets"] = len(statefulsets.items)
            logger.info(f"Found {len(statefulsets.items)} statefulsets")
        except Exception as e:
            logger.warning(f"Could not count statefulsets: {e}")
            common_counts["statefulsets_error"] = str(e)

        # Count DaemonSets
        try:
            daemonsets = apps_v1.list_daemon_set_for_all_namespaces()
            common_counts["daemonsets"] = len(daemonsets.items)
            logger.info(f"Found {len(daemonsets.items)} daemonsets")
        except Exception as e:
            logger.warning(f"Could not count daemonsets: {e}")
            common_counts["daemonsets_error"] = str(e)

        # Count ReplicaSets
        try:
            replicasets = apps_v1.list_replica_set_for_all_namespaces()
            common_counts["replicasets"] = len(replicasets.items)
            logger.info(f"Found {len(replicasets.items)} replicasets")
        except Exception as e:
            logger.warning(f"Could not count replicasets: {e}")
            common_counts["replicasets_error"] = str(e)

    except Exception as e:
        logger.error(f"Error setting up Apps V1 API: {e}")
        common_counts["apps_api_error"] = str(e)

    try:
        # Networking V1 API resources
        networking_v1 = client.NetworkingV1Api()

        # Count Ingresses
        try:
            ingresses = networking_v1.list_ingress_for_all_namespaces()
            common_counts["ingresses"] = len(ingresses.items)
            logger.info(f"Found {len(ingresses.items)} ingresses")
        except Exception as e:
            logger.warning(f"Could not count ingresses: {e}")
            common_counts["ingresses_error"] = str(e)

        # Count NetworkPolicies
        try:
            networkpolicies = networking_v1.list_network_policy_for_all_namespaces()
            common_counts["networkpolicies"] = len(networkpolicies.items)
            logger.info(f"Found {len(networkpolicies.items)} network policies")
        except Exception as e:
            logger.warning(f"Could not count network policies: {e}")
            common_counts["networkpolicies_error"] = str(e)

    except Exception as e:
        logger.error(f"Error setting up Networking V1 API: {e}")
        common_counts["networking_api_error"] = str(e)

    try:
        # Storage V1 API resources
        storage_v1 = client.StorageV1Api()

        # Count StorageClasses
        try:
            storageclasses = storage_v1.list_storage_class()
            common_counts["storageclasses"] = len(storageclasses.items)
            logger.info(f"Found {len(storageclasses.items)} storage classes")
        except Exception as e:
            logger.warning(f"Could not count storage classes: {e}")
            common_counts["storageclasses_error"] = str(e)

    except Exception as e:
        logger.error(f"Error setting up Storage V1 API: {e}")
        common_counts["storage_api_error"] = str(e)

    try:
        # RBAC V1 API resources
        rbac_v1 = client.RbacAuthorizationV1Api()

        # Count Roles
        try:
            roles = rbac_v1.list_role_for_all_namespaces()
            common_counts["roles"] = len(roles.items)
            logger.info(f"Found {len(roles.items)} roles")
        except Exception as e:
            logger.warning(f"Could not count roles: {e}")
            common_counts["roles_error"] = str(e)

        # Count RoleBindings
        try:
            rolebindings = rbac_v1.list_role_binding_for_all_namespaces()
            common_counts["rolebindings"] = len(rolebindings.items)
            logger.info(f"Found {len(rolebindings.items)} role bindings")
        except Exception as e:
            logger.warning(f"Could not count role bindings: {e}")
            common_counts["rolebindings_error"] = str(e)

        # Count ClusterRoles
        try:
            clusterroles = rbac_v1.list_cluster_role()
            common_counts["clusterroles"] = len(clusterroles.items)
            logger.info(f"Found {len(clusterroles.items)} cluster roles")
        except Exception as e:
            logger.warning(f"Could not count cluster roles: {e}")
            common_counts["clusterroles_error"] = str(e)

        # Count ClusterRoleBindings
        try:
            clusterrolebindings = rbac_v1.list_cluster_role_binding()
            common_counts["clusterrolebindings"] = len(
                clusterrolebindings.items)
            logger.info(
                f"Found {len(clusterrolebindings.items)} cluster role bindings")
        except Exception as e:
            logger.warning(f"Could not count cluster role bindings: {e}")
            common_counts["clusterrolebindings_error"] = str(e)

    except Exception as e:
        logger.error(f"Error setting up RBAC V1 API: {e}")
        common_counts["rbac_api_error"] = str(e)

    logger.info("Common resource counting complete.")
    return common_counts


def gather_resource_counts(args) -> Dict[str, Any]:
    """Dynamically discover and count all resources, including CRDs."""
    logger = logging.getLogger("k8s-info")
    logger.info("Starting dynamic resource discovery and counting...")
    counts = {}
    crd_counts = {}
    k8s_client = client.ApiClient()
    dyn_client = DynamicClient(k8s_client)
    discovery = client.ApisApi()
    try:
        logger.info("Fetching API groups and versions...")
        group_list = discovery.get_api_versions().groups
    except Exception as e:
        logger.error(f"Error fetching API groups: {e}")
        return {"error": str(e)}
    all_resources = [("core", "v1")]
    for group in group_list:
        for version in group.versions:
            all_resources.append((group.name, version.version))
    # Add CRDs from apiextensions.k8s.io if present
    try:
        logger.info("Discovering CRDs...")
        crds = dyn_client.resources.get(
            api_version="apiextensions.k8s.io/v1", kind="CustomResourceDefinition"
        )
        crd_list = crds.get().items
        logger.info(f"Found {len(crd_list)} CRDs.")

        # Process each CRD
        for crd in crd_list:
            try:
                # Extract CRD information
                group = crd["spec"]["group"]
                kind = crd["spec"]["names"]["kind"]
                plural = crd["spec"]["names"]["plural"]

                # Try each version of the CRD
                for version in crd["spec"]["versions"]:
                    api_version = f"{group}/{version['name']}"
                    try:
                        logger.debug(
                            f"Counting CRD {kind} ({api_version}) using plural '{plural}'...")

                        # Try to get the resource directly
                        resource = dyn_client.resources.get(
                            api_version=api_version, resource=plural)

                        # Check if the resource has a list method
                        if not hasattr(resource, 'list'):
                            logger.debug(
                                f"Skipping CRD {kind} ({api_version}) - resource object has no 'list' method")
                            continue

                        # List all instances from all namespaces
                        items = resource.list().items
                        crd_counts[f"{kind}.{group}/{version['name']}"] = len(
                            items)
                        logger.info(
                            f"Counted {len(items)} {kind} ({api_version})")

                    except Exception as e:
                        error_msg = str(e)
                        if "403" in error_msg or "Forbidden" in error_msg:
                            if args.skip_forbidden:
                                logger.debug(
                                    f"Skipping CRD {kind} ({api_version}) due to 403 Forbidden")
                            else:
                                logger.warning(
                                    f"Could not list CRD {kind} ({api_version}): {e}")
                        elif "no attribute 'resource'" in error_msg.lower():
                            logger.debug(
                                f"Skipping CRD {kind} ({api_version}) - DynamicClient resource issue: {e}")
                        elif "no attribute 'list'" in error_msg.lower():
                            if args.skip_unauthorized:
                                logger.debug(
                                    f"Skipping CRD {kind} ({api_version}) - resource object has no 'list' method")
                            else:
                                logger.warning(
                                    f"Could not list CRD {kind} ({api_version}) - resource object has no 'list' method")
                        else:
                            logger.warning(
                                f"Could not list CRD {kind} ({api_version}): {e}")

            except Exception as e:
                logger.warning(
                    f"Error processing CRD {crd.get('metadata', {}).get('name', 'unknown')}: {e}")
                continue

    except Exception as e:
        logger.warning(f"Could not fetch CRDs: {e}")

    # If we couldn't get CRDs through discovery, try direct access to common ones
    if not crd_counts:
        try:
            logger.info(
                "CRD discovery failed, trying direct access to common CRDs...")
            direct_crds = try_common_crds_directly(dyn_client)
            if direct_crds:
                crd_counts.update(direct_crds)
                logger.info(
                    f"Successfully accessed {len(direct_crds)} CRDs directly")
        except Exception as e:
            logger.warning(f"Direct CRD access also failed: {e}")

    # Skip the problematic API discovery phase that causes 403 errors
    # Instead, focus on CRDs and common resources we already know about
    logger.info("Skipping API discovery phase to avoid permission issues")
    if crd_counts:
        counts["crds"] = crd_counts

    # Add common resource counts
    try:
        logger.info("Adding common resource counts...")
        common_counts = count_common_resources()
        counts["common_resources"] = common_counts
    except Exception as e:
        logger.warning(f"Could not add common resource counts: {e}")
        counts["common_resources_error"] = str(e)

    logger.info("Resource discovery and counting complete.")
    return counts


def gather_k8s_info(args) -> Dict[str, Any]:
    """Gather all relevant Kubernetes cluster info."""
    logger = logging.getLogger("k8s-info")
    logger.info("Starting Kubernetes info gathering...")
    # Load kube config
    try:
        if args.context:
            config.load_kube_config(context=args.context)
            logger.info(
                f"Loaded kube config from local file with context: {args.context}")
        else:
            config.load_kube_config()
            logger.info("Loaded kube config from local file.")
    except Exception:
        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster kube config.")
        except Exception as e:
            logger.error(f"Failed to load kube config: {e}")
            sys.exit(1)

    result = {}

    # 1. Gather all k8s API versions
    api_versions = {}
    try:
        logger.info("Fetching API groups and versions...")
        apis = client.ApisApi().get_api_versions()
        api_versions["groups"] = {
            group.name: [v.version for v in group.versions] for group in apis.groups
        }
    except Exception as e:
        logger.error(f"Error fetching API groups: {e}")
        api_versions["groups_error"] = str(e)
    try:
        core_api = client.CoreApi()
        core_versions = core_api.get_api_versions()
        api_versions["core"] = core_versions.versions
    except Exception as e:
        logger.error(f"Error fetching core API versions: {e}")
        api_versions["core_error"] = str(e)
    result["api_versions"] = api_versions

    # 2. Gather k8s version
    try:
        logger.info("Fetching Kubernetes version info...")
        version_api = client.VersionApi()
        version = version_api.get_code()
        result["k8s_version"] = {
            "git_version": version.git_version,
            "git_commit": version.git_commit,
            "git_tree_state": version.git_tree_state,
            "build_date": version.build_date,
            "go_version": version.go_version,
            "compiler": version.compiler,
            "platform": version.platform,
        }
    except Exception as e:
        logger.error(f"Error fetching k8s version: {e}")
        result["k8s_version_error"] = str(e)

    # 3. Node info
    try:
        logger.info("Fetching node information...")
        v1 = client.CoreV1Api()
        nodes = v1.list_node().items
        node_list = []
        total_cpu = 0
        total_mem = 0
        for node in nodes:
            mem_raw = node.status.capacity.get("memory", "N/A")
            mem_mib = parse_memory_k8s(mem_raw)
            cpu_raw = node.status.capacity.get("cpu", "N/A")
            try:
                cpu_val = int(cpu_raw)
            except Exception:
                cpu_val = 0
            total_cpu += cpu_val
            try:
                total_mem += int(mem_mib)
            except Exception:
                pass
            node_list.append(
                {
                    "name": node.metadata.name,
                    "os_image": node.status.node_info.os_image,
                    "kubelet_version": node.status.node_info.kubelet_version,
                    "cpu": cpu_raw,
                    "memory_mib": mem_mib,
                }
            )
        result["nodes"] = {
            "count": len(nodes),
            "details": node_list,
            "total_cpu": total_cpu,
            "total_memory_mib": total_mem,
        }
        logger.info(f"Found {len(nodes)} nodes.")
    except Exception as e:
        logger.error(f"Error fetching node info: {e}")
        result["nodes_error"] = str(e)

    # 4. List all Docker images in the cluster (no count, just unique names)
    try:
        logger.info("Listing all Docker images in the cluster...")
        images = set()
        pods = v1.list_pod_for_all_namespaces().items
        for pod in pods:
            for container in pod.spec.containers:
                images.add(container.image)
            if pod.spec.init_containers:
                for container in pod.spec.init_containers:
                    images.add(container.image)
        result["docker_images"] = sorted(images)
        logger.info(
            f"Found {len(result['docker_images'])} unique Docker images.")
    except Exception as e:
        logger.error(f"Error fetching docker images: {e}")
        result["docker_images_error"] = str(e)

    # 5. Gather total resource counts
    try:
        logger.info(
            "Gathering resource counts for all resources (including CRDs)...")
        result["resource_counts"] = gather_resource_counts(args)
    except Exception as e:
        logger.error(f"Error fetching resource counts: {e}")
        result["resource_counts_error"] = str(e)

    # 6. Gather Helm chart information
    try:
        logger.info("Gathering Helm chart information...")
        result["helm_info"] = gather_helm_info()
    except Exception as e:
        logger.error(f"Error fetching Helm information: {e}")
        result["helm_info_error"] = str(e)

    # 7. Add timestamp information
    result["timestamp"] = get_timestamp_info()

    # 8. Add authentication context information
    try:
        logger.info("Checking authentication context...")
        result["auth_context"] = check_auth_context()
    except Exception as e:
        logger.warning(f"Could not check auth context: {e}")
        result["auth_context_error"] = str(e)

    logger.info("Kubernetes info gathering complete.")
    return result


def gather_helm_info() -> Dict[str, Any]:
    """Gather information about Helm releases and charts in the cluster."""
    logger = logging.getLogger("k8s-info")
    logger.info("Gathering Helm chart information...")

    helm_info = {
        "releases": [],
        "total_releases": 0,
        "chart_versions": {}
    }

    try:
        # Look for Helm releases in the cluster
        # Helm 3 stores releases as secrets with specific labels
        v1 = client.CoreV1Api()

        # Search for Helm release secrets
        helm_secrets = v1.list_secret_for_all_namespaces(
            label_selector="owner=helm"
        ).items

        for secret in helm_secrets:
            try:
                # Extract release name and namespace
                release_name = secret.metadata.name.replace(
                    "sh.helm.release.v1.", "")
                namespace = secret.metadata.namespace

                # Try to get chart version from labels or annotations
                chart_version = "unknown"
                chart_name = "unknown"

                if secret.metadata.labels:
                    if "chart" in secret.metadata.labels:
                        chart_name = secret.metadata.labels["chart"]
                    if "version" in secret.metadata.labels:
                        chart_version = secret.metadata.labels["version"]

                # Also check annotations for more details
                if secret.metadata.annotations:
                    if "meta.helm.sh/release-name" in secret.metadata.annotations:
                        release_name = secret.metadata.annotations["meta.helm.sh/release-name"]
                    if "meta.helm.sh/release-version" in secret.metadata.annotations:
                        chart_version = secret.metadata.annotations["meta.helm.sh/release-version"]

                release_info = {
                    "name": release_name,
                    "namespace": namespace,
                    "chart": chart_name,
                    "version": chart_version,
                    "status": "active"
                }

                helm_info["releases"].append(release_info)

                # Track chart versions
                if chart_name not in helm_info["chart_versions"]:
                    helm_info["chart_versions"][chart_name] = []
                if chart_version not in helm_info["chart_versions"][chart_name]:
                    helm_info["chart_versions"][chart_name].append(
                        chart_version)

            except Exception as e:
                logger.debug(
                    f"Could not parse Helm secret {secret.metadata.name}: {e}")
                continue

        # Also look for HelmRelease CRDs (Flux/ArgoCD style)
        try:
            dyn_client = DynamicClient(client.ApiClient())
            helm_releases = dyn_client.resources.get(
                api_version="helm.toolkit.fluxcd.io/v2beta1",
                kind="HelmRelease"
            )
            flux_releases = helm_releases.list().items

            for release in flux_releases:
                try:
                    release_name = release["metadata"]["name"]
                    namespace = release["metadata"]["namespace"]
                    chart_name = release["spec"]["chart"]["spec"]["chart"]
                    chart_version = release["spec"]["chart"]["spec"]["version"]

                    release_info = {
                        "name": release_name,
                        "namespace": namespace,
                        "chart": chart_name,
                        "version": chart_version,
                        "status": "flux"
                    }

                    helm_info["releases"].append(release_info)

                    if chart_name not in helm_info["chart_versions"]:
                        helm_info["chart_versions"][chart_name] = []
                    if chart_version not in helm_info["chart_versions"][chart_name]:
                        helm_info["chart_versions"][chart_name].append(
                            chart_version)

                except Exception as e:
                    logger.debug(
                        f"Could not parse Flux HelmRelease {release['metadata']['name']}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Could not fetch Flux HelmReleases: {e}")

            # Sort chart versions for better display
        for chart_name in helm_info["chart_versions"]:
            helm_info["chart_versions"][chart_name] = sort_versions(
                helm_info["chart_versions"][chart_name]
            )

        helm_info["total_releases"] = len(helm_info["releases"])
        logger.info(f"Found {helm_info['total_releases']} Helm releases.")

    except Exception as e:
        logger.warning(f"Could not gather Helm information: {e}")
        helm_info["error"] = str(e)

    return helm_info


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Gather Kubernetes cluster information.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["log", "json"],
        default="log",
        help="Output format: log (default) or json",
    )
    parser.add_argument(
        "-f", "--output-file", help="If set with -o json, save JSON output to this file."
    )
    parser.add_argument(
        "-H",
        "--html",
        nargs="?",
        const="report.html",
        help=("Optionally output a fancy HTML report to the given file (default: report.html)"),
    )
    parser.add_argument(
        "-P",
        "--pdf",
        nargs="?",
        const="report.pdf",
        help=("Optionally output a PDF report to the given file (default: report.pdf)"),
    )
    parser.add_argument(
        "--skip-forbidden",
        action="store_true",
        help="Skip resources that return 403 Forbidden errors instead of logging warnings",
    )
    parser.add_argument(
        "--skip-unauthorized",
        action="store_true",
        help="Skip resources that can't be accessed due to permission issues",
    )
    parser.add_argument(
        "--context",
        help="Specify the kubeconfig context to use",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logger = logging.getLogger("k8s-info")
    logger.info("Starting k8s-info CLI...")
    result = gather_k8s_info(args)
    if args.output == "json":
        json_str = json.dumps(result, indent=2)
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(json_str)
            logger.info(f"JSON output written to {args.output_file}")
            print(f"JSON output written to {args.output_file}")
        else:
            print(json_str)
    if args.html:
        render_html_report(result, args.html)
        print(f"HTML report written to {args.html}")
    if args.pdf:
        render_pdf_report(result, args.pdf)
        print(f"PDF report written to {args.pdf}")


if __name__ == "__main__":
    main()
