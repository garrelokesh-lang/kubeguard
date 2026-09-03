from kubernetes import client, config
def get_kubernetes_client():
    config.load_kube_config()
    return client.CoreV1Api()


def scan_pod_security():
    kubernetes_client = get_kubernetes_client()
    pods = kubernetes_client.list_pod_for_all_namespaces()

    findings = []

    for pod in pods.items:

        pod_security_context = pod.spec.security_context

        for container in pod.spec.containers:

            security_context = container.security_context

            # Check 1: Container running as root
            if (
                security_context
                and security_context.run_as_user == 0
            ):
                findings.append({
                    "rule_id": "SEC-001",
                    "severity": "HIGH",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "container": container.name,
                    "issue": "Container is configured to run as root",
                })

            # Check 2: Privileged container
            if (
                security_context
                and security_context.privileged is True
            ):
                findings.append({
                    "rule_id": "SEC-002",
                    "severity": "CRITICAL",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "container": container.name,
                    "issue": "Container is running in privileged mode",
                })

            # Check 3: Missing security context
            if security_context is None and pod_security_context is None:
                findings.append({
                    "rule_id": "SEC-003",
                    "severity": "MEDIUM",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "container": container.name,
                    "issue": "Container has no security context configured",
                })

    return findings