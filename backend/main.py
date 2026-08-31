from healing import heal_deployment
from fastapi import FastAPI
from kubernetes import client, config
from security import scan_pod_security

app = FastAPI(
    title="KubeGuard",
    description="Kubernetes Security, Monitoring and Self-Healing Platform",
    version="0.1.0",
)


def get_kubernetes_client():
    config.load_kube_config()
    return client.CoreV1Api()


@app.get("/")
def root():
    return {
        "name": "KubeGuard",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/cluster/pods")
def get_pods():
    kubernetes_client = get_kubernetes_client()
    pods = kubernetes_client.list_pod_for_all_namespaces()

    result = []

    for pod in pods.items:
        result.append({
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "status": pod.status.phase,
        })

    return {
        "count": len(result),
        "pods": result,
    }


@app.get("/cluster/health")
def cluster_health():
    kubernetes_client = get_kubernetes_client()
    pods = kubernetes_client.list_pod_for_all_namespaces()

    healthy = []
    unhealthy = []

    for pod in pods.items:

        restart_count = sum(
            container.restart_count or 0
            for container in (pod.status.container_statuses or [])
        )

        problems = []

        for container in (pod.status.container_statuses or []):

            if container.state:

                if container.state.waiting:
                    reason = container.state.waiting.reason

                    if reason:
                        problems.append(reason)

                if container.state.terminated:
                    reason = container.state.terminated.reason

                    if reason:
                        problems.append(reason)

        problems = list(set(problems))

        if pod.status.phase == "Failed":
            severity = "CRITICAL"

        elif any(
            problem in [
                "CrashLoopBackOff",
                "OOMKilled",
                "ImagePullBackOff",
                "ErrImagePull",
            ]
            for problem in problems
        ):
            severity = "HIGH"

        elif pod.status.phase == "Pending":
            severity = "MEDIUM"

        elif restart_count >= 5:
            severity = "HIGH"

        elif restart_count >= 3:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        pod_info = {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "status": pod.status.phase,
            "restarts": restart_count,
            "problems": problems,
            "severity": severity,
        }

        if pod.status.phase == "Running" and not problems:
            healthy.append(pod_info)
        else:
            unhealthy.append(pod_info)

    return {
        "total_pods": len(pods.items),
        "healthy": len(healthy),
        "unhealthy": len(unhealthy),
        "unhealthy_pods": unhealthy,
    }


@app.get("/security/scan")
def security_scan():
    findings = scan_pod_security()

    return {
        "total_findings": len(findings),
        "findings": findings,
    }


@app.post("/heal/{namespace}/{deployment_name}")
def heal(namespace: str, deployment_name: str):
     return heal_deployment(
         deployment_name=deployment_name,
         namespace=namespace,
     )