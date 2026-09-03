from pathlib import Path
from fastapi.responses import FileResponse
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from kubernetes import client, config

from healing import heal_deployment
from security import scan_pod_security


# How often KubeGuard checks deployments for known broken images
MONITOR_INTERVAL = 30


def get_kubernetes_client():
    config.load_kube_config()
    return client.CoreV1Api()


def check_and_heal_broken_deployments():
    """
    Check all Kubernetes deployments and automatically
    repair deployments using the known KubeGuard broken-image
    test pattern.
    """

    config.load_kube_config()
    apps_api = client.AppsV1Api()

    results = []

    deployments = apps_api.list_deployment_for_all_namespaces()

    for deployment in deployments.items:
        namespace = deployment.metadata.namespace
        name = deployment.metadata.name

        containers = deployment.spec.template.spec.containers or []

        for container in containers:
            image = container.image or ""

            if "does-not-exist-kubeguard" in image:
                print(
                    f"[KubeGuard] Broken deployment detected: "
                    f"{namespace}/{name}"
                )

                result = heal_deployment(
                    deployment_name=name,
                    namespace=namespace,
                )

                results.append(result)

    return results


async def monitoring_loop():
    """
    Background KubeGuard monitoring loop.

    Every 30 seconds it checks Kubernetes deployments
    and automatically heals deployments using the
    known broken-image pattern.
    """

    print(
        f"[KubeGuard] Continuous monitoring started "
        f"(interval: {MONITOR_INTERVAL}s)."
    )

    while True:
        try:
            results = await asyncio.to_thread(
                check_and_heal_broken_deployments
            )

            if results:
                print(
                    f"[KubeGuard] Automatic healing completed: "
                    f"{len(results)} deployment(s)"
                )

        except Exception as error:
            print(f"[KubeGuard] Monitoring error: {error}")

        await asyncio.sleep(MONITOR_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Start the background monitoring task when FastAPI starts.
    """

    monitor_task = asyncio.create_task(monitoring_loop())

    yield

    monitor_task.cancel()

    try:
        await monitor_task
    except asyncio.CancelledError:
        print("[KubeGuard] Continuous monitoring stopped.")


app = FastAPI(
    title="KubeGuard",
    description="Kubernetes Security, Monitoring and Self-Healing Platform",
    version="0.1.0",
    lifespan=lifespan,
)

@app.get("/dashboard")
def dashboard():
    dashboard_file = (
        Path(__file__).resolve().parent.parent
        / "frontend"
        / "index.html"
    )

    return FileResponse(dashboard_file)


# ---------------------------------------------------------
# ROOT
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "KubeGuard",
        "status": "running",
        "version": "0.1.0",
    }


# ---------------------------------------------------------
# APPLICATION HEALTH
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ---------------------------------------------------------
# CLUSTER PODS
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# CLUSTER HEALTH
# ---------------------------------------------------------

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

                # Container waiting state
                if container.state.waiting:
                    reason = container.state.waiting.reason

                    if reason:
                        problems.append(reason)

                # Container terminated state
                if container.state.terminated:
                    reason = container.state.terminated.reason

                    if reason:
                        problems.append(reason)

        # Remove duplicate problems
        problems = list(set(problems))

        # Determine severity
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

        # Healthy pod
        if pod.status.phase == "Running" and not problems:
            healthy.append(pod_info)

        # Unhealthy pod
        else:
            unhealthy.append(pod_info)

    total_pods = len(pods.items)

    # Calculate health percentage
    if total_pods > 0:
        health_percentage = round(
            (len(healthy) / total_pods) * 100,
            2
        )
    else:
        health_percentage = 0

    return {
        "total_pods": total_pods,
        "healthy": len(healthy),
        "unhealthy": len(unhealthy),
        "health_percentage": health_percentage,
        "unhealthy_pods": unhealthy,
    }


# ---------------------------------------------------------
# SECURITY SCAN
# ---------------------------------------------------------

@app.get("/security/scan")
def security_scan():
    findings = scan_pod_security()

    return {
        "total_findings": len(findings),
        "findings": findings,
    }


# ---------------------------------------------------------
# MANUAL HEAL
# ---------------------------------------------------------

@app.post("/heal/{namespace}/{deployment_name}")
def heal(namespace: str, deployment_name: str):
    return heal_deployment(
        deployment_name=deployment_name,
        namespace=namespace,
    )


# ---------------------------------------------------------
# AUTOMATIC HEAL
# ---------------------------------------------------------

@app.post("/heal/auto")
def auto_heal():
    config.load_kube_config()
    apps_api = client.AppsV1Api()

    results = []

    deployments = apps_api.list_deployment_for_all_namespaces()

    for deployment in deployments.items:
        namespace = deployment.metadata.namespace
        name = deployment.metadata.name

        containers = deployment.spec.template.spec.containers or []

        for container in containers:
            image = container.image or ""

            if "does-not-exist-kubeguard" in image:
                result = heal_deployment(
                    deployment_name=name,
                    namespace=namespace,
                )

                results.append(result)

    return {
        "checked_deployments": len(deployments.items),
        "healed": len(results),
        "results": results,
    }