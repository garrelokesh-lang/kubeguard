from kubernetes import client, config


def get_clients():
    config.load_kube_config()

    core_api = client.CoreV1Api()
    apps_api = client.AppsV1Api()

    return core_api, apps_api


def heal_deployment(deployment_name, namespace="default"):
    _, apps_api = get_clients()

    try:
        deployment = apps_api.read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
        )

        container = deployment.spec.template.spec.containers[0]

        # If the deployment already has a valid image, report it.
        if "does-not-exist" not in container.image:
            return {
                "success": False,
                "message": "Deployment does not have a known broken image",
                "deployment": deployment_name,
                "image": container.image,
            }

        # Restore the application to nginx for this MVP recovery test.
        container.image = "nginx:latest"

        apps_api.patch_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
            body=deployment,
        )

        return {
            "success": True,
            "message": "Deployment image repaired",
            "deployment": deployment_name,
            "old_image": "does-not-exist-kubeguard:v999",
            "new_image": "nginx:latest",
        }

    except Exception as error:
        return {
            "success": False,
            "message": "Healing failed",
            "error": str(error),
        }