from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_ROOT = ROOT / "deploy" / "kubernetes"
IMAGE = (
    "ghcr.io/soballin93/dnsquery@"
    "sha256:9f5036833ae64ade9caf7a3e8b57d171fb8587a69acab8cdb95b626fcb23eba2"
)


def load_manifest(name: str) -> dict:
    return json.loads((MANIFEST_ROOT / name).read_text(encoding="utf-8"))


def test_kustomization_names_only_declared_resources() -> None:
    lines = [
        line.strip()
        for line in (MANIFEST_ROOT / "kustomization.yaml")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip().startswith("- ")
    ]
    assert lines == [
        "- deployment.json",
        "- service.json",
        "- network-policy.json",
        "- pod-disruption-budget.json",
    ]

    documents = [
        load_manifest(name.removeprefix("- "))
        for name in lines
    ]
    assert {document["kind"] for document in documents} == {
        "Deployment",
        "Service",
        "NetworkPolicy",
        "PodDisruptionBudget",
    }


def test_deployment_is_digest_pinned_restricted_and_two_node_safe() -> None:
    deployment = load_manifest("deployment.json")
    spec = deployment["spec"]
    pod_spec = spec["template"]["spec"]
    container = pod_spec["containers"][0]

    assert deployment["metadata"]["namespace"] == "platform-optional"
    assert spec["replicas"] == 2
    assert container["image"] == IMAGE
    assert container["imagePullPolicy"] == "IfNotPresent"
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["enableServiceLinks"] is False
    assert pod_spec["securityContext"] == {
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "fsGroup": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert {probe for probe in ("startupProbe", "readinessProbe", "livenessProbe")} <= set(
        container
    )

    affinity = pod_spec["affinity"]
    role_expression = affinity["nodeAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]["nodeSelectorTerms"][0]["matchExpressions"][0]
    assert role_expression == {
        "key": "homelab.oesterreich.local/role",
        "operator": "In",
        "values": ["server-worker"],
    }
    anti_affinity = affinity["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    assert anti_affinity[0]["topologyKey"] == "kubernetes.io/hostname"


def test_service_is_cluster_internal_only() -> None:
    service = load_manifest("service.json")

    assert service["metadata"]["namespace"] == "platform-optional"
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"] == [
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"}
    ]


def test_network_policy_denies_private_egress_and_limits_ingress() -> None:
    policy = load_manifest("network-policy.json")
    spec = policy["spec"]

    assert spec["policyTypes"] == ["Ingress", "Egress"]
    assert spec["ingress"][0]["from"] == [
        {
            "podSelector": {
                "matchLabels": {
                    "homelab.oesterreich.local/dnsquery-client": "true"
                }
            }
        }
    ]
    assert spec["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 8080}]

    public_egress = spec["egress"][0]
    excluded = set(public_egress["to"][0]["ipBlock"]["except"])
    assert {
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
    } <= excluded
    assert public_egress["ports"] == [
        {"protocol": "TCP", "port": 43},
        {"protocol": "TCP", "port": 443},
    ]


def test_disruption_budget_preserves_one_replica() -> None:
    budget = load_manifest("pod-disruption-budget.json")

    assert budget["metadata"]["namespace"] == "platform-optional"
    assert budget["spec"]["minAvailable"] == 1
