# DNSQuery Kubernetes source

This directory is planned migration source for the existing Unraid service. It is not included in
the active homelab Flux Kustomization and does not authorize a Kubernetes apply, ingress, DNS,
firewall, certificate, or Twingate change.

The bundle expects the platform-owned `platform-optional` namespace and its default-deny and DNS
egress policies to exist. It schedules two replicas only on nodes labeled
`homelab.oesterreich.local/role=server-worker`, keeps them on separate hosts, and pins the reviewed
public image by digest. DNSQuery stores no application state. `/tmp` is an ephemeral, size-capped
write boundary for Gunicorn and one-response CSV exports.

## Admission and acceptance

Before any apply:

1. Require the homelab workload-migration phase, signed Flux source, optional namespace envelope,
   and component releases to be accepted and healthy.
2. Reconfirm the pinned digest and render this directory with Kustomize and strict Kubernetes
   schema validation.
3. Recheck the existing Unraid container health, a non-secret `example.com` query, its exact image,
   mounts, environment names, and published access path. Keep it running.
4. Show the exact target diff and obtain the workload-apply and existing-access cutover approvals.

Initially, the ClusterIP permits port 8080 only from same-namespace acceptance Pods labeled
`homelab.oesterreich.local/dnsquery-client=true`. The application may resolve through the
platform DNS policy and may reach public WHOIS and HTTPS endpoints, but this bundle excludes private,
carrier-grade NAT, loopback, link-local, documentation, benchmark, multicast, and reserved ranges.

Acceptance must prove both replicas Ready on different `server-worker` nodes, one-replica
availability during a voluntary disruption, health and a non-secret query through the Service,
blocked access from an unlabeled Pod, and blocked private-address egress. Do not submit a real
SecurityTrails key during cluster acceptance.

## Cutover and rollback

A later reviewed change must add the approved private ingress, certificate, monitoring, and
existing-access migration. It must not create broader reachability than the current service.
After user-facing health, query, denial, and log checks pass, retain the Unraid container stopped but
recoverable for a 24-hour observation interval.

Rollback restores access to the unchanged Unraid container, removes or suspends only the DNSQuery
cluster objects, and verifies health plus the non-secret query at the original endpoint. Because
this bundle creates no persistent volume or database, rollback has no data merge. Retire the source
container only after the observation interval and the platform dependency, monitoring, and backup
exclusion checks pass; preserve the normal seven-day retirement tombstone.
