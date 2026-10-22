# Security policy

Rudy KubePath is an offline static analyzer. It reads manifest files supplied by the operator and does not connect to clusters, execute workloads, use credentials, or modify infrastructure.

Please report security issues privately to `security@rudy.systems` with the affected version, a minimal reproduction, and impact. Do not include live cluster credentials or sensitive production manifests. If that address is unavailable, open a GitHub issue containing only a request for a private reporting channel.

The analyzer itself is not a Kubernetes admission controller or runtime enforcement mechanism. Findings are advisory and must be verified against the target cluster, API server version, admission configuration, identity provider, and network plugin.
