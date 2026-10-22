# Checks and finding identifiers

KubePath gives each finding a stable rule prefix and a content-derived suffix. Reports carry the evidence and recommendations used to reach each result. Severity describes the potential impact of the visible configuration; it is not a claim that a cluster is exploitable.

## Identity and RBAC

| Rule prefix | What is reviewed |
| --- | --- |
| `RBAC_ANONYMOUS_BINDING` | Role grants bound to `system:unauthenticated`. |
| `RBAC_ALL_AUTHENTICATED` | Broad grants bound to `system:authenticated`. |
| `RBAC_SYSTEM_MASTERS` | Bindings to the privileged `system:masters` group. |
| `RBAC_FULL_WILDCARD` | Rules using wildcard API groups, resources, or verbs. |
| `RBAC_ALL_SERVICE_ACCOUNTS` | Broad groups that include service accounts. |
| `RBAC_SECRET_ACCESS` | Secret read or mutation verbs, including resource-name constraints in the rule evidence. |
| `RBAC_BIND_POWER`, `RBAC_ESCALATE_POWER` | Privileges that can bypass normal role-binding checks or create stronger roles. |
| `RBAC_IMPERSONATION` | User, group, or service-account impersonation. |
| `RBAC_NODE_PROXY`, `RBAC_CSR_APPROVAL` | Node proxy access or certificate-signing-request approval. |
| `RBAC_TOKEN_MINTING` | Creation of service-account token subresources. |
| `RBAC_POD_RUNTIME_ACCESS` | Pod exec, attach, port-forward, or ephemeral-container permissions. |
| `RBAC_BINDING_MANAGEMENT` | Role-binding write access, with elevated severity when `bind` is also granted. |
| `RBAC_SERVICEACCOUNT_PATH` | Conditional workload mutation paths to service accounts with sensitive permissions, including chained service-account reachability. |
| `RBAC_ROLE_REF_NOT_FOUND`, `RBAC_INVALID_ROLE_REF_KIND` | Missing or invalid `roleRef` objects. |
| `RBAC_DUPLICATE_ROLE`, `RBAC_DUPLICATE_BINDING` | Duplicate role or binding identities in the supplied input set. |

The analyzer models built-in authenticated and unauthenticated groups and basic user/group membership relationships. It does not resolve external identity-provider group membership or all Kubernetes API authorization details.

## Workload posture

Checks look for privileged or Windows HostProcess containers, host namespaces and host paths, root execution, privilege escalation, dangerous Linux capabilities, missing seccomp, writable root filesystems, mutable image tags, absent CPU/memory bounds, and automatic service-account token mounting. Namespace labels are reviewed for Pod Security Admission `enforce` posture.

These checks inspect fields present in the supplied Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, and CronJob manifests. They do not evaluate rendered Helm/Kustomize output, mutating admission defaults, policy exceptions, runtime image contents, or platform-specific container behavior.

## Network policy visibility

KubePath identifies workload namespaces with no visible NetworkPolicy and reviews whether all-pod policies visibly default-deny ingress and egress. A policy's presence does not prove that traffic is blocked: selectors, peers, ports, CNI implementation, host-network behavior, and other policies affect actual connectivity.

## Severity and confidence

Findings include explicit configuration evidence and recommendations. Confidence reflects how directly the supplied YAML supports the rule, while service-account paths are marked medium because workload admission, token availability, API behavior, and cluster controls can break the inferred path. Always verify important paths against the target cluster and threat model.
