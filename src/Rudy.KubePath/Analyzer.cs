using System.Security.Cryptography;
using System.Text;

namespace Rudy.KubePath;

public sealed record AnalyzeOptions(bool CheckWorkloads = true, bool CheckNetworkPolicy = true, bool FindServiceAccountPaths = true);

public sealed class Analyzer
{
    private sealed record Grant(
        string Principal,
        RoleDefinition Role,
        RoleBindingDefinition Binding,
        string Scope,
        string ScopeNamespace);

    private sealed record ReachabilityState(string Identity, List<Grant> Grants, List<string> Path);

    private static readonly (string ApiGroup, string Resource)[] PodProducingResources =
    [
        ("", "pods"),
        ("apps", "deployments"),
        ("apps", "statefulsets"),
        ("apps", "daemonsets"),
        ("apps", "replicasets"),
        ("batch", "jobs"),
        ("batch", "cronjobs")
    ];
    private static readonly string[] MutableWorkloadVerbs = ["create", "update", "patch"];

    private static readonly string[] SensitiveVerbs = ["get", "list", "watch", "create", "update", "patch", "delete"];
    private static readonly string[] DangerousCapabilities =
    [
        "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "NET_ADMIN", "NET_RAW", "BPF", "DAC_READ_SEARCH"
    ];

    public AnalysisReport Analyze(Inventory inventory, AnalyzeOptions? options = null)
    {
        options ??= new AnalyzeOptions();
        var findings = new Dictionary<string, Finding>(StringComparer.Ordinal);
        var nodes = new Dictionary<string, GraphNode>(StringComparer.Ordinal);
        var edges = new Dictionary<string, GraphEdge>(StringComparer.Ordinal);
        var grants = BuildGrants(inventory, findings, nodes, edges);

        AddDuplicateObjectFindings(inventory, findings);
        AddBroadPrincipalFindings(grants, findings);
        AddRbacPermissionFindings(inventory, grants, findings);

        if (options.FindServiceAccountPaths)
        {
            AddServiceAccountPaths(inventory, grants, findings, nodes, edges);
        }
        if (options.CheckWorkloads)
        {
            AddWorkloadFindings(inventory, findings);
            AddNamespacePolicyFindings(inventory, findings);
        }
        if (options.CheckNetworkPolicy)
        {
            AddNetworkPolicyFindings(inventory, findings);
        }

        foreach (var inputFinding in inventory.InputFindings)
        {
            findings.TryAdd(inputFinding.Id, inputFinding);
        }

        var ordered = findings.Values
            .OrderByDescending(static finding => SeverityText.Rank(finding.Severity))
            .ThenBy(static finding => finding.Id, StringComparer.Ordinal)
            .ToList();
        var summary = new InventorySummary(
            inventory.FileCount,
            inventory.DocumentCount,
            inventory.Roles.Count,
            inventory.Bindings.Count,
            inventory.ServiceAccounts.Select(static sa => $"{sa.Namespace}/{sa.Name}").Distinct(StringComparer.Ordinal).Count(),
            inventory.Workloads.Count,
            inventory.NetworkPolicies.Count,
            ordered.Count,
            ordered.Count(static f => f.Severity == Severity.Critical),
            ordered.Count(static f => f.Severity == Severity.High),
            ordered.Count(static f => f.Severity == Severity.Medium),
            ordered.Count(static f => f.Severity == Severity.Low),
            ordered.Count(static f => f.Severity == Severity.Info));

        return new AnalysisReport(
            "rudy-kubepath/v1",
            "0.1.0",
            summary,
            ordered,
            nodes.Values.OrderBy(static node => node.Id, StringComparer.Ordinal).ToList(),
            edges.Values.OrderBy(static edge => edge.From, StringComparer.Ordinal).ThenBy(static edge => edge.To, StringComparer.Ordinal).ThenBy(static edge => edge.Label, StringComparer.Ordinal).ToList());
    }

    public static string CanonicalSubject(RoleSubject subject)
    {
        if (subject.Kind.Equals("ServiceAccount", StringComparison.OrdinalIgnoreCase))
        {
            return $"ServiceAccount:{subject.Namespace}/{subject.Name}";
        }
        if (subject.Kind.Equals("Group", StringComparison.OrdinalIgnoreCase))
        {
            return $"Group:{subject.Name}";
        }
        return $"User:{subject.Name}";
    }

    private static List<Grant> BuildGrants(
        Inventory inventory,
        Dictionary<string, Finding> findings,
        Dictionary<string, GraphNode> nodes,
        Dictionary<string, GraphEdge> edges)
    {
        var roles = inventory.Roles
            .GroupBy(RoleKey, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.ToList(), StringComparer.Ordinal);
        var grants = new List<Grant>();

        foreach (var role in inventory.Roles)
        {
            var roleNode = RoleNode(role);
            nodes.TryAdd(roleNode.Id, roleNode);
            for (var i = 0; i < role.Rules.Count; i++)
            {
                var rule = role.Rules[i];
                var label = DescribeRule(rule);
                var permission = Node("permission", $"{RoleKey(role)}#{i}", label);
                nodes.TryAdd(permission.Id, permission);
                AddEdge(edges, new GraphEdge(roleNode.Id, permission.Id, $"rule {i + 1}"));
            }
        }

        foreach (var binding in inventory.Bindings)
        {
            var bindingKey = $"{binding.Kind}:{binding.Namespace}:{binding.Name}";
            var bindingNode = Node("binding", bindingKey, $"{binding.Kind} {binding.Namespace}/{binding.Name}");
            nodes.TryAdd(bindingNode.Id, bindingNode);
            var role = ResolveRole(binding, roles);
            if (role is null)
            {
                var invalidKind = binding.Kind == "ClusterRoleBinding" && binding.RoleKind != "ClusterRole";
                var code = invalidKind ? "RBAC_INVALID_ROLE_REF_KIND" : "RBAC_ROLE_REF_NOT_FOUND";
                var detail = invalidKind
                    ? $"ClusterRoleBinding '{binding.Name}' references '{binding.RoleKind}', but only ClusterRole references are valid."
                    : $"{binding.Kind} '{binding.Name}' references missing {binding.RoleKind} '{binding.RoleName}'.";
                AddFinding(findings, code, Severity.High, "Binding cannot be resolved", detail, null, binding.Namespace, binding.Source,
                    [$"{binding.Kind} {binding.Namespace}/{binding.Name}", $"roleRef: {binding.RoleKind}/{binding.RoleName}"],
                    ["Check roleRef.kind, roleRef.name, and namespace; include the referenced Role or ClusterRole in the analyzed input."]);
                continue;
            }

            var scope = binding.Kind == "ClusterRoleBinding" ? "cluster" : "namespace";
            var scopeNamespace = scope == "cluster" ? string.Empty : binding.Namespace;
            AddEdge(edges, new GraphEdge(bindingNode.Id, RoleNode(role).Id, "roleRef"));
            foreach (var subject in binding.Subjects)
            {
                var principal = CanonicalSubject(subject);
                var principalNode = Node("principal", principal, principal);
                nodes.TryAdd(principalNode.Id, principalNode);
                AddEdge(edges, new GraphEdge(principalNode.Id, bindingNode.Id, "subject"));
                grants.Add(new Grant(principal, role, binding, scope, scopeNamespace));
            }
        }

        return grants;
    }

    private static RoleDefinition? ResolveRole(
        RoleBindingDefinition binding,
        IReadOnlyDictionary<string, List<RoleDefinition>> roles)
    {
        if (binding.RoleKind == "ClusterRole")
        {
            return roles.GetValueOrDefault(RoleKey("ClusterRole", string.Empty, binding.RoleName))?.FirstOrDefault();
        }
        if (binding.RoleKind == "Role" && binding.Kind == "RoleBinding")
        {
            return roles.GetValueOrDefault(RoleKey("Role", binding.Namespace, binding.RoleName))?.FirstOrDefault();
        }
        return null;
    }

    private static void AddDuplicateObjectFindings(Inventory inventory, Dictionary<string, Finding> findings)
    {
        var duplicates = inventory.Roles
            .GroupBy(RoleKey, StringComparer.Ordinal)
            .Where(static group => group.Count() > 1);
        foreach (var duplicate in duplicates)
        {
            var role = duplicate.First();
            AddFinding(findings, "RBAC_DUPLICATE_ROLE", Severity.High, "Role identity is duplicated",
                $"Multiple {role.Kind} objects use the same identity '{role.Namespace}/{role.Name}'. This static analysis cannot determine which object will be accepted or replace another.",
                null, role.Namespace, role.Source,
                duplicate.Select(static item => item.Source.ToString()).ToList(),
                ["Give each Role and ClusterRole a unique name within its scope and review the rendered manifests."]);
        }

        var duplicateBindings = inventory.Bindings
            .GroupBy(static binding => $"{binding.Kind}:{binding.Namespace}:{binding.Name}", StringComparer.Ordinal)
            .Where(static group => group.Count() > 1);
        foreach (var duplicate in duplicateBindings)
        {
            var binding = duplicate.First();
            AddFinding(findings, "RBAC_DUPLICATE_BINDING", Severity.High, "Binding identity is duplicated",
                $"Multiple {binding.Kind} objects use the same identity '{binding.Namespace}/{binding.Name}'.",
                null, binding.Namespace, binding.Source,
                duplicate.Select(static item => item.Source.ToString()).ToList(),
                ["Resolve duplicate binding declarations before deploying the rendered manifests."]);
        }
    }

    private static void AddBroadPrincipalFindings(List<Grant> grants, Dictionary<string, Finding> findings)
    {
        foreach (var grant in grants)
        {
            if (!grant.Role.Rules.Any(static rule => rule.Verbs.Count > 0 && (rule.Resources.Count > 0 || rule.NonResourceUrls.Count > 0)))
            {
                continue;
            }
            var source = grant.Binding.Source;
            switch (grant.Principal)
            {
                case "Group:system:unauthenticated":
                    AddFinding(findings, "RBAC_ANONYMOUS_BINDING", Severity.Critical, "Permissions are bound to unauthenticated callers",
                        "The system:unauthenticated group is granted a role. Anyone who can reach the API server without authenticating may receive these permissions.",
                        grant.Principal, grant.ScopeNamespace, source,
                        [grant.Binding.Name, $"{grant.Role.Kind} {grant.Role.Namespace}/{grant.Role.Name}"],
                        ["Remove this binding unless anonymous API access is an intentional, reviewed requirement."]);
                    break;
                case "Group:system:authenticated":
                    AddFinding(findings, "RBAC_ALL_AUTHENTICATED", Severity.High, "Permissions are bound to every authenticated identity",
                        "The system:authenticated group includes all authenticated users and service accounts; the grant is broader than a named application identity.",
                        grant.Principal, grant.ScopeNamespace, source,
                        [grant.Binding.Name, $"{grant.Role.Kind} {grant.Role.Namespace}/{grant.Role.Name}"],
                        ["Bind the role to the smallest explicit user, group, or service account set that needs it."]);
                    break;
                case "Group:system:masters":
                    AddFinding(findings, "RBAC_SYSTEM_MASTERS", Severity.Critical, "A binding targets system:masters",
                        "Members of system:masters bypass normal RBAC checks and have unrestricted cluster access.",
                        grant.Principal, grant.ScopeNamespace, source,
                        [grant.Binding.Name, $"{grant.Role.Kind} {grant.Role.Namespace}/{grant.Role.Name}"],
                        ["Avoid adding identities to system:masters; use narrowly scoped roles and auditable break-glass access."]);
                    break;
            }
        }
    }

    private static void AddRbacPermissionFindings(
        Inventory inventory,
        List<Grant> grants,
        Dictionary<string, Finding> findings)
    {
        var principals = grants.Select(static grant => grant.Principal)
            .Concat(inventory.ServiceAccounts.Select(static sa => $"ServiceAccount:{sa.Namespace}/{sa.Name}"))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static principal => principal, StringComparer.Ordinal);

        foreach (var principal in principals)
        {
            var effective = EffectiveGrants(principal, grants);
            if (effective.Count == 0)
            {
                continue;
            }
            var primary = effective[0];
            var context = effective.Select(static grant => $"{grant.Role.Kind} {grant.Role.Namespace}/{grant.Role.Name} via {grant.Binding.Kind} {grant.Binding.Namespace}/{grant.Binding.Name}").Distinct(StringComparer.Ordinal).ToList();

            if (effective.Any(static grant => grant.Role.Rules.Any(IsFullWildcardRule)))
            {
                AddFinding(findings, "RBAC_FULL_WILDCARD", Severity.Critical, "Principal has a wildcard permission grant",
                    "A bound policy rule uses wildcard API groups, resources, and verbs, which can grant broad access as the cluster API evolves.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Replace wildcard API groups, resources, and verbs with the specific operations required by the workload."]);
            }

            if (principal.StartsWith("Group:system:serviceaccounts", StringComparison.Ordinal))
            {
                AddFinding(findings, "RBAC_ALL_SERVICE_ACCOUNTS", Severity.High, "A broad service-account group receives permissions",
                    "This group applies to many workloads. A compromised pod may inherit the grant through its service account.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Bind the role to specific service accounts instead of a cluster-wide service-account group."]);
            }

            if (CanAny(effective, SensitiveVerbs, ["secrets"], string.Empty, null))
            {
                AddFinding(findings, "RBAC_SECRET_ACCESS", Severity.High, "Principal can read or change Kubernetes Secrets",
                    "Secret access may expose application credentials and, in some clusters, long-lived service-account credentials. The effect depends on which named secrets and admission controls are in scope.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove broad Secret access or narrow it to required names; keep credentials out of namespaces and workloads that do not need them."]);
            }

            if (CanAny(effective, ["bind"], ["roles", "clusterroles"], "rbac.authorization.k8s.io", null))
            {
                AddFinding(findings, "RBAC_BIND_POWER", Severity.Critical, "Principal can bypass role-binding privilege checks",
                    "The bind verb on Roles or ClusterRoles can permit creating a binding to permissions the caller does not already hold.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove bind unless a trusted role-management service specifically requires it; constrain its target roles and scope."]);
            }
            if (CanAny(effective, ["escalate"], ["roles", "clusterroles"], "rbac.authorization.k8s.io", null))
            {
                AddFinding(findings, "RBAC_ESCALATE_POWER", Severity.Critical, "Principal can create or update roles with stronger permissions",
                    "The escalate verb can bypass the API server's normal restriction on adding permissions that the caller does not already have.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove escalate unless a trusted role-management service specifically requires it; constrain the role scope and review its callers."]);
            }

            if (CanAny(effective, ["impersonate"], ["users", "groups", "serviceaccounts", "userextras/*"], "authentication.k8s.io", null)
                || CanAny(effective, ["impersonate"], ["users", "groups", "serviceaccounts"], string.Empty, null))
            {
                AddFinding(findings, "RBAC_IMPERSONATION", Severity.High, "Principal can impersonate other identities",
                    "Impersonation can make API requests with another user, group, or service-account identity and exercise that identity's permissions.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove impersonate or restrict it to a tightly controlled identity set and purpose."]);
            }

            if (CanAny(effective, ["get", "create", "update", "patch"], ["nodes/proxy"], string.Empty, null))
            {
                AddFinding(findings, "RBAC_NODE_PROXY", Severity.Critical, "Principal can access the kubelet node proxy",
                    "Access to nodes/proxy can expose privileged kubelet APIs beyond ordinary Kubernetes resource permissions.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove nodes/proxy access; use a narrowly scoped, audited mechanism for any required node operations."]);
            }

            if (CanAny(effective, ["create"], ["serviceaccounts/token"], string.Empty, null))
            {
                AddFinding(findings, "RBAC_TOKEN_MINTING", Severity.High, "Principal can request service-account tokens",
                    "The principal can request a token for a service account and may act with that account's API permissions.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Restrict serviceaccounts/token creation to a trusted token broker or remove it where unused."]);
            }

            if (CanAny(effective, ["create", "update", "patch"], ["certificatesigningrequests/approval"], "certificates.k8s.io", null))
            {
                AddFinding(findings, "RBAC_CSR_APPROVAL", Severity.Critical, "Principal can approve certificate signing requests",
                    "Certificate approval combined with a permissive signer or signer-specific issuance path can grant a new cluster identity.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Remove generic CSR approval and limit any required approval to validated signers and request policies."]);
            }

            if (CanAny(effective, ["get", "create", "update", "patch"], ["pods/exec", "pods/attach", "pods/ephemeralcontainers"], string.Empty, null))
            {
                AddFinding(findings, "RBAC_POD_RUNTIME_ACCESS", Severity.High, "Principal can enter or alter running pods",
                    "Pod exec, attach, or ephemeral-container access can expose application data and credentials in the affected namespace.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Limit pod runtime access to an audited operator group and isolate sensitive workloads by namespace."]);
            }

            if (CanAny(effective, ["create"], ["clusterrolebindings", "rolebindings"], "rbac.authorization.k8s.io", null))
            {
                var canBind = CanAny(effective, ["bind"], ["roles", "clusterroles"], "rbac.authorization.k8s.io", null);
                AddFinding(findings, "RBAC_BINDING_MANAGEMENT", canBind ? Severity.Critical : Severity.Medium,
                    canBind ? "Principal can create bindings and bind arbitrary role permissions" : "Principal can manage role bindings",
                    canBind
                        ? "The combination of creating bindings and bind permission can attach roles with permissions beyond the principal's existing grants."
                        : "Binding changes affect who receives a role; Kubernetes still applies its built-in permission checks unless bind is separately granted.",
                    principal, ScopeLabel(effective), primary.Binding.Source,
                    context,
                    ["Restrict role-binding creation to a trusted identity-management path and review changes in code review."]);
            }
        }
    }

    private static void AddServiceAccountPaths(
        Inventory inventory,
        List<Grant> grants,
        Dictionary<string, Finding> findings,
        Dictionary<string, GraphNode> nodes,
        Dictionary<string, GraphEdge> edges)
    {
        var principals = grants.Select(static grant => grant.Principal)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static principal => principal, StringComparer.Ordinal)
            .ToList();

        var serviceAccounts = inventory.ServiceAccounts
            .GroupBy(static sa => $"{sa.Namespace}/{sa.Name}", StringComparer.Ordinal)
            .Select(static group => group.First())
            .ToList();

        foreach (var principal in principals)
        {
            var initialGrants = EffectiveGrants(principal, grants);
            var pending = new Queue<ReachabilityState>();
            pending.Enqueue(new ReachabilityState(principal, initialGrants, []));
            var grantsByIdentity = new Dictionary<string, HashSet<Grant>>(StringComparer.Ordinal)
            {
                [principal] = new HashSet<Grant>(initialGrants)
            };

            while (pending.Count > 0)
            {
                var state = pending.Dequeue();
                foreach (var ns in inventory.ObservedNamespaces.OrderBy(static value => value, StringComparer.Ordinal))
                {
                    var actorGrants = state.Grants.Where(grant => HasScope(grant, ns) &&
                        grant.Role.Rules.Any(CanManagePodWorkload))
                        .ToList();
                    if (actorGrants.Count == 0)
                    {
                        continue;
                    }

                    foreach (var serviceAccount in serviceAccounts.Where(sa => sa.Namespace == ns))
                    {
                        var saPrincipal = $"ServiceAccount:{serviceAccount.Namespace}/{serviceAccount.Name}";
                        var saGrants = EffectiveGrants(saPrincipal, grants);
                        if (saGrants.Count == 0)
                        {
                            continue;
                        }

                        var combinedGrants = state.Grants.Concat(saGrants).Distinct().ToList();
                        if (!grantsByIdentity.TryGetValue(saPrincipal, out var knownGrants))
                        {
                            knownGrants = [];
                            grantsByIdentity.Add(saPrincipal, knownGrants);
                        }
                        var addedGrant = false;
                        foreach (var grant in combinedGrants)
                        {
                            addedGrant |= knownGrants.Add(grant);
                        }
                        if (!addedGrant)
                        {
                            continue;
                        }

                        var actorGrant = actorGrants[0];
                        var saNode = Node("principal", saPrincipal, saPrincipal);
                        nodes.TryAdd(saNode.Id, saNode);
                        var actorNode = Node("principal", state.Identity, state.Identity);
                        nodes.TryAdd(actorNode.Id, actorNode);
                        var workloadNode = Node("workload-scope", $"{state.Identity}:{ns}", $"pod-producing workloads in {ns}");
                        nodes.TryAdd(workloadNode.Id, workloadNode);
                        AddEdge(edges, new GraphEdge(actorNode.Id, workloadNode.Id, "can create or change", $"namespace={ns}"));
                        AddEdge(edges, new GraphEdge(workloadNode.Id, saNode.Id, "can select service account", "subject to admission and token policy"));

                        var nextPath = new List<string>(state.Path)
                        {
                            $"{state.Identity} can create or change pod-producing resources in namespace '{ns}' through {actorGrant.Role.Kind} {actorGrant.Role.Namespace}/{actorGrant.Role.Name}.",
                            $"A workload in '{ns}' can use ServiceAccount {serviceAccount.Namespace}/{serviceAccount.Name}."
                        };
                        var risk = DescribeServiceAccountRisk(saGrants);
                        if (risk is not null)
                        {
                            var saGrant = risk.Value.Grant;
                            var severity = risk.Value.Critical ? Severity.Critical : Severity.High;
                            var recommendations = new List<string>
                            {
                                "Remove workload-creation access from identities that do not need it, or constrain it with admission policy and namespace boundaries.",
                                "Reduce the service account's permissions and avoid binding application accounts to broad roles."
                            };
                            if (serviceAccount.AutomountServiceAccountToken == false)
                            {
                                recommendations.Add("The ServiceAccount disables automatic token mounting, but an authorized workload creator may set the Pod-level option; verify that admission policy prevents this override.");
                            }
                            var evidence = new List<string>(nextPath)
                            {
                                $"Reachable capability: {risk.Value.Description}",
                                $"Service-account grant: {saGrant.Role.Kind} {saGrant.Role.Namespace}/{saGrant.Role.Name} through {saGrant.Binding.Kind} {saGrant.Binding.Namespace}/{saGrant.Binding.Name}.",
                                "This path is conditional on workload admission, service-account token availability, and cluster-specific controls."
                            };
                            var pathText = $"{principal} can reach {risk.Value.Description} by following {string.Join(" then ", nextPath)}";
                            AddFinding(findings, "RBAC_SERVICEACCOUNT_PATH", severity, "Workload permissions reach a more privileged service account",
                                pathText, principal, ns, actorGrant.Binding.Source, evidence, recommendations, "medium");

                            var capabilityNode = Node("capability", $"{saPrincipal}:{risk.Value.Description}", risk.Value.Description);
                            nodes.TryAdd(capabilityNode.Id, capabilityNode);
                            AddEdge(edges, new GraphEdge(saNode.Id, capabilityNode.Id, "bound through", $"{saGrant.Role.Kind} {saGrant.Role.Namespace}/{saGrant.Role.Name}"));
                        }

                        pending.Enqueue(new ReachabilityState(
                            saPrincipal,
                            knownGrants.ToList(),
                            nextPath));
                    }
                }
            }
        }
    }

    private static void AddWorkloadFindings(Inventory inventory, Dictionary<string, Finding> findings)
    {
        foreach (var workload in inventory.Workloads)
        {
            var serviceAccount = inventory.ServiceAccounts.FirstOrDefault(sa =>
                sa.Namespace == workload.Namespace && sa.Name == workload.ServiceAccountName);
            var automount = workload.AutomountServiceAccountToken
                ?? serviceAccount?.AutomountServiceAccountToken
                ?? true;
            if (automount)
            {
                AddWorkloadFinding(findings, "POD_SERVICE_ACCOUNT_TOKEN_AUTOMOUNT", Severity.Medium, "Workload receives a service-account API token",
                    $"Workload {workload.Namespace}/{workload.Name} has service-account token automount enabled or unspecified. The token's permissions depend on its service account and cluster configuration.",
                    workload, [$"serviceAccountName={workload.ServiceAccountName}", $"pod automount={workload.AutomountServiceAccountToken?.ToString() ?? "unset"}"],
                    ["Set automountServiceAccountToken=false unless the workload needs Kubernetes API access; apply a Pod-level setting when overriding the ServiceAccount default."]);
            }
            if (workload.HostProcess)
            {
                AddWorkloadFinding(findings, "POD_HOST_PROCESS", Severity.Critical, "Windows HostProcess container is enabled",
                    $"Workload {workload.Namespace}/{workload.Name} requests Windows HostProcess access, which runs the container with host-level process access.",
                    workload, ["hostProcess=true"], ["Remove HostProcess unless a narrowly controlled node-management workload requires it."]);
            }
            if (workload.HostNetwork || workload.HostPid || workload.HostIpc)
            {
                var enabled = new List<string>();
                if (workload.HostNetwork) enabled.Add("hostNetwork");
                if (workload.HostPid) enabled.Add("hostPID");
                if (workload.HostIpc) enabled.Add("hostIPC");
                AddWorkloadFinding(findings, "POD_HOST_NAMESPACE", Severity.High, "Workload shares a host namespace",
                    $"Workload {workload.Namespace}/{workload.Name} enables {string.Join(", ", enabled)} and reduces isolation from the node.",
                    workload, enabled, ["Remove host namespace access unless a node-level workload has a documented need and additional controls."]);
            }
            foreach (var path in workload.HostPaths)
            {
                AddWorkloadFinding(findings, "POD_HOSTPATH", Severity.High, "Workload mounts a host path",
                    $"Workload {workload.Namespace}/{workload.Name} mounts host path '{path}'. HostPath can expose node files, credentials, or runtime sockets depending on the path and mount mode.",
                    workload, [path], ["Replace hostPath with a scoped volume where possible; otherwise use an approved path, read-only mounts, and node-level policy."]);
            }

            foreach (var container in workload.Containers)
            {
                if (container.Privileged == true)
                {
                    AddContainerFinding(findings, "POD_PRIVILEGED", Severity.Critical, "Privileged container is enabled",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} requests privileged mode, weakening container isolation.",
                        workload, container, ["securityContext.privileged=true"], ["Remove privileged mode or isolate the workload on dedicated nodes with a documented exception."]);
                }
                if (container.RunAsUser == 0 || container.RunAsNonRoot == false)
                {
                    AddContainerFinding(findings, "POD_ROOT_USER", Severity.High, "Container may run as root",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} is configured with UID 0 or runAsNonRoot=false.",
                        workload, container, ["runAsUser=0 or runAsNonRoot=false"], ["Use a non-root image and set runAsNonRoot=true with a nonzero runAsUser where the application supports it."]);
                }
                else if (container.RunAsNonRoot is null && container.RunAsUser is null)
                {
                    AddContainerFinding(findings, "POD_RUN_AS_NON_ROOT_MISSING", Severity.Medium, "Container does not declare a non-root identity",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} has no non-root user setting in the inspected Pod or container security context.",
                        workload, container, ["runAsNonRoot and runAsUser are unset"], ["Set runAsNonRoot=true and use an unprivileged UID; verify image compatibility."]);
                }

                if (container.AllowPrivilegeEscalation == true)
                {
                    AddContainerFinding(findings, "POD_PRIVILEGE_ESCALATION", Severity.High, "Container allows privilege escalation",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} explicitly allows privilege escalation.",
                        workload, container, ["allowPrivilegeEscalation=true"], ["Set allowPrivilegeEscalation=false unless the application has a documented requirement."]);
                }
                else if (container.AllowPrivilegeEscalation is null)
                {
                    AddContainerFinding(findings, "POD_PRIVILEGE_ESCALATION_UNSET", Severity.Medium, "Container does not disable privilege escalation",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} does not explicitly set allowPrivilegeEscalation=false.",
                        workload, container, ["allowPrivilegeEscalation is unset"], ["Set allowPrivilegeEscalation=false and validate the workload under the target runtime."]);
                }

                var dangerous = container.AddedCapabilities
                    .Where(capability => capability == "*" || DangerousCapabilities.Contains(capability, StringComparer.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (dangerous.Count > 0)
                {
                    var severity = dangerous.Contains("*", StringComparer.Ordinal) || dangerous.Contains("SYS_ADMIN", StringComparer.OrdinalIgnoreCase)
                        ? Severity.Critical
                        : Severity.High;
                    AddContainerFinding(findings, "POD_DANGEROUS_CAPABILITY", severity, "Container adds a powerful Linux capability",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} adds {string.Join(", ", dangerous)}.",
                        workload, container, dangerous, ["Remove unneeded capabilities; use a minimal allowlist and drop all capabilities before adding specific requirements."]);
                }

                if (!container.DropsAllCapabilities)
                {
                    AddContainerFinding(findings, "POD_DROP_CAPABILITIES_MISSING", Severity.Low, "Container does not drop all capabilities",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} has no capabilities.drop: [ALL] declaration.",
                        workload, container, ["capabilities.drop does not include ALL"], ["Drop all capabilities, then add back only the capabilities the application requires."]);
                }

                if (container.ReadOnlyRootFilesystem != true)
                {
                    AddContainerFinding(findings, "POD_ROOT_FILESYSTEM_WRITABLE", Severity.Medium, "Container root filesystem is not read-only",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} does not set readOnlyRootFilesystem=true.",
                        workload, container, ["readOnlyRootFilesystem is false or unset"], ["Set readOnlyRootFilesystem=true and provide writable volumes only for required paths."]);
                }

                if (string.IsNullOrWhiteSpace(container.SeccompProfileType))
                {
                    AddContainerFinding(findings, "POD_SECCOMP_UNSET", Severity.Medium, "Container has no explicit seccomp profile",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} has no seccomp profile in the inspected Pod or container settings.",
                        workload, container, ["seccompProfile.type is unset"], ["Set RuntimeDefault or a reviewed Localhost profile, and verify compatibility with the target runtime."]);
                }
                else if (container.SeccompProfileType.Equals("Unconfined", StringComparison.OrdinalIgnoreCase))
                {
                    AddContainerFinding(findings, "POD_SECCOMP_UNCONFINED", Severity.High, "Container disables seccomp filtering",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} uses seccompProfile.type=Unconfined.",
                        workload, container, ["seccompProfile.type=Unconfined"], ["Use RuntimeDefault or a reviewed Localhost profile."]);
                }

                if (!IsPinnedImage(container.Image))
                {
                    AddContainerFinding(findings, "POD_IMAGE_UNPINNED", Severity.Low, "Container image is not pinned by digest",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} uses '{container.Image}' without an immutable image digest.",
                        workload, container, [string.IsNullOrWhiteSpace(container.Image) ? "image is missing" : container.Image],
                        ["Pin production images by digest and verify signatures or provenance through your approved supply-chain controls."]);
                }
                if (!container.HasResourceRequests || !container.HasResourceLimits)
                {
                    AddContainerFinding(findings, "POD_RESOURCE_BOUNDS_MISSING", Severity.Low, "Container resource requests or limits are missing",
                        $"Container '{container.Name}' in {workload.Namespace}/{workload.Name} lacks a CPU or memory request or limit declaration.",
                        workload, container,
                        [container.HasResourceRequests ? "requests are present" : "requests are missing", container.HasResourceLimits ? "limits are present" : "limits are missing"],
                        ["Set resource requests and reviewed limits to reduce noisy-neighbor and resource-exhaustion risk."]);
                }
            }
        }
    }

    private static void AddNamespacePolicyFindings(Inventory inventory, Dictionary<string, Finding> findings)
    {
        foreach (var ns in inventory.Namespaces)
        {
            var mode = ns.Labels.GetValueOrDefault("pod-security.kubernetes.io/enforce");
            if (string.IsNullOrWhiteSpace(mode))
            {
                AddFinding(findings, "POD_SECURITY_ENFORCE_UNDECLARED", Severity.Medium, "Namespace does not declare a Pod Security enforce level",
                    $"Namespace '{ns.Name}' has no pod-security.kubernetes.io/enforce label in the supplied manifests. Cluster-wide defaults or external admission controls are not visible here.",
                    null, ns.Name, ns.Source,
                    ["pod-security.kubernetes.io/enforce is absent"],
                    ["Declare an appropriate Pod Security Admission enforce level for the namespace and verify any required exemptions."]);
            }
            else if (!mode.Equals("restricted", StringComparison.OrdinalIgnoreCase))
            {
                AddFinding(findings, "POD_SECURITY_ENFORCE_NOT_RESTRICTED", mode.Equals("privileged", StringComparison.OrdinalIgnoreCase) ? Severity.High : Severity.Medium,
                    "Namespace does not enforce the Restricted Pod Security Standard",
                    $"Namespace '{ns.Name}' declares enforce={mode}. Some workloads may need a different level, but that exception should be explicit.",
                    null, ns.Name, ns.Source,
                    [$"pod-security.kubernetes.io/enforce={mode}"],
                    ["Use enforce=restricted where workloads support it; otherwise document and isolate the narrow exception."]);
            }
        }
    }

    private static void AddNetworkPolicyFindings(Inventory inventory, Dictionary<string, Finding> findings)
    {
        var namespacesWithWorkloads = inventory.Workloads.Select(static workload => workload.Namespace)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static ns => ns, StringComparer.Ordinal);

        foreach (var ns in namespacesWithWorkloads)
        {
            var policies = inventory.NetworkPolicies.Where(policy => policy.Namespace == ns).ToList();
            if (policies.Count == 0)
            {
                AddFinding(findings, "NETWORKPOLICY_NONE", Severity.Medium, "Workload namespace has no NetworkPolicy",
                    $"The supplied manifests contain workloads in namespace '{ns}' but no NetworkPolicy. Kubernetes allows ingress and egress by default when a namespace has no selecting policy, subject to CNI and platform behavior.",
                    null, ns, inventory.Workloads.First(workload => workload.Namespace == ns).Source,
                    [$"namespace={ns}", "NetworkPolicy count=0"],
                    ["Define and test namespace-appropriate ingress and egress policies; confirm the CNI plugin enforces them."]);
                continue;
            }

            foreach (var direction in new[] { "ingress", "egress" })
            {
                var hasDefaultDeny = policies.Any(policy => policy.SelectsAllPods &&
                    (direction == "ingress" ? policy.DeniesIngressByDefault : policy.DeniesEgressByDefault));
                if (!hasDefaultDeny)
                {
                    AddFinding(findings, $"NETWORKPOLICY_NO_DEFAULT_DENY_{direction.ToUpperInvariant()}", Severity.Low,
                        $"No all-pod default-deny {direction} policy is visible",
                        $"Namespace '{ns}' has NetworkPolicy objects, but none in the supplied manifests selects all pods and leaves {direction} without allow rules. More targeted policies may still isolate selected workloads.",
                        null, ns, policies[0].Source,
                        policies.Select(static policy => policy.Name).ToList(),
                        [$"Review whether a namespace-wide default-deny {direction} policy is appropriate and verify coverage with the cluster's CNI plugin."],
                        "medium");
                }
            }

            foreach (var policy in policies.Where(static policy => policy.SelectsAllPods && (!policy.DeniesIngressByDefault || !policy.DeniesEgressByDefault)))
            {
                AddFinding(findings, "NETWORKPOLICY_ALL_PODS_NOT_DENIED", Severity.Medium, "All-pod NetworkPolicy allows a direction by omission or explicit rule",
                    $"NetworkPolicy '{policy.Name}' selects every pod in '{ns}' but does not default-deny both ingress and egress.",
                    null, ns, policy.Source,
                    [$"selects all pods={policy.SelectsAllPods}", $"default-deny ingress={policy.DeniesIngressByDefault}", $"default-deny egress={policy.DeniesEgressByDefault}"],
                    ["Confirm which directions should be isolated; NetworkPolicy allow rules are additive, so test the combined policy set with the cluster CNI."]);
            }
        }
    }

    private static bool IsFullWildcardRule(PolicyRule rule) =>
        ContainsWildcard(rule.ApiGroups) && ContainsWildcard(rule.Resources) && ContainsWildcard(rule.Verbs);

    private static bool ContainsWildcard(IReadOnlyList<string> values) =>
        values.Any(static value => value == "*");

    private static bool CanAny(
        IReadOnlyList<Grant> grants,
        IReadOnlyList<string> verbs,
        IReadOnlyList<string> resources,
        string apiGroup,
        string? namespaceName) =>
        grants.Any(grant => (namespaceName is null || HasScope(grant, namespaceName)) &&
            grant.Role.Rules.Any(rule => verbs.Any(verb => resources.Any(resource => RuleAllows(rule, verb, resource, apiGroup)))));

    private static bool RuleAllowsAnyVerb(PolicyRule rule, string resource, string apiGroup) =>
        SensitiveVerbs.Any(verb => RuleAllows(rule, verb, resource, apiGroup));

    private static bool CanManagePodWorkload(PolicyRule rule) =>
        PodProducingResources.Any(target => MutableWorkloadVerbs.Any(verb =>
            RuleAllows(rule, verb, target.Resource, target.ApiGroup)));

    private static bool RuleAllows(PolicyRule rule, string verb, string resource, string apiGroup) =>
        TokenMatches(rule.Verbs, verb)
        && ResourceMatches(rule.Resources, resource)
        && TokenMatches(rule.ApiGroups, apiGroup);

    private static bool TokenMatches(IReadOnlyList<string> patterns, string value) =>
        patterns.Any(pattern =>
            pattern == "*"
            || pattern.Equals(value, StringComparison.Ordinal));

    // Kubernetes permits */subresource, not resource/* prefix globs.
    private static bool ResourceMatches(IReadOnlyList<string> patterns, string value)
    {
        var slash = value.IndexOf('/');
        return TokenMatches(patterns, value)
            || (slash >= 0 && patterns.Contains("*" + value[slash..], StringComparer.Ordinal));
    }

    private static List<Grant> EffectiveGrants(string principal, List<Grant> allGrants)
    {
        var identities = new HashSet<string>(StringComparer.Ordinal) { principal };
        if (principal.StartsWith("User:", StringComparison.Ordinal) && principal != "User:system:anonymous")
        {
            identities.Add("Group:system:authenticated");
        }
        else if (principal.StartsWith("ServiceAccount:", StringComparison.Ordinal))
        {
            identities.Add("Group:system:authenticated");
            var rest = principal["ServiceAccount:".Length..];
            var slash = rest.IndexOf('/');
            if (slash > 0)
            {
                var ns = rest[..slash];
                identities.Add("Group:system:serviceaccounts");
                identities.Add($"Group:system:serviceaccounts:{ns}");
            }
        }
        else if (principal == "User:system:anonymous")
        {
            identities.Add("Group:system:unauthenticated");
        }
        return allGrants.Where(grant => identities.Contains(grant.Principal)).ToList();
    }

    private static bool HasScope(Grant grant, string ns) =>
        grant.Scope == "cluster" || (grant.Scope == "namespace" && grant.ScopeNamespace == ns);

    private static string ScopeLabel(IEnumerable<Grant> grants)
    {
        var scopes = grants.Select(static grant => grant.Scope == "cluster" ? "cluster-wide" : grant.ScopeNamespace)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static item => item, StringComparer.Ordinal)
            .ToList();
        return string.Join(", ", scopes);
    }

    private static (Grant Grant, bool Critical, string Description)? DescribeServiceAccountRisk(List<Grant> grants)
    {
        foreach (var grant in grants)
        {
            foreach (var rule in grant.Role.Rules)
            {
                if (IsFullWildcardRule(rule))
                    return (grant, true, "wildcard access to API groups, resources, and verbs");
                if (RuleAllows(rule, "bind", "roles", "rbac.authorization.k8s.io") || RuleAllows(rule, "bind", "clusterroles", "rbac.authorization.k8s.io")
                    || RuleAllows(rule, "escalate", "roles", "rbac.authorization.k8s.io") || RuleAllows(rule, "escalate", "clusterroles", "rbac.authorization.k8s.io"))
                    return (grant, true, "RBAC role-binding or role-escalation control");
                if (RuleAllows(rule, "get", "nodes/proxy", string.Empty) || RuleAllows(rule, "create", "nodes/proxy", string.Empty))
                    return (grant, true, "kubelet node-proxy access");
                if (RuleAllowsAnyVerb(rule, "secrets", string.Empty))
                    return (grant, false, "Kubernetes Secret access");
                if (RuleAllows(rule, "create", "serviceaccounts/token", string.Empty))
                    return (grant, false, "service-account token creation");
                if (RuleAllowsAnyVerb(rule, "clusterrolebindings", "rbac.authorization.k8s.io")
                    || RuleAllowsAnyVerb(rule, "rolebindings", "rbac.authorization.k8s.io"))
                    return (grant, false, "role-binding management");
                if (CanManagePodWorkload(rule))
                    return (grant, false, "ability to create additional workloads");
            }
        }
        return null;
    }

    private static bool IsPinnedImage(string image)
    {
        if (string.IsNullOrWhiteSpace(image))
        {
            return false;
        }
        var at = image.LastIndexOf('@');
        if (at <= 0 || !image[(at + 1)..].StartsWith("sha256:", StringComparison.Ordinal))
            return false;
        var digest = image[(at + 8)..];
        return digest.Length == 64 && digest.All(static ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static void AddContainerFinding(
        Dictionary<string, Finding> findings,
        string code,
        Severity severity,
        string title,
        string message,
        WorkloadDefinition workload,
        ContainerDefinition container,
        IReadOnlyList<string> evidence,
        IReadOnlyList<string> recommendations)
    {
        AddFinding(findings, code, severity, title, message, null, workload.Namespace, container.Source,
            [$"{workload.Kind} {workload.Namespace}/{workload.Name}", $"container={container.Name}", .. evidence],
            recommendations);
    }

    private static void AddWorkloadFinding(
        Dictionary<string, Finding> findings,
        string code,
        Severity severity,
        string title,
        string message,
        WorkloadDefinition workload,
        IReadOnlyList<string> evidence,
        IReadOnlyList<string> recommendations)
    {
        AddFinding(findings, code, severity, title, message, null, workload.Namespace, workload.Source,
            [$"{workload.Kind} {workload.Namespace}/{workload.Name}", .. evidence],
            recommendations);
    }

    private static void AddFinding(
        Dictionary<string, Finding> findings,
        string code,
        Severity severity,
        string title,
        string message,
        string? principal,
        string? ns,
        SourceRef source,
        IReadOnlyList<string> evidence,
        IReadOnlyList<string> recommendations,
        string confidence = "high")
    {
        var identityParts = new List<string> { code, principal ?? string.Empty, ns ?? string.Empty, source.File, source.Document.ToString(), title };
        identityParts.AddRange(evidence);
        var identity = string.Join('\n', identityParts);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)))[..12].ToLowerInvariant();
        var finding = new Finding($"KPATH-{code}-{digest}", severity, title, message, principal, ns, source, evidence, recommendations, confidence);
        findings.TryAdd(finding.Id, finding);
    }

    private static string RoleKey(RoleDefinition role) => RoleKey(role.Kind, role.Namespace, role.Name);
    private static string RoleKey(string kind, string ns, string name) => $"{kind}:{ns}:{name}";

    private static GraphNode RoleNode(RoleDefinition role) =>
        Node("role", RoleKey(role), $"{role.Kind} {role.Namespace}/{role.Name}");

    private static GraphNode Node(string kind, string key, string label)
    {
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{kind}\n{key}")))[..12].ToLowerInvariant();
        return new GraphNode($"{kind}-{digest}", kind, label);
    }

    private static void AddEdge(Dictionary<string, GraphEdge> edges, GraphEdge edge)
    {
        var key = $"{edge.From}\n{edge.To}\n{edge.Label}\n{edge.Condition}";
        edges.TryAdd(key, edge);
    }

    private static string DescribeRule(PolicyRule rule) =>
        $"apiGroups=[{string.Join(",", rule.ApiGroups)}]; resources=[{string.Join(",", rule.Resources)}]; verbs=[{string.Join(",", rule.Verbs)}]";
}
