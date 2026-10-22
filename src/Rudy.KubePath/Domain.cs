namespace Rudy.KubePath;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public sealed record SourceRef(string File, int Document)
{
    public override string ToString() => $"{File}#document-{Document}";
}

public sealed record ManifestInput(string Path, string Text, long? ByteLength = null);

public sealed record PolicyRule(
    IReadOnlyList<string> ApiGroups,
    IReadOnlyList<string> Resources,
    IReadOnlyList<string> Verbs,
    IReadOnlyList<string> ResourceNames,
    IReadOnlyList<string> NonResourceUrls,
    SourceRef Source);

public sealed record RoleDefinition(
    string Kind,
    string Name,
    string Namespace,
    IReadOnlyList<PolicyRule> Rules,
    SourceRef Source);

public sealed record RoleSubject(string Kind, string Name, string Namespace);

public sealed record RoleBindingDefinition(
    string Kind,
    string Name,
    string Namespace,
    string RoleKind,
    string RoleName,
    IReadOnlyList<RoleSubject> Subjects,
    SourceRef Source);

public sealed record ServiceAccountDefinition(
    string Name,
    string Namespace,
    bool? AutomountServiceAccountToken,
    SourceRef Source,
    bool IsSynthetic = false);

public sealed record ContainerDefinition(
    string Name,
    string Image,
    bool? Privileged,
    bool? AllowPrivilegeEscalation,
    bool? RunAsNonRoot,
    long? RunAsUser,
    bool? ReadOnlyRootFilesystem,
    string? SeccompProfileType,
    IReadOnlyList<string> AddedCapabilities,
    bool DropsAllCapabilities,
    bool HasResourceRequests,
    bool HasResourceLimits,
    bool HasReadinessProbe,
    SourceRef Source);

public sealed record WorkloadDefinition(
    string Kind,
    string Name,
    string Namespace,
    string ServiceAccountName,
    bool? AutomountServiceAccountToken,
    bool HostNetwork,
    bool HostPid,
    bool HostIpc,
    bool HostProcess,
    IReadOnlyList<string> HostPaths,
    IReadOnlyList<ContainerDefinition> Containers,
    SourceRef Source);

public sealed record NetworkPolicyDefinition(
    string Name,
    string Namespace,
    bool SelectsAllPods,
    bool DeniesIngressByDefault,
    bool DeniesEgressByDefault,
    SourceRef Source);

public sealed record NamespaceDefinition(string Name, IReadOnlyDictionary<string, string> Labels, SourceRef Source);

public sealed class Inventory
{
    public List<RoleDefinition> Roles { get; } = [];
    public List<RoleBindingDefinition> Bindings { get; } = [];
    public List<ServiceAccountDefinition> ServiceAccounts { get; } = [];
    public List<WorkloadDefinition> Workloads { get; } = [];
    public List<NetworkPolicyDefinition> NetworkPolicies { get; } = [];
    public List<NamespaceDefinition> Namespaces { get; } = [];
    public List<Finding> InputFindings { get; } = [];
    public HashSet<string> ObservedNamespaces { get; } = new(StringComparer.Ordinal);
    public int DocumentCount { get; set; }
    public int FileCount { get; set; }
}

public sealed record Finding(
    string Id,
    Severity Severity,
    string Title,
    string Message,
    string? Principal,
    string? Namespace,
    SourceRef Source,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> Recommendations,
    string Confidence = "high");

public sealed record GraphNode(string Id, string Kind, string Label);
public sealed record GraphEdge(string From, string To, string Label, string? Condition = null);

public sealed record InventorySummary(
    int Files,
    int Documents,
    int Roles,
    int Bindings,
    int ServiceAccounts,
    int Workloads,
    int NetworkPolicies,
    int Findings,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info);

public sealed record AnalysisReport(
    string Schema,
    string ToolVersion,
    InventorySummary Summary,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<GraphNode> GraphNodes,
    IReadOnlyList<GraphEdge> GraphEdges);

public static class SeverityText
{
    public static string ToText(this Severity severity) => severity.ToString().ToUpperInvariant();

    public static int Rank(Severity severity) => severity switch
    {
        Severity.Critical => 4,
        Severity.High => 3,
        Severity.Medium => 2,
        Severity.Low => 1,
        _ => 0
    };
}
