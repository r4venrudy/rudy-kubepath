using YamlDotNet.RepresentationModel;
using YamlDotNet.Core;

namespace Rudy.KubePath;

public sealed class ManifestLoader
{
    public const int MaxYamlDocuments = 5_000;
    public const int MaxInputBytesPerFile = 8 * 1024 * 1024;
    public const int MaxWorkloadContainers = 20_000;

    public Inventory Parse(IEnumerable<ManifestInput> inputs)
    {
        var inventory = new Inventory();

        foreach (var input in inputs)
        {
            inventory.FileCount++;
            if ((input.ByteLength ?? System.Text.Encoding.UTF8.GetByteCount(input.Text)) > MaxInputBytesPerFile)
            {
                AddInputError(inventory, "INPUT_FILE_LIMIT", $"Input exceeds the {MaxInputBytesPerFile / (1024 * 1024)} MiB per-file limit.", input.Path, 0);
                continue;
            }

            try
            {
                var stream = new YamlStream();
                using var reader = new StringReader(input.Text);
                stream.Load(reader);

                foreach (var document in stream.Documents)
                {
                    if (inventory.DocumentCount >= MaxYamlDocuments)
                    {
                        AddInputError(inventory, "INPUT_DOCUMENT_LIMIT", $"Input exceeds the {MaxYamlDocuments} document limit.", input.Path, inventory.DocumentCount + 1);
                        return inventory;
                    }

                    inventory.DocumentCount++;
                    var source = new SourceRef(input.Path, inventory.DocumentCount);
                    ParseDocument(document.RootNode, source, inventory);
                }
            }
            catch (YamlException ex)
            {
                AddInputError(inventory, "YAML_PARSE_ERROR", ex.Message, input.Path, inventory.DocumentCount + 1);
            }
            catch (InvalidOperationException ex)
            {
                AddInputError(inventory, "MANIFEST_READ_ERROR", ex.Message, input.Path, inventory.DocumentCount + 1);
            }
        }

        AddSyntheticServiceAccounts(inventory);
        return inventory;
    }

    private static void ParseDocument(YamlNode rootNode, SourceRef source, Inventory inventory)
    {
        if (rootNode is not YamlMappingNode root)
        {
            AddInputError(inventory, "YAML_ROOT_NOT_MAPPING", "Each Kubernetes document must have a mapping at its root.", source.File, source.Document);
            return;
        }

        var kind = Scalar(Get(root, "kind"));
        var metadata = Mapping(Get(root, "metadata"));
        var name = Scalar(Get(metadata, "name"));
        var ns = Scalar(Get(metadata, "namespace"));

        switch (kind)
        {
            case "Role":
            case "ClusterRole":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", $"{kind} has no metadata.name.", source.File, source.Document);
                    return;
                }
                if (kind == "Role" && string.IsNullOrWhiteSpace(ns))
                {
                    AddInputError(inventory, "ROLE_NAMESPACE_MISSING", $"Role '{name}' has no metadata.namespace.", source.File, source.Document);
                    return;
                }
                ObserveNamespace(inventory, ns);
                inventory.Roles.Add(new RoleDefinition(kind, name, ns, ParseRules(Get(root, "rules"), source), source));
                break;

            case "RoleBinding":
            case "ClusterRoleBinding":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", $"{kind} has no metadata.name.", source.File, source.Document);
                    return;
                }
                if (kind == "RoleBinding" && string.IsNullOrWhiteSpace(ns))
                {
                    AddInputError(inventory, "BINDING_NAMESPACE_MISSING", $"RoleBinding '{name}' has no metadata.namespace.", source.File, source.Document);
                    return;
                }
                ObserveNamespace(inventory, ns);
                var roleRef = Mapping(Get(root, "roleRef"));
                var subjects = ParseSubjects(Get(root, "subjects"), ns);
                foreach (var subject in subjects.Where(static s => s.Kind.Equals("ServiceAccount", StringComparison.OrdinalIgnoreCase)))
                {
                    ObserveNamespace(inventory, subject.Namespace);
                }
                inventory.Bindings.Add(new RoleBindingDefinition(
                    kind,
                    name,
                    ns,
                    Scalar(Get(roleRef, "kind")),
                    Scalar(Get(roleRef, "name")),
                    subjects,
                    source));
                break;

            case "ServiceAccount":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", "ServiceAccount has no metadata.name.", source.File, source.Document);
                    return;
                }
                ns = string.IsNullOrWhiteSpace(ns) ? "default" : ns;
                ObserveNamespace(inventory, ns);
                inventory.ServiceAccounts.Add(new ServiceAccountDefinition(
                    name,
                    ns,
                    NullableBool(Get(root, "automountServiceAccountToken")),
                    source));
                break;

            case "Namespace":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", "Namespace has no metadata.name.", source.File, source.Document);
                    return;
                }
                var labels = new Dictionary<string, string>(StringComparer.Ordinal);
                var labelMap = Mapping(Get(metadata, "labels"));
                if (labelMap is not null)
                {
                    foreach (var pair in labelMap.Children)
                    {
                        var key = Scalar(pair.Key);
                        if (!string.IsNullOrWhiteSpace(key))
                        {
                            labels[key] = Scalar(pair.Value);
                        }
                    }
                }
                inventory.Namespaces.Add(new NamespaceDefinition(name, labels, source));
                ObserveNamespace(inventory, name);
                break;

            case "NetworkPolicy":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", "NetworkPolicy has no metadata.name.", source.File, source.Document);
                    return;
                }
                ns = string.IsNullOrWhiteSpace(ns) ? "default" : ns;
                ObserveNamespace(inventory, ns);
                var policySpec = Mapping(Get(root, "spec"));
                var selector = Mapping(Get(policySpec, "podSelector"));
                var selectsAll = selector is not null && selector.Children.Count == 0;
                var ingress = Sequence(Get(policySpec, "ingress"));
                var egress = Sequence(Get(policySpec, "egress"));
                var declaredTypes = Strings(Get(policySpec, "policyTypes")).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (declaredTypes.Count == 0)
                {
                    declaredTypes.Add("Ingress");
                    if (egress.Count > 0)
                    {
                        declaredTypes.Add("Egress");
                    }
                }
                inventory.NetworkPolicies.Add(new NetworkPolicyDefinition(
                    name,
                    ns,
                    selectsAll,
                    declaredTypes.Contains("Ingress") && ingress.Count == 0,
                    declaredTypes.Contains("Egress") && egress.Count == 0,
                    source));
                break;

            case "Pod":
            case "Deployment":
            case "StatefulSet":
            case "DaemonSet":
            case "ReplicaSet":
            case "Job":
            case "CronJob":
                if (string.IsNullOrWhiteSpace(name))
                {
                    AddInputError(inventory, "OBJECT_NAME_MISSING", $"{kind} has no metadata.name.", source.File, source.Document);
                    return;
                }
                ns = string.IsNullOrWhiteSpace(ns) ? "default" : ns;
                ObserveNamespace(inventory, ns);
                var podSpec = FindPodSpec(root, kind);
                if (podSpec is null)
                {
                    AddInputError(inventory, "POD_SPEC_MISSING", $"{kind} '{name}' has no recognized PodSpec.", source.File, source.Document);
                    return;
                }
                inventory.Workloads.Add(ParseWorkload(kind, name, ns, podSpec, source));
                var serviceAccountName = Scalar(Get(podSpec, "serviceAccountName"));
                if (!string.IsNullOrWhiteSpace(serviceAccountName))
                {
                    inventory.ServiceAccounts.Add(new ServiceAccountDefinition(serviceAccountName, ns, null, source));
                }
                break;

            default:
                // Other Kubernetes resources are intentionally ignored; this tool does not need a live API schema.
                break;
        }
    }

    private static IReadOnlyList<PolicyRule> ParseRules(YamlNode? node, SourceRef source)
    {
        var rules = new List<PolicyRule>();
        foreach (var item in Sequence(node))
        {
            var map = Mapping(item);
            if (map is null)
            {
                continue;
            }
            rules.Add(new PolicyRule(
                Strings(Get(map, "apiGroups"), includeEmpty: true),
                Strings(Get(map, "resources")),
                Strings(Get(map, "verbs")),
                Strings(Get(map, "resourceNames")),
                Strings(Get(map, "nonResourceURLs")),
                source));
        }
        return rules;
    }

    private static IReadOnlyList<RoleSubject> ParseSubjects(YamlNode? node, string bindingNamespace)
    {
        var subjects = new List<RoleSubject>();
        foreach (var item in Sequence(node))
        {
            var map = Mapping(item);
            if (map is null)
            {
                continue;
            }
            var kind = Scalar(Get(map, "kind"));
            var name = Scalar(Get(map, "name"));
            var ns = Scalar(Get(map, "namespace"));
            if (kind.Equals("ServiceAccount", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(ns))
            {
                ns = bindingNamespace;
            }
            if (!string.IsNullOrWhiteSpace(kind) && !string.IsNullOrWhiteSpace(name))
            {
                subjects.Add(new RoleSubject(kind, name, ns));
            }
        }
        return subjects;
    }

    private static WorkloadDefinition ParseWorkload(string kind, string name, string ns, YamlMappingNode podSpec, SourceRef source)
    {
        var podSecurity = Mapping(Get(podSpec, "securityContext"));
        var containers = new List<ContainerDefinition>();
        foreach (var section in new[] { "containers", "initContainers", "ephemeralContainers" })
        {
            foreach (var item in Sequence(Get(podSpec, section)))
            {
                var container = Mapping(item);
                if (container is null)
                {
                    continue;
                }
                var security = Mapping(Get(container, "securityContext"));
                var capabilities = Mapping(Get(security, "capabilities"));
                var dropped = Strings(Get(capabilities, "drop")).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var resources = Mapping(Get(container, "resources"));
                var windows = Mapping(Get(security, "windowsOptions"));
                var readiness = Get(container, "readinessProbe") is not null;
                containers.Add(new ContainerDefinition(
                    Scalar(Get(container, "name")),
                    Scalar(Get(container, "image")),
                    NullableBool(Get(security, "privileged")),
                    NullableBool(Get(security, "allowPrivilegeEscalation")),
                    NullableBool(Get(security, "runAsNonRoot")) ?? NullableBool(Get(podSecurity, "runAsNonRoot")),
                    NullableLong(Get(security, "runAsUser")) ?? NullableLong(Get(podSecurity, "runAsUser")),
                    NullableBool(Get(security, "readOnlyRootFilesystem")),
                    Scalar(Get(Mapping(Get(security, "seccompProfile")) ?? Mapping(Get(podSecurity, "seccompProfile")), "type")),
                    Strings(Get(capabilities, "add")),
                    dropped.Contains("ALL"),
                    HasCpuAndMemory(Get(resources, "requests")),
                    HasCpuAndMemory(Get(resources, "limits")),
                    readiness,
                    source));
            }
        }

        var hostPaths = new List<string>();
        foreach (var volume in Sequence(Get(podSpec, "volumes")))
        {
            var hostPath = Mapping(Get(Mapping(volume), "hostPath"));
            if (hostPath is not null)
            {
                var path = Scalar(Get(hostPath, "path"));
                hostPaths.Add(string.IsNullOrWhiteSpace(path) ? "(path unspecified)" : path);
            }
        }

        var podWindows = Mapping(Get(podSecurity, "windowsOptions"));
        var hostProcess = NullableBool(Get(podWindows, "hostProcess")) ?? false;
        foreach (var containerNode in Sequence(Get(podSpec, "containers")))
        {
            var windows = Mapping(Get(Mapping(containerNode), "windowsOptions"));
            hostProcess |= NullableBool(Get(windows, "hostProcess")) ?? false;
        }

        return new WorkloadDefinition(
            kind,
            name,
            ns,
            string.IsNullOrWhiteSpace(Scalar(Get(podSpec, "serviceAccountName"))) ? "default" : Scalar(Get(podSpec, "serviceAccountName")),
            NullableBool(Get(podSpec, "automountServiceAccountToken")),
            NullableBool(Get(podSpec, "hostNetwork")) ?? false,
            NullableBool(Get(podSpec, "hostPID")) ?? false,
            NullableBool(Get(podSpec, "hostIPC")) ?? false,
            hostProcess,
            hostPaths,
            containers,
            source);
    }

    private static YamlMappingNode? FindPodSpec(YamlMappingNode root, string kind)
    {
        var spec = Mapping(Get(root, "spec"));
        if (spec is null)
        {
            return null;
        }
        if (kind == "Pod")
        {
            return spec;
        }
        if (kind == "CronJob")
        {
            return Mapping(Get(Mapping(Get(Mapping(Get(spec, "jobTemplate")), "spec")), "template")) is { } cronTemplate
                ? Mapping(Get(cronTemplate, "spec"))
                : null;
        }
        return Mapping(Get(Mapping(Get(spec, "template")), "spec"));
    }

    private static void AddSyntheticServiceAccounts(Inventory inventory)
    {
        var seen = inventory.ServiceAccounts
            .Select(static sa => $"{sa.Namespace}/{sa.Name}")
            .ToHashSet(StringComparer.Ordinal);
        var sources = inventory.Bindings.Select(static b => b.Source)
            .Concat(inventory.Workloads.Select(static w => w.Source))
            .ToList();

        foreach (var binding in inventory.Bindings)
        {
            foreach (var subject in binding.Subjects.Where(static s => s.Kind.Equals("ServiceAccount", StringComparison.OrdinalIgnoreCase)))
            {
                if (!string.IsNullOrWhiteSpace(subject.Namespace) && !string.IsNullOrWhiteSpace(subject.Name))
                {
                    var key = $"{subject.Namespace}/{subject.Name}";
                    if (seen.Add(key))
                    {
                        inventory.ServiceAccounts.Add(new ServiceAccountDefinition(subject.Name, subject.Namespace, null, binding.Source, true));
                    }
                }
            }
        }

        foreach (var ns in inventory.ObservedNamespaces)
        {
            var key = $"{ns}/default";
            if (seen.Add(key))
            {
                inventory.ServiceAccounts.Add(new ServiceAccountDefinition("default", ns, null, sources.FirstOrDefault() ?? new SourceRef("<implicit>", 0), true));
            }
        }
    }

    private static void ObserveNamespace(Inventory inventory, string ns)
    {
        if (!string.IsNullOrWhiteSpace(ns))
        {
            inventory.ObservedNamespaces.Add(ns);
        }
    }

    private static void AddInputError(Inventory inventory, string id, string message, string path, int document)
    {
        inventory.InputFindings.Add(new Finding(
            id,
            Severity.High,
            "Manifest input could not be fully analyzed",
            message,
            null,
            null,
            new SourceRef(path, document),
            [path],
            ["Fix or remove the malformed input, then rerun the analysis."]));
    }

    internal static YamlMappingNode? Mapping(YamlNode? node) => node as YamlMappingNode;

    internal static YamlNode? Get(YamlMappingNode? map, string key)
    {
        if (map is null)
        {
            return null;
        }
        foreach (var pair in map.Children)
        {
            if (Scalar(pair.Key).Equals(key, StringComparison.Ordinal))
            {
                return pair.Value;
            }
        }
        return null;
    }

    internal static string Scalar(YamlNode? node) => (node as YamlScalarNode)?.Value ?? string.Empty;

    internal static List<YamlNode> Sequence(YamlNode? node) => node is YamlSequenceNode sequence
        ? sequence.Children.ToList()
        : [];

    internal static List<string> Strings(YamlNode? node, bool includeEmpty = false)
    {
        if (node is YamlScalarNode scalar)
        {
            return string.IsNullOrWhiteSpace(scalar.Value) && !includeEmpty ? [] : [scalar.Value ?? string.Empty];
        }
        return Sequence(node)
            .Select(Scalar)
            .Where(value => includeEmpty || !string.IsNullOrWhiteSpace(value))
            .ToList();
    }

    internal static bool? NullableBool(YamlNode? node)
    {
        if (node is not YamlScalarNode scalar || string.IsNullOrWhiteSpace(scalar.Value))
        {
            return null;
        }
        return bool.TryParse(scalar.Value, out var result) ? result : null;
    }

    internal static long? NullableLong(YamlNode? node) =>
        long.TryParse(Scalar(node), out var result) ? result : null;

    private static bool HasCpuAndMemory(YamlNode? node)
    {
        var map = Mapping(node);
        return Get(map, "cpu") is not null && Get(map, "memory") is not null;
    }
}
