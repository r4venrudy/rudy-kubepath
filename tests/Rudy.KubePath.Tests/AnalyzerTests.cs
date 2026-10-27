using System.Text.Json;
using Rudy.KubePath;
using Xunit;

namespace Rudy.KubePath.Tests;

public sealed class AnalyzerTests
{
    [Theory]
    [InlineData("", false)]
    [InlineData("0123456789abcdef", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", false)]
    public void ImagePinRequiresACompleteHexDigest(string digest, bool pinned)
    {
        var report = Analyze($$"""
            apiVersion: v1
            kind: Pod
            metadata: { name: app, namespace: demo }
            spec:
              containers:
              - name: app
                image: "registry.invalid/app@sha256:{{digest}}"
            """);
        Assert.Equal(!pinned, report.Findings.Any(f => f.Id.Contains("POD_IMAGE_UNPINNED", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("*/proxy", true)]
    [InlineData("nodes/proxy", true)]
    [InlineData("*", true)]
    [InlineData("nodes/*", false)]
    [InlineData("*/scale", false)]
    public void SubresourceWildcardsMatchTheKubernetesAuthorizer(string resource, bool allowed)
    {
        var report = Analyze($$"""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: proxy }
            rules:
            - apiGroups: [""]
              resources: ["{{resource}}"]
              verbs: [get]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: proxy }
            subjects: [{ kind: User, name: alice }]
            roleRef: { kind: ClusterRole, name: proxy }
            """);
        Assert.Equal(allowed, report.Findings.Any(f => f.Id.Contains("RBAC_NODE_PROXY", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("secrets", "GET")]
    [InlineData("Secrets", "get")]
    public void RbacResourceAndVerbTokensAreCaseSensitive(string resource, string verb)
    {
        var report = Analyze($$"""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: reader }
            rules:
            - apiGroups: [""]
              resources: ["{{resource}}"]
              verbs: ["{{verb}}"]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: reader }
            subjects: [{ kind: User, name: alice }]
            roleRef: { kind: ClusterRole, name: reader }
            """);
        Assert.DoesNotContain(report.Findings, f => f.Id.Contains("RBAC_SECRET_ACCESS", StringComparison.Ordinal));
    }

    [Fact]
    public void RoleBindingScopesAClusterRoleToItsNamespace()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: secret-reader
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get, list]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata:
              name: alice-reader
              namespace: dev
            subjects:
            - kind: User
              name: alice
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: secret-reader
            """);

        var finding = SingleRule(report, "RBAC_SECRET_ACCESS");
        Assert.Equal("User:alice", finding.Principal);
        Assert.Equal("dev", finding.Namespace);
        Assert.DoesNotContain("cluster-wide", finding.Evidence);
    }

    [Fact]
    public void ClusterRoleBindingKeepsClusterWideScope()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: secret-reader
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: alice-reader
            subjects:
            - kind: User
              name: alice
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: secret-reader
            """);

        var finding = SingleRule(report, "RBAC_SECRET_ACCESS");
        Assert.Equal("cluster-wide", finding.Namespace);
    }

    [Fact]
    public void WildcardRuleIsCritical()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: everything }
            rules:
            - apiGroups: ["*"]
              resources: ["*"]
              verbs: ["*"]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: alice-everything }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: everything }
            """);

        Assert.Equal(Severity.Critical, SingleRule(report, "RBAC_FULL_WILDCARD").Severity);
    }

    [Fact]
    public void UnauthenticatedGroupGrantIsCritical()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: reader }
            rules:
            - apiGroups: [""]
              resources: [pods]
              verbs: [get]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: anonymous-read }
            subjects: [{ kind: Group, name: system:unauthenticated }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader }
            """);

        Assert.Equal(Severity.Critical, SingleRule(report, "RBAC_ANONYMOUS_BINDING").Severity);
    }

    [Fact]
    public void MissingRoleReferenceIsReported()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: broken, namespace: dev }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: absent }
            """);

        Assert.Contains(report.Findings, finding => finding.Id.Contains("RBAC_ROLE_REF_NOT_FOUND", StringComparison.Ordinal));
    }

    [Fact]
    public void ClusterRoleBindingCannotReferenceANamespacedRole()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: invalid }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: local }
            """);

        Assert.Contains(report.Findings, finding => finding.Id.Contains("RBAC_INVALID_ROLE_REF_KIND", StringComparison.Ordinal));
    }

    [Fact]
    public void PodCreatorCanReachSensitiveServiceAccountPermissions()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: api-reader, namespace: blue }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: secret-reader, namespace: blue }
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get, list]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: bind-api-reader, namespace: blue }
            subjects: [{ kind: ServiceAccount, name: api-reader, namespace: blue }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: secret-reader }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: deployer, namespace: blue }
            rules:
            - apiGroups: [apps]
              resources: [deployments]
              verbs: [create]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: alice-deployer, namespace: blue }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: deployer }
            """);

        var path = SingleRule(report, "RBAC_SERVICEACCOUNT_PATH");
        Assert.Equal(Severity.High, path.Severity);
        Assert.Equal("User:alice", path.Principal);
        Assert.Contains("ServiceAccount blue/api-reader", path.Message);
        Assert.Contains(report.GraphEdges, edge => edge.Label == "can select service account");
    }

    [Fact]
    public void PodCreatorCanChangeExistingWorkloadsToUseServiceAccount()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: elevated, namespace: blue }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: token-maker, namespace: blue }
            rules:
            - apiGroups: [""]
              resources: [serviceaccounts/token]
              verbs: [create]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: bind-elevated, namespace: blue }
            subjects: [{ kind: ServiceAccount, name: elevated, namespace: blue }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: token-maker }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: editor, namespace: blue }
            rules:
            - apiGroups: [apps]
              resources: [deployments]
              verbs: [patch, update]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: alice-editor, namespace: blue }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: editor }
            """);

        Assert.Contains(report.Findings, finding => finding.Id.Contains("RBAC_SERVICEACCOUNT_PATH", StringComparison.Ordinal));
    }

    [Fact]
    public void ServiceAccountPathsCanChainAcrossNamespaces()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: bridge, namespace: blue }
            ---
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: elevated, namespace: red }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: launch-in-red }
            rules:
            - apiGroups: [apps]
              resources: [deployments]
              verbs: [create]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: bridge-can-launch }
            subjects: [{ kind: ServiceAccount, name: bridge, namespace: blue }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: launch-in-red }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: read-red-secrets, namespace: red }
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get, list]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: elevated-can-read-secrets, namespace: red }
            subjects: [{ kind: ServiceAccount, name: elevated, namespace: red }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: read-red-secrets }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: blue-deployer, namespace: blue }
            rules:
            - apiGroups: [apps]
              resources: [deployments]
              verbs: [create]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: alice-blue-deployer, namespace: blue }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: blue-deployer }
            """);

        var findings = report.Findings.Where(finding => finding.Id.Contains("RBAC_SERVICEACCOUNT_PATH", StringComparison.Ordinal)).ToList();
        Assert.Contains(findings, finding => finding.Principal == "User:alice" &&
            finding.Message.Contains("red/elevated", StringComparison.Ordinal) &&
            finding.Evidence.Any(item => item.Contains("blue/bridge", StringComparison.Ordinal)));
    }

    [Fact]
    public void PodLevelAutomountFalseOverridesServiceAccountDefault()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: worker, namespace: blue }
            automountServiceAccountToken: true
            ---
            apiVersion: v1
            kind: Pod
            metadata: { name: worker, namespace: blue }
            spec:
              serviceAccountName: worker
              automountServiceAccountToken: false
              containers:
              - name: app
                image: example.invalid/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            """);

        Assert.DoesNotContain(report.Findings, finding => finding.Id.Contains("POD_SERVICE_ACCOUNT_TOKEN_AUTOMOUNT", StringComparison.Ordinal));
    }

    [Fact]
    public void NamespaceServiceAccountGroupFlowsToKnownServiceAccounts()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: app, namespace: prod }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: reader }
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: prod-readers }
            subjects: [{ kind: Group, name: system:serviceaccounts:prod }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader }
            """);

        Assert.Contains(report.Findings, finding =>
            finding.Id.Contains("RBAC_SECRET_ACCESS", StringComparison.Ordinal)
            && finding.Principal == "ServiceAccount:prod/app");
    }

    [Fact]
    public void PodSecurityFindingsCoverPrivilegeAndHostPath()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: Pod
            metadata: { name: risky, namespace: prod }
            spec:
              hostPID: true
              volumes:
              - name: host
                hostPath:
                  path: /var/run/containerd/containerd.sock
              containers:
              - name: app
                image: example.invalid/app:latest
                securityContext:
                  privileged: true
                  runAsUser: 0
            """);

        Assert.Contains(report.Findings, finding => finding.Id.Contains("POD_PRIVILEGED", StringComparison.Ordinal));
        Assert.Contains(report.Findings, finding => finding.Id.Contains("POD_HOSTPATH", StringComparison.Ordinal));
        Assert.Contains(report.Findings, finding => finding.Id.Contains("POD_HOST_NAMESPACE", StringComparison.Ordinal));
        Assert.Contains(report.Findings, finding => finding.Id.Contains("POD_ROOT_USER", StringComparison.Ordinal));
        Assert.Contains(report.Findings, finding => finding.Id.Contains("POD_IMAGE_UNPINNED", StringComparison.Ordinal));
    }

    [Fact]
    public void DeploymentTemplateIsParsedAndPodFieldsAreInherited()
    {
        var report = Analyze("""
            apiVersion: apps/v1
            kind: Deployment
            metadata: { name: api, namespace: prod }
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    seccompProfile:
                      type: RuntimeDefault
                  containers:
                  - name: app
                    image: registry.invalid/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
                    securityContext:
                      allowPrivilegeEscalation: false
                      capabilities:
                        drop: [ALL]
                      readOnlyRootFilesystem: true
                    resources:
                      requests: { cpu: 100m, memory: 64Mi }
                      limits: { cpu: 200m, memory: 128Mi }
            """);

        Assert.Equal(1, report.Summary.Workloads);
        Assert.DoesNotContain(report.Findings, finding =>
            finding.Id.Contains("POD_SECCOMP_UNSET", StringComparison.Ordinal)
            || finding.Id.Contains("POD_RUN_AS_NON_ROOT_MISSING", StringComparison.Ordinal)
            || finding.Id.Contains("POD_IMAGE_UNPINNED", StringComparison.Ordinal)
            || finding.Id.Contains("POD_RESOURCE_BOUNDS_MISSING", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingNetworkPolicyIsExplainedAsDefaultAllow()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: Pod
            metadata: { name: web, namespace: public }
            spec:
              containers:
              - name: app
                image: registry.invalid/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            """);

        var finding = SingleRule(report, "NETWORKPOLICY_NONE");
        Assert.Contains("ingress and egress by default", finding.Message);
    }

    [Fact]
    public void AllPodDefaultDenyIngressAndEgressAreRecognized()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: Pod
            metadata: { name: web, namespace: private }
            spec:
              containers:
              - name: app
                image: registry.invalid/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            ---
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: { name: default-deny, namespace: private }
            spec:
              podSelector: {}
              policyTypes: [Ingress, Egress]
            """);

        Assert.DoesNotContain(report.Findings, finding =>
            finding.Id.Contains("NETWORKPOLICY_NO_DEFAULT_DENY", StringComparison.Ordinal)
            || finding.Id.Contains("NETWORKPOLICY_ALL_PODS_NOT_DENIED", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceNamesDoNotRestrictCreateForPodPathAnalysis()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: ServiceAccount
            metadata: { name: privileged, namespace: ns1 }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: secret-reader, namespace: ns1 }
            rules:
            - apiGroups: [""]
              resources: [secrets]
              verbs: [get]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: bind-sa, namespace: ns1 }
            subjects: [{ kind: ServiceAccount, name: privileged, namespace: ns1 }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: secret-reader }
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: { name: creator, namespace: ns1 }
            rules:
            - apiGroups: [""]
              resources: [pods]
              resourceNames: [only-this-name]
              verbs: [create]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: { name: bind-alice, namespace: ns1 }
            subjects: [{ kind: User, name: alice }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: creator }
            """);

        Assert.Contains(report.Findings, finding => finding.Id.Contains("RBAC_SERVICEACCOUNT_PATH", StringComparison.Ordinal));
    }

    [Fact]
    public void MalformedYamlIsAHighSeverityIncompleteInput()
    {
        var inventory = new ManifestLoader().Parse([new ManifestInput("bad.yaml", "kind: [")]);
        var report = new Analyzer().Analyze(inventory);

        Assert.Contains(report.Findings, finding => finding.Id == "YAML_PARSE_ERROR");
        Assert.Equal(1, report.Summary.High);
    }

    [Fact]
    public void JsonOutputIsMachineReadableAndHasTheContractVersion()
    {
        var report = Analyze("""
            apiVersion: v1
            kind: Pod
            metadata: { name: tiny, namespace: dev }
            spec:
              containers:
              - name: app
                image: example.invalid/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            """);

        using var json = JsonDocument.Parse(OutputRenderer.Render(report, "json"));
        Assert.Equal("rudy-kubepath/v1", json.RootElement.GetProperty("schema").GetString());
        Assert.True(json.RootElement.GetProperty("findings").GetArrayLength() > 0);
    }

    [Fact]
    public void SarifAndDotOutputsHaveExpectedStructure()
    {
        var report = Analyze("""
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata: { name: dangerous }
            rules:
            - apiGroups: ["*"]
              resources: ["*"]
              verbs: ["*"]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata: { name: all }
            subjects: [{ kind: Group, name: system:authenticated }]
            roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: dangerous }
            """);

        using var sarif = JsonDocument.Parse(OutputRenderer.Render(report, "sarif"));
        Assert.Equal("2.1.0", sarif.RootElement.GetProperty("version").GetString());
        var result = sarif.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
        Assert.False(string.IsNullOrWhiteSpace(result.GetProperty("locations")[0]
            .GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()));
        Assert.False(result.GetProperty("locations")[0].GetProperty("physicalLocation").TryGetProperty("region", out _));
        Assert.Contains("digraph RudyKubePath", OutputRenderer.Render(report, "dot"));
    }

    [Fact]
    public void CliFailureGateUsesRequestedSeverity()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kubepath-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, """
            apiVersion: v1
            kind: Pod
            metadata: { name: app, namespace: dev }
            spec:
              containers:
              - name: app
                image: example.invalid/app:latest
                securityContext:
                  readOnlyRootFilesystem: true
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false
                  capabilities:
                    drop: [ALL]
                  seccompProfile:
                    type: RuntimeDefault
            """);
        try
        {
            var output = new StringWriter();
            var error = new StringWriter();
            var exitCode = new CliApplication().Run(["analyze", path, "--format", "json", "--fail-on", "low"], output, error);
            Assert.Equal(1, exitCode);
            Assert.Empty(error.ToString());
            Assert.Contains("POD_IMAGE_UNPINNED", output.ToString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static AnalysisReport Analyze(string yaml)
    {
        var inventory = new ManifestLoader().Parse([new ManifestInput("fixtures/input.yaml", yaml)]);
        return new Analyzer().Analyze(inventory);
    }

    private static Finding SingleRule(AnalysisReport report, string code)
    {
        var findings = report.Findings
            .Where(finding => finding.Id.Contains(code, StringComparison.Ordinal))
            .ToList();
        Assert.Single(findings);
        return findings[0];
    }
}
