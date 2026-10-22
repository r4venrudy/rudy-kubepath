using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rudy.KubePath;

public static class OutputRenderer
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static string Render(AnalysisReport report, string format) => format.ToLowerInvariant() switch
    {
        "json" => JsonSerializer.Serialize(report, JsonOptions),
        "sarif" => RenderSarif(report),
        "dot" => RenderDot(report),
        _ => RenderText(report)
    };

    private static string RenderText(AnalysisReport report)
    {
        var summary = report.Summary;
        var lines = new List<string>
        {
            $"Rudy KubePath {report.ToolVersion} | {summary.Files} files, {summary.Documents} documents",
            $"Inventory: {summary.Roles} roles, {summary.Bindings} bindings, {summary.ServiceAccounts} service accounts, {summary.Workloads} workloads, {summary.NetworkPolicies} network policies",
            $"Findings: {summary.Critical} critical, {summary.High} high, {summary.Medium} medium, {summary.Low} low, {summary.Info} info"
        };

        foreach (var finding in report.Findings)
        {
            lines.Add(string.Empty);
            lines.Add($"[{finding.Severity.ToText()}] {finding.Id}");
            lines.Add($"  {finding.Title}");
            lines.Add($"  {finding.Message}");
            lines.Add($"  Source: {finding.Source}");
            if (!string.IsNullOrWhiteSpace(finding.Principal))
            {
                lines.Add($"  Principal: {finding.Principal}");
            }
            if (!string.IsNullOrWhiteSpace(finding.Namespace))
            {
                lines.Add($"  Scope: {finding.Namespace}");
            }
            foreach (var item in finding.Evidence)
            {
                lines.Add($"  Evidence: {item}");
            }
            foreach (var item in finding.Recommendations)
            {
                lines.Add($"  Fix: {item}");
            }
            lines.Add($"  Confidence: {finding.Confidence}");
        }

        if (report.Findings.Count == 0)
        {
            lines.Add(string.Empty);
            lines.Add("No findings were produced. This result covers only the supplied manifests and implemented checks.");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string RenderSarif(AnalysisReport report)
    {
        var results = report.Findings.Select(finding =>
        {
            var ruleId = RuleId(finding.Id);
            return new
            {
                ruleId,
                level = SarifLevel(finding.Severity),
                message = new { text = finding.Message },
                locations = new[]
                {
                    new
                    {
                        physicalLocation = new
                        {
                            artifactLocation = new { uri = SarifUri(finding.Source.File) }
                        }
                    }
                },
                properties = new
                {
                    finding.Severity,
                    finding.Title,
                    finding.Principal,
                    finding.Namespace,
                    finding.Confidence,
                    finding.Evidence,
                    finding.Recommendations,
                    finding.Source.Document
                }
            };
        }).ToList();
        var rules = report.Findings
            .GroupBy(static finding => RuleId(finding.Id), StringComparer.Ordinal)
            .Select(static group => new { id = group.Key, name = group.First().Title, shortDescription = new { text = group.First().Title } })
            .ToList();
        var sarif = new Dictionary<string, object?>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new[]
            {
                new
                {
                    tool = new { driver = new { name = "Rudy KubePath", version = report.ToolVersion, rules } },
                    results
                }
            }
        };
        return JsonSerializer.Serialize(sarif, JsonOptions);
    }

    private static string RenderDot(AnalysisReport report)
    {
        var lines = new List<string>
        {
            "digraph RudyKubePath {",
            "  rankdir=LR;",
            "  graph [bgcolor=\"#101820\", fontcolor=\"#e6edf3\", fontname=\"Segoe UI\"];",
            "  node [style=filled, fillcolor=\"#16283a\", color=\"#55e0b6\", fontcolor=\"#e6edf3\", fontname=\"Segoe UI\"];",
            "  edge [color=\"#55e0b6\", fontcolor=\"#9eb4c8\", fontname=\"Segoe UI\"];"
        };
        foreach (var node in report.GraphNodes)
        {
            var shape = node.Kind switch
            {
                "principal" => "ellipse",
                "role" => "box",
                "binding" => "diamond",
                "permission" => "note",
                _ => "box"
            };
            lines.Add($"  \"{EscapeDot(node.Id)}\" [label=\"{EscapeDot(node.Label)}\", shape={shape}];");
        }
        foreach (var edge in report.GraphEdges)
        {
            var label = string.IsNullOrWhiteSpace(edge.Condition) ? edge.Label : $"{edge.Label}\\n{edge.Condition}";
            lines.Add($"  \"{EscapeDot(edge.From)}\" -> \"{EscapeDot(edge.To)}\" [label=\"{EscapeDot(label)}\"];");
        }
        lines.Add("}");
        return string.Join(Environment.NewLine, lines);
    }

    private static string SarifLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note"
    };

    private static string SarifUri(string path)
    {
        try
        {
            var workingDirectory = Path.GetFullPath(Environment.CurrentDirectory) + Path.DirectorySeparatorChar;
            var filePath = Path.GetFullPath(path);
            return new Uri(workingDirectory).MakeRelativeUri(new Uri(filePath)).ToString();
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UriFormatException or UnauthorizedAccessException)
        {
            return path.Replace('\\', '/');
        }
    }

    private static string RuleId(string findingId)
    {
        var separator = findingId.LastIndexOf('-');
        return separator > 0 ? findingId[..separator] : findingId;
    }

    private static string EscapeDot(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
