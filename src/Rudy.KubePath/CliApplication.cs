using System.Text;

namespace Rudy.KubePath;

public sealed class CliApplication
{
    private const long MaxTotalInputBytes = 64L * 1024 * 1024;
    private const int DefaultMaxFiles = 1_000;
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".yaml", ".yml", ".json" };
    private static readonly HashSet<string> SkippedDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".terraform", "bin", "obj", "node_modules", ".venv", "vendor"
    };

    public int Run(string[] args, TextWriter? stdout = null, TextWriter? stderr = null)
    {
        stdout ??= Console.Out;
        stderr ??= Console.Error;

        if (args.Length == 0 || args.Any(static arg => arg is "--help" or "-h"))
        {
            stdout.WriteLine(Usage);
            return 0;
        }

        if (args[0] is not "analyze")
        {
            stderr.WriteLine($"Unknown command '{args[0]}'.");
            stderr.WriteLine(Usage);
            return 2;
        }

        var parsed = ParseOptions(args.Skip(1).ToArray());
        if (parsed.Error is not null)
        {
            stderr.WriteLine(parsed.Error);
            stderr.WriteLine(Usage);
            return 2;
        }
        if (parsed.Paths.Count == 0)
        {
            stderr.WriteLine("Supply at least one YAML, YML, or JSON file or directory.");
            stderr.WriteLine(Usage);
            return 2;
        }

        var (inputs, readFindings) = ReadInputs(parsed.Paths, parsed.MaxFiles);
        if (inputs.Count == 0 && readFindings.Count == 0)
        {
            stderr.WriteLine("No supported manifest files were found.");
            return 2;
        }

        var inventory = new ManifestLoader().Parse(inputs);
        inventory.InputFindings.AddRange(readFindings);
        var report = new Analyzer().Analyze(inventory, new AnalyzeOptions(
            CheckWorkloads: !parsed.NoWorkloadChecks,
            CheckNetworkPolicy: !parsed.NoNetworkPolicyChecks,
            FindServiceAccountPaths: !parsed.NoServiceAccountPaths));
        var output = OutputRenderer.Render(report, parsed.Format);

        try
        {
            if (parsed.OutputPath is null)
            {
                stdout.WriteLine(output);
            }
            else
            {
                var fullPath = Path.GetFullPath(parsed.OutputPath);
                var parent = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrWhiteSpace(parent))
                {
                    Directory.CreateDirectory(parent);
                }
                var temporary = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                File.WriteAllText(temporary, output + Environment.NewLine, new UTF8Encoding(false));
                File.Move(temporary, fullPath, true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            stderr.WriteLine($"Could not write output: {ex.Message}");
            return 3;
        }

        if (inventory.InputFindings.Count > 0)
        {
            return 2;
        }
        if (parsed.FailOn is not null && report.Findings.Any(finding => SeverityText.Rank(finding.Severity) >= SeverityText.Rank(parsed.FailOn.Value)))
        {
            return 1;
        }
        return 0;
    }

    private static (List<ManifestInput> Inputs, List<Finding> Findings) ReadInputs(IReadOnlyList<string> paths, int maxFiles)
    {
        var files = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var findings = new List<Finding>();
        var truncated = false;

        foreach (var path in paths)
        {
            if (File.Exists(path))
            {
                files.Add(Path.GetFullPath(path));
                continue;
            }
            if (!Directory.Exists(path))
            {
                findings.Add(InputFinding("INPUT_PATH_NOT_FOUND", $"Path '{path}' does not exist.", path));
                continue;
            }
            var pending = new Stack<string>();
            pending.Push(Path.GetFullPath(path));
            while (pending.Count > 0 && !truncated)
            {
                var current = pending.Pop();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(current).OrderBy(static file => file, StringComparer.OrdinalIgnoreCase))
                    {
                        if (Extensions.Contains(Path.GetExtension(file)))
                        {
                            files.Add(Path.GetFullPath(file));
                            if (files.Count > maxFiles)
                            {
                                truncated = true;
                                break;
                            }
                        }
                    }
                    foreach (var directory in Directory.EnumerateDirectories(current).OrderByDescending(static dir => dir, StringComparer.OrdinalIgnoreCase))
                    {
                        var info = new DirectoryInfo(directory);
                        if (!SkippedDirectoryNames.Contains(info.Name) && (info.Attributes & FileAttributes.ReparsePoint) == 0)
                        {
                            pending.Push(directory);
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    findings.Add(InputFinding("INPUT_DIRECTORY_UNREADABLE", ex.Message, current));
                }
            }
        }

        if (files.Count > maxFiles)
        {
            findings.Add(InputFinding("INPUT_FILE_COUNT_LIMIT", $"Directory walk exceeded the configured limit of {maxFiles} files; additional files were not analyzed.", string.Join(", ", paths)));
        }

        var inputs = new List<ManifestInput>();
        long totalBytes = 0;
        foreach (var file in files.Take(maxFiles))
        {
            try
            {
                var length = new FileInfo(file).Length;
                if (length > ManifestLoader.MaxInputBytesPerFile)
                {
                    inputs.Add(new ManifestInput(file, string.Empty, length));
                    continue;
                }
                if (totalBytes + length > MaxTotalInputBytes)
                {
                    findings.Add(InputFinding("INPUT_TOTAL_SIZE_LIMIT", $"Input set exceeds the {MaxTotalInputBytes / (1024 * 1024)} MiB total read limit; remaining files were not analyzed.", file));
                    break;
                }
                var text = File.ReadAllText(file, Encoding.UTF8);
                totalBytes += length;
                inputs.Add(new ManifestInput(file, text, length));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException)
            {
                findings.Add(InputFinding("INPUT_FILE_UNREADABLE", ex.Message, file));
            }
        }

        return (inputs, findings);
    }

    private static Finding InputFinding(string id, string message, string path) =>
        new(id, Severity.High, "Manifest input could not be fully analyzed", message, null, null,
            new SourceRef(path, 0), [path], ["Fix the input path or access issue, then rerun the analysis."]);

    private sealed record ParsedOptions(
        List<string> Paths,
        string Format,
        Severity? FailOn,
        int MaxFiles,
        string? OutputPath,
        bool NoWorkloadChecks,
        bool NoNetworkPolicyChecks,
        bool NoServiceAccountPaths,
        string? Error);

    private static ParsedOptions ParseOptions(string[] args)
    {
        var paths = new List<string>();
        var format = "text";
        Severity? failOn = Severity.Critical;
        var maxFiles = DefaultMaxFiles;
        string? output = null;
        var noWorkloadChecks = false;
        var noNetworkPolicyChecks = false;
        var noServiceAccountPaths = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg == "--format" && i + 1 < args.Length)
            {
                format = args[++i].ToLowerInvariant();
                if (format is not ("text" or "json" or "sarif" or "dot"))
                    return Error($"Unsupported format '{format}'.");
            }
            else if (arg == "--fail-on" && i + 1 < args.Length)
            {
                var value = args[++i].ToLowerInvariant();
                failOn = value switch
                {
                    "none" => null,
                    "critical" => Severity.Critical,
                    "high" => Severity.High,
                    "medium" => Severity.Medium,
                    "low" => Severity.Low,
                    "info" => Severity.Info,
                    _ => (Severity?)null
                };
                if (value is not ("none" or "critical" or "high" or "medium" or "low" or "info"))
                    return Error($"Unsupported --fail-on value '{value}'.");
            }
            else if (arg == "--max-files" && i + 1 < args.Length && int.TryParse(args[++i], out var limit) && limit is > 0 and <= 10_000)
            {
                maxFiles = limit;
            }
            else if (arg == "--output" && i + 1 < args.Length)
            {
                output = args[++i];
            }
            else if (arg == "--no-workload-checks")
            {
                noWorkloadChecks = true;
            }
            else if (arg == "--no-network-policy-checks")
            {
                noNetworkPolicyChecks = true;
            }
            else if (arg == "--no-service-account-paths")
            {
                noServiceAccountPaths = true;
            }
            else if (arg.StartsWith("-", StringComparison.Ordinal))
            {
                return Error($"Unknown option '{arg}'.");
            }
            else
            {
                paths.Add(arg);
            }
        }

        return new ParsedOptions(paths, format, failOn, maxFiles, output, noWorkloadChecks,
            noNetworkPolicyChecks, noServiceAccountPaths, null);

        static ParsedOptions Error(string message) =>
            new([], "text", Severity.Critical, DefaultMaxFiles, null, false, false, false, message);
    }

    private const string Usage = """
Rudy KubePath — offline Kubernetes permission and workload risk analysis

Usage:
  rudy-kubepath analyze <file-or-directory>... [options]

Options:
  --format text|json|sarif|dot    Output format (default: text)
  --fail-on none|critical|high|medium|low|info
                                Exit 1 when a finding meets or exceeds this severity (default: critical)
  --max-files <count>             Maximum files read from directories (default: 1000; max: 10000)
  --output <path>                 Write the report atomically to a file
  --no-workload-checks            Skip Pod security-context checks
  --no-network-policy-checks      Skip NetworkPolicy review
  --no-service-account-paths      Skip workload-to-ServiceAccount escalation paths
  -h, --help                      Show this help

Exit codes: 0 = gate passed, 1 = severity gate triggered, 2 = usage or incomplete input, 3 = output error.
The tool reads supplied files only; it never connects to a Kubernetes cluster.
""";
}
