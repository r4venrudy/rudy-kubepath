# Contributing

Thanks for helping improve Rudy KubePath. Start with a focused issue or pull request that describes the Kubernetes behavior being modeled and cites the relevant upstream documentation.

## Development

Requirements: .NET 10 SDK.

```sh
dotnet restore tests/Rudy.KubePath.Tests/Rudy.KubePath.Tests.csproj
dotnet build tests/Rudy.KubePath.Tests/Rudy.KubePath.Tests.csproj --no-restore
dotnet test tests/Rudy.KubePath.Tests/Rudy.KubePath.Tests.csproj --no-build
```

Add regression tests for parser changes, scope rules, path inference, and output contracts. Keep findings explicit about assumptions and avoid representing inferred paths as guaranteed exploitability. Do not add cluster credentials, production manifests, or live-cluster side effects to fixtures or CI.

## Pull requests

- Explain the concrete behavior and include a small sanitized manifest fixture when it helps.
- Run the full test suite and mention any platform-specific validation limits.
- Update README and rule documentation when behavior or limitations change.
- Keep output deterministic and retain stable rule identifiers where possible.
