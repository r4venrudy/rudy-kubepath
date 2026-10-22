# Example manifests

These examples are synthetic and are not intended for deployment.

- `unsafe-cluster.yaml` demonstrates a workload-creator path to a secret-reading service account, privileged container settings, a permissive Pod Security Admission label, and a namespace with no NetworkPolicy.
- `hardened-sample.yaml` shows narrower RBAC, disabled service-account token automount, a restricted Pod Security Admission label, container hardening, resource bounds, an image digest, and a default-deny NetworkPolicy.

Run `rudy-kubepath analyze examples/ --format text --fail-on high` to see a human-readable report. The unsafe example intentionally causes a nonzero exit because it crosses the selected severity gate. Use `--format sarif` to create GitHub Code Scanning input or `--format dot` to render the relationship graph with Graphviz.
