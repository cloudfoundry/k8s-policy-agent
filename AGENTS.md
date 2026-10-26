# AGENTS.md

Guidance for humans and AI agents working in `k8s-policy-agent`. For contribution process
(PR scope, raising issues, code of conduct) see [`CONTRIBUTING.md`](CONTRIBUTING.md); this
file covers how the repo is built and how to work in it effectively.

## What this repo is

An alternative to Cloud Foundry's `vxlan-policy-agent` for Kubernetes, written in Go.
It polls the Cloud Foundry policy server over mutual TLS and translates application
security groups (ASGs) and container-to-container (C2C) policies into CNI resources:
`CiliumNetworkPolicy` for Cilium or `NetworkPolicy` from the Calico API. Both backends
are supported. Use `code.cloudfoundry.org/k8s-policy-agent` as the Go import path.

The agent discovers space GUIDs from labeled pods, fetches policies and security
groups, then reconciles the desired resources: create missing policies, update
changed policies, and remove obsolete policies labeled `app=policy-agent`.

## Layout

| Path | Responsibility |
| --- | --- |
| `cmd/policy-agent/main.go` | Startup, dependency wiring, logging, and shutdown signals. |
| `internal/agent/` | Polling loop, policy-server mTLS client, controller-runtime manager and cache. |
| `internal/config/` | Environment variables, defaults, and parsing. |
| `internal/reconciler/` | CNI-independent policy lifecycle and C2C aggregation. |
| `internal/cni/` | Translator interface and backend selection. |
| `internal/cni/{cilium,calico}/` | Backend-specific selectors, rules, resource types, and equality checks. |
| `internal/cni/util/` | Shared IP range utilities. |
| `internal/types/` | Shared label constants. |
| `internal/agent/agentfakes/` | Generated Counterfeiter test doubles. |
| `integration/` | Ginkgo connectivity tests; fixtures include SQL, manifests, and Helm/Kind values. |
| `helm/` | Deployment chart, values, and JSON schema. |
| `Makefile`, `Dockerfile`, `scripts/` | Build, test, image, and fake-generation tooling. |

## Running it

Use the Go version declared in `go.mod`; CI reads that file too. Run commands from
the repository root. Install `golangci-lint` to use the lint target.

```sh
make build  # builds bin/runner with CGO disabled
make unit   # non-integration tests; writes coverage.out
make lint   # golangci-lint run
make image  # builds policy-agent:latest; requires Docker
```

Running `bin/runner` requires Kubernetes credentials (kubeconfig locally or an
in-cluster service account), the selected CNI's APIs, and a reachable policy server
with valid client certificates. Configuration comes from environment variables;
see `internal/config/config.go` for the authoritative definitions.

| Variable | Default / requirement |
| --- | --- |
| `POLICY_SERVER_URL` | Required. |
| `CNI` | `cilium`; also supports `calico`. |
| `NAMESPACE` | `cf-workloads`; namespace for generated policies. |
| `POLL_INTERVAL` | `5s`; positive Go duration. |
| `PER_PAGE_SECURITY_GROUPS` | `100`. |
| `TLS_CERT_PATH` | `/etc/ssl/certs/policy-agent/tls.crt`. |
| `TLS_KEY_PATH` | `/etc/ssl/certs/policy-agent/tls.key`. |
| `TLS_CA_PATH` | `/etc/ssl/certs/policy-agent/ca.crt`. |

For deployment, use `helm/`; supply `certificateSecret` and set the CNI and policy
server address for the target cluster. The integration values files show working
chart configurations for each backend.

## Tests and generated code

- Tests use Ginkgo v2 and Gomega, with suites beside the code. Follow the nearby
  test conventions and use the existing Kubernetes fake client and Counterfeiter
  doubles where appropriate.
- For a focused run, use e.g. `go test -count=1 -vet=off ./internal/cni/...`.
  Use `make unit` for the full unit suite; `go test ./...` also includes integration
  tests that require external infrastructure.
- After changing an interface with a `counterfeiter:generate` directive, run
  `make generate` and include the regenerated fakes. This target deletes all
  `*fakes` directories before regenerating them; do not hand-edit generated files.
- Integration tests require Docker, Kind, Helm, kubectl, OpenSSL, and network
  access to download images and charts. Run `make integration-cilium` or
  `make integration-calico`, or `make integration` for both sequentially.
- Each integration target creates the Kind cluster `policy-agent`, generates
  test certificates, installs the CNI and supporting services, deploys the agent,
  and tests connectivity. Both targets share the cluster name and local files;
  do not run them concurrently or with `make -j`. kubectl/Helm setup commands use
  the current context, so use the disposable Kind context when running steps
  manually.
- Successful integration runs delete the cluster. After a failure, inspect it
  before running `make delete-kind` to clean up and allow a fresh run.

## Making changes

- Keep CNI-specific translation in its backend and shared reconciliation in
  `internal/reconciler/`. For shared policy behavior, check both backends and add
  corresponding coverage.
- Treat pod selectors, staging/running distinctions, policy names, and ownership
  labels as behavior contracts. Preserve which workloads receive a rule and
  which resources the agent can delete; test changes to those boundaries.
- Preserve the polling loop's behavior of skipping reconciliation when policy or
  security-group fetching fails, so a fetch failure does not become an empty
  desired policy set.
- Keep configuration changes aligned with `internal/config/`, Helm templates,
  `helm/values.yaml`, `helm/values.schema.json`, and relevant integration fixtures.
  Not every runtime environment variable is currently exposed by the chart.
- Format changed Go files with `gofmt`. Add regression coverage for behavior
  changes, run the relevant tests, and run `make unit`, `make lint`, and
  `make build` for Go changes. Use integration tests when translation or
  reconciliation changes can affect actual connectivity.
- Keep generated binaries, coverage output, and test certificates out of commits
  (`bin/`, `*.out`, and `certs/` are ignored). Summarize behavior changes and the
  checks run in the PR; explicitly identify any checks that could not be run.

## CI

- `.github/workflows/ci.yaml` runs lint, unit tests, and a container build, followed
  by separate Calico and Cilium integration jobs. The coverage check requires
  70% for `./internal/...`, with exclusions defined in the workflow. Successful
  integration on `main` also feeds release drafting.
- Treat the workflows, `Makefile`, and `go.mod` as the sources of truth for checks,
  commands, and tool versions; update this guide when those workflows change.
