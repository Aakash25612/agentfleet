# agentfleet

A take-home for the staff engineer role. Three parts:

- **[DESIGN.md](DESIGN.md):** the architecture for ~1,000 concurrent multi-tenant agents on Kubernetes. 4 pages plus 3 diagrams.
- **This PoC:** one vertical slice of that design, runnable with one command.
- **[AI_LOG.md](AI_LOG.md):** where AI helped, where I overrode it, and what I did without it.

## Run it

You need Docker with Compose v2 (Docker Desktop or Linux) and about 1.5 GB of disk. You don't need Go or Kubernetes.

```bash
make demo    # build, start the stack, run scripted agents, print the audit trail
make test    # safety suite (unit tests already ran inside the image build)
make bench   # cold start, warm exec, proxy overhead
make audit TENANT=acme AGENT=repo-triager   # the auditor's question
make down    # stop everything, remove leftover sandboxes
```

`make demo` ends with `all expectations held` and exits 0. It exits non-zero if any expectation fails.

**gVisor.** If your Docker daemon has `runsc` registered as a runtime, the executor detects it and uses it. You can also force it with `SANDBOX_RUNTIME=runsc make demo`. If `runsc` isn't there, sandboxes run under `runc` with the same hardening, and the demo says so in its first line. Nothing else changes.

## The slice and why I picked it

**The slice is the credential boundary for execution tools.** It has three parts:
- a sandbox whose only route out is an egress proxy;
- a proxy that holds the tenant's credentials, authorizes each request against the agent's pinned definition, injects the credential and strips it from responses;
- an audit trail that ties each request to the tool call that caused it.

**Why this one.** The rest of the design uses patterns I've already built: durable workflows on Temporal, an API gateway with policy checks, fair queuing. What I was *least* sure of was the requirement "credentials never enter the model context", applied to **execution** tools. An agent that can run `gh`, `git`, `curl` or a Python script can read anything in its environment. If unmodified CLIs could not work with a credential they can't read, that requirement would fail for the riskiest kind of tool. Every other part of the design would then need a different shape: tokens inside sandboxes, so leaking them becomes an accepted risk.

**What it proves:**
- Unmodified `gh` 2.62 and `curl`, `git` and Python `urllib` work through it.
- A real token is never readable inside the sandbox.
- Every egress decision is attributed to the exact tool call.

**What I learned building it:**
1. **A Docker `internal` network still exposes the host.** The host owns the bridge address and answers on every port it listens on. My first probe got HTTP 200 from a host service. The fix is `com.docker.network.bridge.inhibit_ipv4`, and a test now sweeps the sandbox subnet for any neighbour. The Kubernetes version of the same lesson: check that NetworkPolicy also blocks node and host-network IPs, which depends on the CNI.
2. **The first version of that test passed for the wrong reason.** With no gateway, the proxy takes the subnet's `.1` address, so a probe of `.1` answered "connection refused" in both the fixed and broken builds. I only found this by deliberately breaking the code to make sure the test failed (*mutation testing*).
3. **Injecting by host is not enough.** "github.internal gets acme's token" also lets an injected agent file issues in `evil-org/*` as acme. Grants have to be scoped by method and path.
4. **Cold start breaks down under concurrency.** 420 ms p50 for one sandbox becomes 4.3 s p50 for 20 at once on 2 vCPUs, mostly from network setup. Warm pools are a requirement, not an optimisation.

**What I'd build second:** the durable run workflow (Temporal) that calls this executor. Its "an exec was interrupted, so the workspace is restored to step k and the command is not re-run" contract is the interface between the two halves. It's also where the node-loss failure mode in DESIGN §6 actually gets exercised.

## What's in the box

```
cmd/egressproxy   the egress proxy: sandbox identity, authz, TLS termination, credential injection, redaction
cmd/executor      sandbox lifecycle and the exec tool API (docker engine API, stdlib only)
cmd/afinit        PID 1 inside each sandbox: writes the tenant CA, reaps zombies
cmd/demo          the orchestrator, played by a scripted fake model
cmd/mockup        fake GitHub, exfiltration sink, cloud metadata service
cmd/auditq        "show me every command agent X ran last Tuesday"
internal/policy   agent definitions + Authorize(): the code both enforcement points share
internal/audit    append-only, hash-chained JSONL, verification, queries
internal/netguard resolve-then-check-then-dial; blocks metadata/link-local/loopback/CGNAT
agents/           versioned agent definitions (the registry)
test/e2e          the safety suite, run against the live stack
```

Go standard library only. There are no third-party modules to audit.

## What's real and what's faked

| Real | Faked or simplified |
|---|---|
| Sandbox isolation: own network with no gateway, read-only rootfs, all capabilities dropped, no-new-privileges, non-root, memory, pids, CPU and workspace limits, per-command timeout plus an outer kill-all guard | The LLM. A scripted list of tool calls stands in for the model (`cmd/demo`). |
| The egress proxy: CONNECT, TLS termination with a per-tenant CA, method/host/path authorization, credential injection, response redaction, IP-literal / plaintext / port denial, resolve-then-dial address checks | GitHub, the attacker endpoint and cloud metadata are local mocks. The metadata mock really sits at `169.254.169.254`. |
| Unmodified `gh`, `curl`, `git`, `python3` and `pandoc` running inside the sandbox | Credentials are static values in `config/tenant-credentials.json`, mounted only into the proxy. In the design, Vault or a GitHub App mints short-lived tokens. |
| A sandbox's identity at the proxy: a per-session credential **bound to the source IP** | There is no Temporal and no orchestrator. Runs are driven directly against the executor API. |
| Hash-chained audit log written *before* each effect, failing closed if the write fails | The audit log is local fsynced JSONL, not Kafka/ClickHouse/Object Lock. |
| Agent definitions that are versioned and pinned per run | Hibernation is just deletion; the workspace isn't snapshotted. |

### Why Docker Compose and not kind

The properties this slice demonstrates are network topology, the credential path and process confinement. Kubernetes adds nothing to proving them, and it's slower for you to run. The mapping is direct:

| PoC (Docker) | Kubernetes (design) |
|---|---|
| A network per session (`internal`, `inhibit_ipv4`), with only the proxy attached | Default-deny NetworkPolicy; egress only to the proxy Service |
| `HostConfig.Runtime=runsc` | `runtimeClassName: gvisor` via `SandboxTemplate` |
| ReadonlyRootfs, CapDrop ALL, no-new-privileges, user 65534 | Pod `securityContext` |
| Memory, NanoCPUs, PidsLimit, tmpfs `size=` | `resources.limits`, pid limit, emptyDir `sizeLimit` |
| Executor registers `(session, IP) → run identity` with the proxy | The proxy watches `SandboxClaim`s for pod IP → run labels |
| The executor sweeps containers labelled `agentfleet.session` on start | Owner references plus a reaper on run completion |

## Tests

Unit tests (`internal/...`) run inside `docker build`, so a red test is a red build. `make test` runs the end-to-end suite from a container on the platform network against the live proxy, executor and real sandboxes. Each test runs an attack from *inside* a sandbox and checks two things: what the agent saw, and what actually arrived at the other end (every mock counts what it receives).

| Test | Property it proves |
|---|---|
| `TestCredentialUsableButNeverVisible` | `gh` authenticates as the tenant, but the real token isn't in the env, `/proc/*/environ`, files, `gh auth token`, an API that echoes it back, or the audit log. The upstream only ever saw the real token, never the placeholder. |
| `TestTenantGetsOwnCredentialAndCA` | Same command, other tenant: other identity and other CA. |
| `TestUngrantedHostGetsNothing` | curl, plaintext, Python, git and proxy bypass to an attacker host all fail. **The sink received 0 requests.** Every denial is audited. |
| `TestGrantIsScopedToMethodPathAndVersion` | POST to `acme/*` is allowed; another org, path traversal, DELETE and the wrong API are denied. A run pinned to v2 (read-only) can't POST. The upstream never saw a denied request. |
| `TestMetadataEndpointUnreachable` | Direct, via the proxy, IP literal, and *a grant that allows a name resolving to 169.254.169.254*: all refused. **The metadata service received 0 requests.** |
| `TestNoRouteOutExceptTheProxy` | No route to another tenant's sandbox, the proxy admin API, the executor, the upstreams or the internet. No default route and no other neighbour on the sandbox subnet, so the Docker host isn't reachable. A stolen session credential fails (407) from another IP. |
| `TestSandboxConfinement` | Non-root, no capabilities, no-new-privileges, read-only rootfs. pids, memory and disk limits hit. The timeout kills; a detached child holding stdout open doesn't hang the tool call; the sandbox survives all of it. |
| `TestEveryActionIsAttributed` | Each exec and egress event carries tenant, agent@version, run, user and the tool call id. Editing the real log breaks verification. |
| `TestAgentWithoutExecToolGetsNoSandbox` | An agent without the exec grant gets no sandbox; a tenant can't resolve another tenant's agent. |

**The tests fail when their protection is removed** (mutation-checked while building): removing `inhibit_ipv4` fails the routing test; removing source-IP binding fails it too; removing redaction fails the credential test and the proxy unit tests.

### Numbers

From `make bench` on a 2-vCPU, 8 GB Linux VM with runc. gVisor will add some start-up and syscall overhead.

| | |
|---|---|
| Sandbox cold start, one at a time | p50 **420 ms** |
| Sandbox cold start, 20 at once | p50 4.3 s, p99 5.3 s. Breakdown at p50: network setup 1.6 s, start 1.3 s, create 0.8 s, ready 0.4 s |
| Warm exec of `true`, 20 sandboxes busy at once | p50 0.9 s, p99 1.7 s (CPU-bound on 2 vCPUs) |
| Proxied HTTPS request (authz + inject + redact + 2 fsynced audit writes) | p50 **2 ms**, p99 7 ms |

## Known gaps

- **gVisor resource limits are not what `TestSandboxConfinement` asserts.** On this machine I installed `runsc` release-20260928.0 and reran the suite. `make demo` passed, and so did the credential, routing, metadata and audit tests. The confinement test did not: a pid bomb made `runsc` return `WaitPID ... EOF` and the sandbox died, so the pid and disk checks never completed. An OOM under gVisor ends the whole sandbox (`exit 137, sandbox terminated`) rather than one process. That test was verified under runc. Escape resistance is still gVisor's claim, not something this PoC proves.
- **Both images were built from the Dockerfiles in this repo** (`debian:bookworm-slim` plus `gh` 2.62.0 for the sandbox; the services image from `images/services.Dockerfile`). `make demo` and `make test` passed on that build under runc.
- **The proxy buffers responses up to 16 MB** so it can redact them. Larger responses fail closed (502), which won't do for large downloads. The fix is streaming redaction with a window the size of the longest secret.
- **Only the HTTP Authorization-style header is injected.** Request-signing schemes such as AWS SigV4 need a signer per credential type in the proxy.
- **Single proxy instance, in-memory session map.** In the design, the session map is rebuilt from `SandboxClaim`s and the proxy scales horizontally.
- **Sandbox subnets come from `10.231.0.0/16`, and the compose networks use `172.29.0.0/24`, `172.29.1.0/24` and `169.254.169.0/24`.** If these clash with a VPN or existing Docker networks, change them in `internal/executor` and `docker-compose.yml`.
- **No workspace snapshot or restore**, so hibernation is deletion.

## Time

About 8 hours, stopped at the budget: 1 hour reading the brief and choosing the slice, 2 hours on the design, 4 hours on the proof of concept, 1 hour on the README, the AI log, and running `make demo` and `make test` locally.
