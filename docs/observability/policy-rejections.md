# Runtime secret-policy rejection events

The runtime emits one canonical metadata event when its placeholder detector rejects
a secret that the connection is not permitted to substitute or pass through. All
three blocking actions emit it, including `block`. The sandbox tracing filter keeps
this target enabled with diagnostics off (no selected level), error, or any other
level. Packet-denial aggregation remains a separate event stream.

## Parser contract for Distributed

- Tracing target: `microsandbox::network::policy::rejection`.
- Level: `WARN`; message: `policy rejected request`.
- Structured field: `policy_rejection`, containing one compact JSON object.
- In the runtime's ANSI-free text log, locate the exact target and then the
  `policy_rejection=` field. Decode one JSON object from that position. Do not
  split its value on whitespace or depend on timestamps, JSON key order, or the
  surrounding formatter layout. A JSON tracing subscriber represents the field
  as a string containing that object.

The object has these fields:

| Field | Type | Contract |
| --- | --- | --- |
| `reason` | string | `secret_not_permitted`: the placeholder has no substitution or passthrough permission on this connection, including TLS-identity restrictions. |
| `host` | string | Connection SNI or inspected first-flight HTTP host; CONNECT uses its parsed target name. Falls back to the original guest destination IP when no name is known or the name contains a configured placeholder/credential, or empty when no destination metadata is attached. Truncated to 253 Unicode scalar values. |
| `dest_port` | integer or null | Original guest destination port, or null when no destination is attached. For CONNECT metadata this is the guest's proxy endpoint port. |
| `secret_env_var` | string | Configured secret environment name, truncated to 128 Unicode scalar values; empty if the name contains a configured placeholder/credential. |
| `protocol` | string | `http/1.1`, `http/2`, or `opaque`. HTTP/1 requires a parsed HTTP/1.0 or HTTP/1.1 request line; both use the `http/1.1` label. Unknown request-line versions use `opaque`. |
| `action` | string | `block`, `block-and-log`, or `block-and-terminate`. |
| `location` | string | `header`, `query`, `authorization_basic`, `body`, `chunk_metadata`, `trailer`, or `unknown`. |
| `match_form` | string | `raw`, `percent_decoded`, `json_unescaped`, or `basic_auth_decoded`. |
| `http2_stream_id` | integer or null | Inspected HTTP/2 stream ID when available. |

Untrusted string metadata is bounded before JSON encoding. JSON escapes quotes,
backslashes and control characters, so metadata cannot inject another log line.
Metadata containing configured placeholders or credential values is withheld
using ASCII-case-insensitive comparison, including after host normalization.
The event contains no placeholder, credential value, header value, request path,
query, body, grant marker, or provider response. Equivalent rejected requests
produce the same metadata regardless of unrelated guest payloads. Log-reader
validation and errors belong to Distributed, not this runtime event producer.

TLS, connect, broker, OAuth transform and ordinary EOF failures do not become this
event, even when an operational error uses `PermissionDenied`. Parser/framing
failures and unsupported substitution formats are not placeholder-permission
rejections and retain their existing handling.

## HTTP response boundary

Parsed HTTP/1 requests receive `HTTP/1.1 403 Forbidden` with the fixed body
`Secret not permitted on this connection\n` only before any request bytes have
been forwarded upstream on that connection. This includes first-flight header
and complete-body rejections, and inspected CONNECT metadata. Once forwarding
starts, a rejection emits the event and closes without a synthetic response.
The marker is connection-scoped and is not reset on keep-alive requests.
HTTP/2 and opaque rejections emit the event and close without HTTP/1 bytes.
HTTP-shaped request lines, including CONNECT, with versions other than HTTP/1.0
or HTTP/1.1 also close without a synthetic response.
`block-and-terminate` also invokes the existing sandbox termination hook.

Upstream responses are not stalled. Split-body rejections after forwarded headers
therefore close rather than append a 403, including after an early final response
or `100 Continue`. There is no response-state tracking or change to Expect handling.

## Validation

Run through the repository's devbox environment:

```sh
cargo test -p microsandbox-network --test secret_violation_logs
cargo test -p microsandbox-network --lib engine::secrets::handler
cargo test -p microsandbox-network --lib engine::tcp::proxy
cargo test -p microsandbox-network --lib engine::tls::proxy
cargo test -p microsandbox-cli --no-default-features --features net,ssh --lib log_args::tests
```

The real-loopback proxy fixture covers first-flight headers/body, split bodies,
an early upstream 200, Expect/100 Continue, CONNECT, opaque traffic, HTTP/2,
termination actions, diagnostics-off/error event capture and ordinary EOF.
Real plaintext and CONNECT cases cover normalized placeholder/credential hosts;
hostless non-HTTP and unknown-version cases, including CONNECT HTTP/1.2 and
HTTP/2.0, verify closure without a 403. CONNECT HTTP/1.0 retains its pre-forward 403.
Metadata checks cover repeated canonical events, bounds, escaping and absent secrets.
CLI tests exercise the actual runtime filter at every diagnostic level.

## Compatibility and fork delivery

This adds a log target and improves only pre-forward HTTP policy rejection
responses. SDK launch JSON, flags, control/agent protocols, catalogs, journals,
log paths and rotation are unchanged. Old SDKs can launch the new runtime using
the same contract; a new SDK with an old runtime gets its old rejection behavior
and cannot expect this event. No cross-version adapter or migration is required.

After separate operator release approval, Distributed's fork delivery route is
`.github/workflows/runtime-release.yml`, triggered by a new `v*-gitii.*` tag.
It publishes `microsandbox-runtime-<os>-<arch>.tar.gz` and `checksums.sha256`,
including `bin/msb`, libkrunfw, the Go FFI and `distributed-runtime.commit`.
It also creates `sdk/go/<tag>` for the Go module. Manual dispatch takes an
existing tag whose publication failed; published assets are never replaced.
Distributed must select the approved new runtime tag/checksums separately.
