//! Shared sandbox domain types.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use microsandbox_types_macros::ConfigPatch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use typed_path::{Utf8Component, Utf8UnixComponent, Utf8UnixPath};
use zeroize::Zeroizing;

use crate::modify::SecretSource;
use crate::{TypesError, TypesResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of virtual CPUs in a sandbox specification.
pub const DEFAULT_SANDBOX_CPUS: u8 = 1;

/// Default guest memory in MiB in a sandbox specification.
pub const DEFAULT_SANDBOX_MEMORY_MIB: u32 = 512;

/// Default metrics sampling interval in milliseconds.
pub const DEFAULT_METRICS_SAMPLE_INTERVAL_MS: u64 = 1000;

/// The well-known NAT64 prefix from RFC 6052.
pub const WELL_KNOWN_NAT64_PREFIX: &str = "64:ff9b::/96";

//--------------------------------------------------------------------------------------------------
// Types: Root Filesystems
//--------------------------------------------------------------------------------------------------

/// Disk image format for virtio-blk root filesystems and volume mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum DiskImageFormat {
    /// QEMU Copy-on-Write v2.
    Qcow2,
    /// Raw disk image.
    Raw,
    /// VMware Disk (FLAT/ZERO only, no delta links).
    Vmdk,
}

/// Strategy used to create a sandbox-owned instance of a cached flat rootfs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum FlatClone {
    /// Use a native copy-on-write clone when supported, otherwise make a sparse copy.
    #[default]
    Auto,

    /// Always create an independent sparse-aware copy.
    Copy,

    /// Require a native copy-on-write clone and fail when it is unavailable.
    Reflink,
}

/// Root filesystem source for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum RootfsSource {
    /// Use a host directory directly as the root filesystem.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
        /// Whether to follow symlinks when resolving the host rootfs path.
        ///
        /// Defaults to `false`: the path is resolved following no symlink in any
        /// component, matching the `--mount` protection, so a symlink at or under
        /// the rootfs path cannot redirect the mount. Set `true` to opt out when
        /// the host rootfs path legitimately traverses a symlink.
        #[serde(default)]
        follow_root_symlinks: bool,
    },

    /// Use an OCI image reference with an EROFS lower and ext4 overlay upper.
    Oci(OciRootfsSource),

    /// Use a disk image file as the root filesystem via virtio-blk.
    DiskImage {
        /// Path to the disk image file on the host.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
        /// Disk image format.
        format: DiskImageFormat,
        /// Inner filesystem type (optional; auto-detected if absent).
        fstype: Option<String>,
    },
}

/// OCI root filesystem source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct OciRootfsSource {
    /// OCI image reference (e.g. `python`).
    pub reference: String,

    /// Writable rootfs layer backing. `None` resolves to a managed 4 GiB upper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk: Option<RootDisk>,
}

/// Backing for the writable rootfs layer (overlay upper) of an OCI sandbox.
///
/// This lives only on [`OciRootfsSource`]: the root disk is a property of how an OCI image
/// becomes a rootfs. Every user surface (CLI `--root-disk`, SDK builders) is sugar resolving
/// into this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RootDisk {
    /// Sparse ext4 created and owned by microsandbox in the sandbox dir. Default. Persistent;
    /// grow-only via modify; deleted with the sandbox.
    Managed {
        /// Virtual size in MiB. `None` resolves to 4096.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },

    /// RAM-backed upper. Ephemeral: the rootfs is pristine on every boot. Pages come from
    /// guest memory, so the size must not exceed the sandbox memory.
    Tmpfs {
        /// Size in MiB. `None` resolves to half the sandbox memory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },

    /// User-supplied disk image attached writable as the upper. User-owned lifecycle: never
    /// created, resized, or deleted by microsandbox.
    DiskImage {
        /// Host path to the image file.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        path: PathBuf,
        /// Disk image format. Never probed from file contents.
        format: DiskImageFormat,
        /// Inner filesystem type. `None` resolves to ext4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fstype: Option<String>,
    },

    /// A complete OCI root filesystem materialized into one private writable filesystem.
    ///
    /// This is microsandbox-owned like [`RootDisk::Managed`], but it replaces the layered
    /// EROFS-plus-OverlayFS topology rather than supplying only its writable upper.
    Flat {
        /// Final guest filesystem capacity in MiB. `None` resolves to the greater of 4096 MiB
        /// and the materialized image's minimum size.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
        /// Generated filesystem type. `None` resolves to ext4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fstype: Option<String>,
        /// Requested private-instance strategy.
        #[serde(default, skip_serializing_if = "FlatClone::is_auto")]
        clone: FlatClone,
    },
}

/// Controls when an OCI registry is contacted for manifest freshness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum PullPolicy {
    /// Use cached layers if complete, pull otherwise.
    #[default]
    IfMissing,

    /// Always fetch the manifest from the registry, reusing cached layers whose digests still match.
    Always,

    /// Never contact the registry. Error if the image is not fully cached locally.
    Never,
}

//--------------------------------------------------------------------------------------------------
// Types: Mounts
//--------------------------------------------------------------------------------------------------

/// Stat virtualization policy for a virtiofs-backed volume mount.
///
/// Serializes/deserializes as the lowercase variant name (`"strict"`, `"relaxed"`, `"off"`) so persisted JSON aligns with the CLI grammar (`stat-virt=strict|relaxed|off`) and the NAPI string contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum StatVirtualization {
    /// Fail-closed: probe the host backing path; require xattr support.
    Strict,
    /// Opportunistic: apply the overlay when present; tolerate missing xattr support.
    Relaxed,
    /// Literal host metadata: do not read or apply the override xattr.
    Off,
}

/// Host permission propagation policy for a virtiofs-backed volume mount.
///
/// Serializes/deserializes as the lowercase variant name (`"private"`, `"mirror"`) to align with the CLI and NAPI spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum HostPermissions {
    /// Guest chmod stays in the metadata overlay only.
    Private,
    /// Mirror ordinary rwx bits for regular files and directories to the host inode.
    Mirror,
}

/// Sandbox-level in-guest security profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    /// Preserve normal guest-root semantics.
    ///
    /// Exec sessions do not set `no_new_privs` and keep `CAP_SYS_ADMIN`, so workflows such as `sudo`, package managers, and Docker-in-Docker work as they would in a regular VM.
    #[default]
    Default,

    /// Harden guest exec sessions.
    ///
    /// Agentd sets `no_new_privs`, drops `CAP_SYS_ADMIN`, and forces `nosuid,nodev` on user mounts. Workloads that need privilege elevation or guest mount administration, such as `sudo` and Docker-in-Docker, are intentionally incompatible with this profile.
    Restricted,
}

/// Host-runtime isolation profile applied when a sandbox is deployed.
///
/// Unlike [`SecurityProfile`], which changes behavior inside the guest, this
/// profile controls defenses enforced by host-side runtime backends. A hosting
/// platform can override the requested value before launch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    /// The sandbox runs for one trusted tenant with the requested host-runtime configuration.
    #[default]
    SingleTenant,

    /// The sandbox runs on shared infrastructure with platform-owned isolation floors.
    MultiTenant,
}

/// Guest mount behavior shared by every volume mount kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct MountOptions {
    /// Whether the mount is read-only.
    ///
    /// Guest writes fail with the kernel's read-only filesystem behavior. Virtiofs-backed mounts also reject writes on the host-side filesystem server as defense in depth.
    pub readonly: bool,

    /// Whether direct execution from the mount is disabled.
    ///
    /// This prevents `execve` of binaries or scripts located on the mount. Interpreters can still read files from the mount, for example `sh /mnt/script.sh`, because the interpreter itself executes from a different filesystem.
    pub noexec: bool,

    /// Whether setuid and setgid privilege elevation from files on the mount is ignored.
    pub nosuid: bool,

    /// Whether device files on the mount are ignored.
    pub nodev: bool,

    /// Guest uid presented for host files under this mount that carry no
    /// per-file stat override.
    ///
    /// Host-created files (written outside the guest) have no override, so
    /// without this they surface with the runtime's fallback owner. When set,
    /// such files are presented as this uid instead. Must be set together with
    /// [`override_gid`](Self::override_gid). `None` keeps the fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_uid: Option<u32>,

    /// Guest gid presented for host files under this mount that carry no
    /// per-file stat override. See [`override_uid`](Self::override_uid); the two
    /// must be set together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_gid: Option<u32>,
}

/// Storage kind for a named volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum VolumeKind {
    /// Directory-backed named volume mounted through virtiofs.
    Directory,

    /// Raw ext4 disk-image named volume mounted through virtio-blk.
    Disk,
}

/// Configuration for creating a named volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct VolumeSpec {
    /// Volume name.
    pub name: String,

    /// Storage kind.
    pub kind: VolumeKind,

    /// Size quota in MiB. `None` means unlimited.
    pub quota_mib: Option<u32>,

    /// Disk capacity in MiB. Required for disk volumes.
    pub capacity_mib: Option<u32>,

    /// Labels for organization.
    pub labels: Vec<(String, String)>,
}

/// Sandbox-time behavior for a named volume mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum NamedVolumeMode {
    /// Require the named volume to already exist.
    Existing,

    /// Create the named volume and fail if it already exists.
    Create,

    /// Ensure the named volume exists, or reuse a compatible existing volume.
    EnsureExists,
}

/// Creation metadata for sandbox-time named volume provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NamedVolumeCreate {
    /// Creation behavior for this named volume mount.
    pub mode: NamedVolumeMode,

    /// Volume name to create or ensure exists.
    pub name: String,

    /// Storage kind to create or ensure exists.
    pub kind: VolumeKind,

    /// Directory quota in MiB, if configured.
    pub quota_mib: Option<u32>,

    /// Disk capacity in MiB, if configured.
    pub capacity_mib: Option<u32>,

    /// Labels to attach to newly-created volumes.
    pub labels: Vec<(String, String)>,
}

/// Storage for a volume whose lifetime belongs exclusively to its sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum OwnedVolumeStorage {
    /// A private directory exposed through virtiofs.
    Directory {
        /// Guest-write budget in MiB; `None` uses the directory-mount default.
        quota_mib: Option<u32>,
    },
    /// A private ext4 disk exposed through virtio-blk.
    Disk {
        /// Required, positive capacity in MiB.
        capacity_mib: u32,
    },
}

/// A volume mount specification for a sandbox.
#[derive(Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(tag = "type"))]
pub enum VolumeMount {
    /// An unnamed private volume removed with its owning sandbox.
    Owned {
        /// Guest mount path, also the stable identity within the sandbox.
        guest: String,
        /// Directory or ext4 disk storage.
        storage: OwnedVolumeStorage,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy for directory storage.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy for directory storage.
        host_permissions: HostPermissions,
    },
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
        /// Whether to follow symlinks when resolving the host mount root.
        ///
        /// Defaults to `false`: the host path is resolved following no symlink in
        /// any component, so a symlink planted at (or under) the mount root cannot
        /// redirect the mount out of its intended target. Set `true` to opt out
        /// when the host path legitimately traverses a symlink.
        follow_root_symlinks: bool,
        /// Guest-write byte budget in MiB.
        ///
        /// Bounds how much the guest may add beyond the directory's existing
        /// contents. `None` applies the protective default at spawn time; set a
        /// value to override it.
        quota_mib: Option<u32>,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Creation metadata for sandbox-time named volume provisioning.
        ///
        /// This is transient and intentionally skipped when sandbox configs are persisted; restarting a sandbox mounts the already-created volume.
        create: Option<NamedVolumeCreate>,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
        /// Whether to follow symlinks when resolving the host mount root.
        ///
        /// Defaults to `false` (resolve following no symlink). See
        /// [`VolumeMount::Bind`] for details.
        follow_root_symlinks: bool,
    },

    /// Temporary filesystem backed by guest memory.
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        size_mib: Option<u32>,
        /// Guest mount behavior.
        options: MountOptions,
    },

    /// Mount a disk image file as a virtio-blk device at a guest path.
    DiskImage {
        /// Host path to the disk image file.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Disk image format.
        format: DiskImageFormat,
        /// Inner filesystem type. When `None`, agentd probes `/proc/filesystems`.
        fstype: Option<String>,
        /// Guest mount behavior.
        options: MountOptions,
    },
}

/// Rootfs patch applied before VM startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Patch {
    /// Write text content to a file.
    Text {
        /// Absolute guest path, such as `/etc/app.conf`.
        path: String,
        /// Text content to write.
        content: String,
        /// File permissions, such as `0o644`. `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },

    /// Write raw bytes to a file.
    File {
        /// Absolute guest path.
        path: String,
        /// Raw byte content to write.
        content: Vec<u8>,
        /// File permissions, such as `0o644`. `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },

    /// Copy a file from the host into the rootfs.
    CopyFile {
        /// Host path to copy from.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// File permissions. `None` preserves source permissions.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },

    /// Copy a directory from the host into the rootfs.
    CopyDir {
        /// Host directory to copy from.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// Allow replacing files that already exist in the rootfs.
        replace: bool,
    },

    /// Create a symlink.
    Symlink {
        /// Symlink target path.
        target: String,
        /// Absolute guest path where the symlink is created.
        link: String,
        /// Allow replacing a path that already exists in the rootfs.
        replace: bool,
    },

    /// Create a directory.
    Mkdir {
        /// Absolute guest path.
        path: String,
        /// Directory permissions, such as `0o755`. `None` uses the default.
        mode: Option<u32>,
    },

    /// Remove a file or directory.
    Remove {
        /// Absolute guest path to remove.
        path: String,
    },

    /// Append content to an existing file.
    Append {
        /// Absolute guest path of the file to append to.
        path: String,
        /// Content to append.
        content: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Types: Networking
//--------------------------------------------------------------------------------------------------

/// HTTP responses returned when network policy denies a request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct HttpConfig {
    /// Return readable HTTP 403 responses for supported denied requests. Default: false.
    pub deny_response: bool,

    /// Denial response body. `{host}` names the blocked host.
    /// Used only when `deny_response` is enabled. Omission uses the default;
    /// an empty string produces an empty body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_message: Option<String>,
}

/// Complete network specification for a sandbox.
///
/// Common, backend-visible fields are typed directly. Rich local-engine subdocuments such as policy, DNS, TLS, secrets, and interface overrides are carried as JSON so the shared contract can preserve them without depending on the local networking engine crate.
#[derive(Debug, Clone, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct NetworkSpec {
    /// Whether networking is enabled for this sandbox.
    pub enabled: bool,

    /// Guest interface overrides for the local network engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nested)]
    pub interface: Option<InterfaceOverrides>,

    /// Host-to-guest port mappings.
    pub ports: Vec<PublishedPortSpec>,

    /// Egress and ingress policy subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicy>,

    /// DNS interception and filtering subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nested)]
    pub dns: Option<DnsConfig>,

    /// TLS interception subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nested)]
    pub tls: Option<TlsConfig>,

    /// Require hostname-based policy allows to use inspectable application authority.
    pub strict: bool,

    /// Secret substitution subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nested)]
    pub secrets: Option<SecretsConfig>,

    /// TCP connection cap. `max_connections` is a deprecated configuration alias.
    // Keep saved configurations readable by releases that predate the TCP-specific name.
    #[serde(rename = "max_connections", alias = "max_tcp_connections")]
    pub max_tcp_connections: Option<usize>,

    /// Max concurrent UDP relay sessions. Omitted is unlimited for single-tenant and 1024 for multi-tenant; zero means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_udp_connections: Option<usize>,

    /// Accept-queue depth for published TCP port listeners, `1..=2147483647`. Omitted is 1024.
    /// The host kernel clamps it to `net.core.somaxconn` (Linux) or `kern.ipc.somaxconn` (macOS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_accept_queue_size: Option<u32>,

    /// Local network rate limits. Missing means unlimited in both directions.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nested)]
    pub rate_limiter: Option<NetworkRateLimiterConfig>,

    /// NAT64 `/96` prefixes for policy classification.
    #[serde(default = "default_nat64_prefixes")]
    #[cfg_attr(feature = "ts", ts(type = "Array<string>"))]
    #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
    pub nat64_prefixes: Vec<Ipv6Network>,

    /// Whether to copy trusted host CAs into the guest at boot.
    pub trust_host_cas: bool,

    /// HTTP denial response settings.
    #[config_patch(nested)]
    pub http: HttpConfig,

    /// Proxy used for outbound sandbox connections and supported datagram flows.
    ///
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` inherits defaults; use a sparse patch to clear.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[config_patch(nullable)]
    pub outbound_proxy: Option<OutboundProxy>,
}

/// Proxy configuration for outbound sandbox connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "protocol", rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundProxy {
    /// An HTTP proxy that opens TCP tunnels with CONNECT.
    #[serde(rename = "http_connect")]
    HttpConnect {
        /// Proxy socket address.
        address: String,
    },

    /// A SOCKS4 proxy at the given `IP:port` address.
    Socks4 {
        /// Proxy socket address.
        address: String,
        /// Optional user ID sent during the SOCKS4 handshake.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
    },

    /// A SOCKS5 proxy at the given `IP:port` address.
    Socks5 {
        /// Proxy socket address.
        address: String,
        /// Optional username/password authentication credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials: Option<Socks5Credentials>,
    },
}

/// Environment-backed username/password credentials for a SOCKS5 proxy.
///
/// This durable configuration contains only the host-side password source.
/// The resolved password is carried by the private launch contract instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Socks5Credentials {
    /// SOCKS5 authentication username.
    pub username: String,

    /// Host-side source for the SOCKS5 authentication password.
    pub password: SecretSource,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct PublishedPortSpec {
    /// Host-side port to bind.
    pub host_port: u16,

    /// Guest-side port to forward to.
    pub guest_port: u16,

    /// Transport protocol.
    #[serde(default)]
    pub protocol: PortProtocol,

    /// Host address to bind. Defaults to loopback.
    pub host_bind: String,
}

/// Transport protocol for a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum PortProtocol {
    /// TCP.
    #[default]
    #[serde(rename = "tcp")]
    Tcp,

    /// UDP.
    #[serde(rename = "udp")]
    Udp,
}

//--------------------------------------------------------------------------------------------------
// Types: Vsock
//--------------------------------------------------------------------------------------------------

/// Host services exposed to a sandbox through virtio-vsock.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct VsockSpec {
    /// Guest-to-host routes registered before the VM starts.
    pub routes: Vec<VsockRouteSpec>,
}

impl VsockSpec {
    /// Return whether no host services are exposed through vsock.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// One host local-IPC endpoint exposed on a host-CID vsock port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct VsockRouteSpec {
    /// Existing Unix socket path or local Windows named-pipe path.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub host_socket: PathBuf,

    /// Port guests address on `VMADDR_CID_HOST` (CID 2).
    pub port: u32,

    /// Message semantics used by the guest and host endpoints.
    #[serde(default)]
    pub socket_type: VsockSocketType,
}

/// Socket semantics for a host-CID vsock route.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum VsockSocketType {
    /// Reliable, ordered byte stream.
    #[default]
    Stream,

    /// Best-effort message transport preserving datagram boundaries.
    Dgram,
}

//--------------------------------------------------------------------------------------------------
// Types: Init
//--------------------------------------------------------------------------------------------------

/// Fully-assembled handoff-init specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct HandoffInit {
    /// Init binary: absolute path inside the guest rootfs, or the literal `auto`.
    ///
    /// Always a Linux-style `/`-separated path — never build it with host OS path APIs, whose semantics diverge on Windows (`\` separators, `/sbin/init` treated as relative).
    pub cmd: String,

    /// Supplemental argv. `argv[0]` is implicitly `cmd`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Extra env vars merged on top of the inherited env.
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

//--------------------------------------------------------------------------------------------------
// Types: Lifecycle
//--------------------------------------------------------------------------------------------------

/// Sandbox lifecycle policy.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxPolicy {
    /// Whether the sandbox is ephemeral.
    ///
    /// Ephemeral sandboxes are one-off: the host runtime that owns the
    /// process removes the persisted DB row and on-disk state when the VM
    /// reaches a terminal status, and other host runtimes opportunistically
    /// clean up ephemeral leftovers from runtimes that died before they
    /// could self-clean. Defaults to `false` (persistent); named and created
    /// sandboxes stay inspectable and restartable after they stop.
    #[serde(default)]
    pub ephemeral: bool,

    /// Hard cap on total sandbox lifetime in seconds. `None` = run forever.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds. `None` = no idle detection.
    pub idle_timeout_secs: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Types: Snapshots
//--------------------------------------------------------------------------------------------------

/// Inputs to create a snapshot.
///
/// Installed artifacts live at `dest_dir/<group>/<snapshot_id>`. A friendly name
/// is scoped to the group; it does not change the portable snapshot identity.
/// Save/load moves artifacts between stores without starting a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SnapshotSpec {
    /// Optional guest writeback policy. Auto flushes live disk-only captures, not full RAM.
    #[serde(default)]
    pub guest_flush: crate::GuestFlush,
    /// Friendly member name within a group; empty selects a generated name.
    pub name: String,

    /// Local snapshot group; defaults to the source sandbox's name.
    #[serde(default)]
    pub group: Option<String>,

    /// Group-store root. `None` selects the default snapshots directory.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub dest_dir: Option<PathBuf>,

    /// Source sandbox. Disk capture accepts running, paused, or stopped sources.
    pub source_sandbox: String,

    /// User-supplied labels.
    pub labels: Vec<(String, String)>,

    /// Overwrite a direct archive destination; installed members remain immutable.
    pub force: bool,

    /// Compute and record upper-layer content integrity at creation time.
    pub record_integrity: bool,

    /// Capture disk, memory, execution, and device state from a running sandbox.
    #[serde(default)]
    pub full: bool,
}

//--------------------------------------------------------------------------------------------------
// Types: Sandbox Specs
//--------------------------------------------------------------------------------------------------

/// Backend-neutral sandbox task description.
///
/// This is the durable contract for fields that are already shared across backends. Local-only execution state such as resolved manifest digests, snapshot upper-layer paths, registry credentials, replace flags, and backend dispatch stays outside this type.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxSpec {
    /// Unique sandbox name.
    pub name: String,

    /// Root filesystem source.
    #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
    pub image: RootfsSource,

    /// CPU and memory resources.
    #[config_patch(nested)]
    pub resources: SandboxResources,

    /// Guest runtime options.
    #[config_patch(nested)]
    pub runtime: SandboxRuntimeOptions,

    /// Environment variables visible to commands in the sandbox.
    #[config_patch(merge_with = merge_env_vars)]
    pub env: Vec<EnvVar>,

    /// User-defined labels attached to the sandbox.
    #[config_patch(merge)]
    pub labels: BTreeMap<String, String>,

    /// Sandbox-wide resource limits inherited by guest processes.
    pub rlimits: Vec<Rlimit>,

    /// Volume mounts.
    pub mounts: Vec<VolumeMount>,

    /// Rootfs patches applied before VM start.
    pub patches: Vec<Patch>,

    /// Network specification.
    #[config_patch(nested)]
    pub network: NetworkSpec,

    /// Local host services exposed through virtio-vsock.
    #[serde(default, skip_serializing_if = "VsockSpec::is_empty")]
    #[config_patch(nested)]
    pub vsock: VsockSpec,

    /// Hand off PID 1 to a guest init binary after agentd setup.
    pub init: Option<HandoffInit>,

    /// Pull policy for OCI images.
    pub pull_policy: PullPolicy,

    /// In-guest security profile.
    pub security_profile: SecurityProfile,

    /// Host-runtime deployment profile.
    ///
    /// Local callers may request a profile, while a managed backend can
    /// override it before launch. The cloud create wire intentionally omits
    /// this field so tenant requests cannot select the platform profile.
    pub deployment_profile: DeploymentProfile,

    /// Sandbox lifecycle policy.
    #[config_patch(nested)]
    pub lifecycle: SandboxPolicy,
}

/// CPU and memory resources for a sandbox.
#[derive(Debug, Clone, Serialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxResources {
    /// Number of virtual CPUs currently presented to the guest at boot.
    pub cpus: u8,

    /// Guest memory currently presented to the guest at boot, in MiB.
    pub memory_mib: u32,

    /// Maximum virtual CPUs the sandbox may expose after boot-time hotplug support lands.
    pub max_cpus: u8,

    /// Maximum guest memory the sandbox may expose after boot-time hotplug support lands, in MiB.
    pub max_memory_mib: u32,

    /// Host CPU placement requested for this sandbox.
    #[serde(default, skip_serializing_if = "CpuPlacement::is_inherit")]
    pub cpu_placement: CpuPlacement,

    /// Host-defined placement profile selected for this sandbox.
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` inherits defaults; use a sparse patch to clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[config_patch(nullable)]
    pub placement_profile: Option<String>,

    /// Guest transparent huge-page policy selected at boot.
    #[serde(default, skip_serializing_if = "TransparentHugePagePolicy::is_madvise")]
    pub thp: TransparentHugePagePolicy,
}

/// Controls how Microsandbox places vCPU threads on host processors.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum CpuPlacement {
    /// Preserve the invoking process's existing scheduler and affinity behavior.
    #[default]
    Inherit,

    /// Spread across cores, then use SMT siblings, then share logical processors under pressure.
    Auto,

    /// Preserve the widest practical distribution, sharing logical processors when necessary.
    Spread,

    /// Prefer SMT siblings and fewer physical cores, then share balanced logical processors.
    Compact,
}

/// Concrete host NUMA scope selected by a named placement profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum NumaPlacement {
    /// Prefer one host NUMA node, falling back to inherited host placement when it cannot fit.
    PreferSingle,
    /// Require maximum CPU and memory capacity to fit one host NUMA node.
    StrictSingle,
    /// Preserve the operating system's ordinary NUMA behavior.
    Inherit,
}

/// Host backing policy for guest memory selected by a named placement profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryPlacement {
    /// Back guest RAM from the selected CPU node when enforceable, otherwise inherit host policy.
    FollowCpu,
    /// Preserve the operating system's ordinary memory policy.
    Inherit,
}

/// Host-owned named placement profile resolved before a local VM starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct PlacementProfile {
    /// NUMA scope used while selecting host CPU capacity.
    pub numa: NumaPlacement,
    /// Host-memory behavior used for the resolved CPU nodes.
    pub memory: MemoryPlacement,
}

/// Guest transparent huge-page policy applied through the kernel command line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum TransparentHugePagePolicy {
    /// Transparently use huge pages for eligible anonymous mappings.
    Always,

    /// Use huge pages only for mappings that explicitly request them.
    #[default]
    Madvise,

    /// Disable transparent huge pages for anonymous mappings.
    Never,
}

/// Host control over the guest wall clock (`CLOCK_REALTIME`).
///
/// Serializes as the lowercase variant name (`"sync"`, `"off"`) to match the CLI spelling.
/// The guest monotonic clock is never adjusted by either policy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum GuestClockPolicy {
    /// Keep the guest wall clock in step with the host.
    ///
    /// The runtime sends the host time at boot and about once a minute, and steps the
    /// guest clock to host time when a full snapshot is restored or a paused sandbox resumes.
    #[default]
    Sync,

    /// Never set the guest wall clock after boot.
    ///
    /// The guest keeps the time it read at boot and advances it on its own. A restored full
    /// snapshot continues from the captured guest time instead of jumping to host time.
    Off,
}

/// Guest runtime options for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxRuntimeOptions {
    /// Working directory inside the guest.
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` inherits defaults; use a sparse patch to clear.
    #[config_patch(nullable)]
    pub workdir: Option<String>,

    /// Default shell for scripts and interactive sessions.
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` explicitly clears lower-layer defaults; managed overrides still apply.
    #[config_patch(nullable)]
    pub shell: Option<String>,

    /// Named scripts available inside the guest.
    #[config_patch(merge)]
    pub scripts: BTreeMap<String, String>,

    /// Image entrypoint override.
    pub entrypoint: Option<Vec<String>>,

    /// Image command override.
    pub cmd: Option<Vec<String>>,

    /// Guest hostname override.
    pub hostname: Option<String>,

    /// Guest user identity override.
    pub user: Option<String>,

    /// Runtime log verbosity.
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` explicitly clears lower-layer defaults; managed overrides still apply.
    #[config_patch(nullable)]
    pub log_level: Option<SandboxLogLevel>,

    /// Metrics sampling interval in milliseconds. `None` disables sampling.
    /// In Rust SDK creation from a concrete `SandboxConfig`, `None` explicitly clears lower-layer defaults; managed overrides still apply.
    #[config_patch(nullable)]
    pub metrics_sample_interval_ms: Option<u64>,

    /// Force-disable metrics sampling regardless of `metrics_sample_interval_ms`.
    pub disable_metrics_sample: bool,

    /// Host control over the guest wall clock. `None` selects [`GuestClockPolicy::Sync`];
    /// a full snapshot restore without an explicit value keeps the policy recorded in the snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_clock: Option<GuestClockPolicy>,
}

/// Environment variable entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EnvVar {
    /// Environment variable name.
    pub key: String,

    /// Environment variable value.
    pub value: String,
}

/// Runtime log verbosity for sandbox specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum SandboxLogLevel {
    /// Emit only error logs.
    Error,

    /// Emit warning and error logs.
    Warn,

    /// Emit info, warning, and error logs.
    Info,

    /// Emit debug and higher-severity logs.
    Debug,

    /// Emit trace and higher-severity logs.
    Trace,
}

//--------------------------------------------------------------------------------------------------
// Types: Exec
//--------------------------------------------------------------------------------------------------

/// POSIX resource limit identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum RlimitResource {
    /// Max CPU time in seconds (`RLIMIT_CPU`).
    Cpu,
    /// Max file size in bytes (`RLIMIT_FSIZE`).
    Fsize,
    /// Max data segment size (`RLIMIT_DATA`).
    Data,
    /// Max stack size (`RLIMIT_STACK`).
    Stack,
    /// Max core file size (`RLIMIT_CORE`).
    Core,
    /// Max resident set size (`RLIMIT_RSS`).
    Rss,
    /// Max number of processes (`RLIMIT_NPROC`).
    Nproc,
    /// Max open file descriptors (`RLIMIT_NOFILE`).
    Nofile,
    /// Max locked memory (`RLIMIT_MEMLOCK`).
    Memlock,
    /// Max address space size (`RLIMIT_AS`).
    As,
    /// Max file locks (`RLIMIT_LOCKS`).
    Locks,
    /// Max pending signals (`RLIMIT_SIGPENDING`).
    Sigpending,
    /// Max bytes in POSIX message queues (`RLIMIT_MSGQUEUE`).
    Msgqueue,
    /// Max nice priority (`RLIMIT_NICE`).
    Nice,
    /// Max real-time priority (`RLIMIT_RTPRIO`).
    Rtprio,
    /// Max real-time timeout (`RLIMIT_RTTIME`).
    Rttime,
}

/// A POSIX resource limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Rlimit {
    /// Resource type.
    pub resource: RlimitResource,

    /// Soft limit (can be raised up to hard limit by the process).
    pub soft: u64,

    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

//--------------------------------------------------------------------------------------------------
// Types: Logs
//--------------------------------------------------------------------------------------------------

/// Source tag on a captured log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    /// Captured from a session's stdout (pipe mode).
    Stdout,

    /// Captured from a session's stderr (pipe mode).
    Stderr,

    /// Captured from a session in pty mode (stdout + stderr merged at the kernel level inside the guest arrive as a single stream tagged `output`).
    Output,

    /// Synthetic system entry: lifecycle markers, runtime diagnostics, kernel console output.
    System,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxResourcesPatch {
    /// Whether this patch explicitly sets the initial vCPU count, even to its default value.
    pub fn has_cpus(&self) -> bool {
        self.cpus.is_some()
    }

    /// Whether this patch explicitly sets initial memory, even to its default value.
    pub fn has_memory_mib(&self) -> bool {
        self.memory_mib.is_some()
    }

    /// Whether this patch explicitly sets the maximum vCPU count.
    pub fn has_max_cpus(&self) -> bool {
        self.max_cpus.is_some()
    }

    /// Whether this patch explicitly sets maximum memory.
    pub fn has_max_memory_mib(&self) -> bool {
        self.max_memory_mib.is_some()
    }
}

impl DiskImageFormat {
    /// Returns the format as a CLI-safe lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
            Self::Vmdk => "vmdk",
        }
    }

    /// Parse a disk image format from a file extension.
    ///
    /// Returns `None` if the extension is not a recognized disk image format.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "qcow2" => Some(Self::Qcow2),
            "raw" => Some(Self::Raw),
            "vmdk" => Some(Self::Vmdk),
            _ => None,
        }
    }
}

impl OciRootfsSource {
    /// Create a new OCI rootfs source.
    pub fn new(reference: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            root_disk: None,
        }
    }
}

impl TransparentHugePagePolicy {
    /// Whether this is the density-conscious default policy.
    pub fn is_madvise(&self) -> bool {
        matches!(self, Self::Madvise)
    }

    /// Return the lowercase kernel command-line representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Madvise => "madvise",
            Self::Never => "never",
        }
    }
}

impl GuestClockPolicy {
    /// Whether the runtime keeps the guest wall clock in step with the host.
    pub fn is_sync(&self) -> bool {
        matches!(self, Self::Sync)
    }

    /// Return the lowercase configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Off => "off",
        }
    }
}

impl RootDisk {
    /// Create a managed root disk with the given size in MiB.
    pub fn managed(size_mib: u32) -> Self {
        Self::Managed {
            size_mib: Some(size_mib),
        }
    }

    /// Create a tmpfs root disk with the given size in MiB.
    pub fn tmpfs(size_mib: u32) -> Self {
        Self::Tmpfs {
            size_mib: Some(size_mib),
        }
    }

    /// Create a flat root disk with the given final capacity in MiB.
    pub fn flat(size_mib: u32) -> Self {
        Self::Flat {
            size_mib: Some(size_mib),
            fstype: None,
            clone: FlatClone::Auto,
        }
    }

    /// Return the configured size in MiB, if this kind carries one.
    pub fn size_mib(&self) -> Option<u32> {
        match self {
            Self::Managed { size_mib } | Self::Tmpfs { size_mib } | Self::Flat { size_mib, .. } => {
                *size_mib
            }
            Self::DiskImage { .. } => None,
        }
    }

    /// Return the lowercase kind tag used on the wire, in the DB, and in CLI output.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Managed { .. } => "managed",
            Self::Tmpfs { .. } => "tmpfs",
            Self::DiskImage { .. } => "disk-image",
            Self::Flat { .. } => "flat",
        }
    }

    /// Whether this is the managed (default) kind.
    pub fn is_managed(&self) -> bool {
        matches!(self, Self::Managed { .. })
    }
}

impl FlatClone {
    /// Return the stable lowercase value used by CLI, SDK and persisted metadata surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Copy => "copy",
            Self::Reflink => "reflink",
        }
    }

    /// Whether this is the default auto strategy.
    pub const fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl RootfsSource {
    /// Create an OCI rootfs source from an image reference.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci(OciRootfsSource::new(reference))
    }

    /// Return the OCI image reference if this is an OCI rootfs.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Oci(oci) => Some(&oci.reference),
            _ => None,
        }
    }

    /// Return the configured root disk if this is an OCI rootfs.
    pub fn oci_root_disk(&self) -> Option<&RootDisk> {
        match self {
            Self::Oci(oci) => oci.root_disk.as_ref(),
            _ => None,
        }
    }

    /// Return the managed root disk size in MiB if this is an OCI rootfs with a managed
    /// (or unset, i.e. default-managed) root disk. Non-managed kinds return `None`.
    pub fn oci_managed_root_disk_size_mib(&self) -> Option<u32> {
        match self {
            Self::Oci(oci) => match &oci.root_disk {
                Some(RootDisk::Managed { size_mib }) => *size_mib,
                Some(_) => None,
                None => None,
            },
            _ => None,
        }
    }
}

impl EnvVar {
    /// Create an environment variable entry.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Return this entry as key and value string slices.
    pub fn as_pair(&self) -> (&str, &str) {
        (&self.key, &self.value)
    }
}

impl VolumeKind {
    /// Return the lowercase database and CLI representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "dir",
            Self::Disk => "disk",
        }
    }

    /// Parse a persisted database value, defaulting to directory for unknown values.
    pub fn from_db_value(value: &str) -> Self {
        match value {
            "disk" => Self::Disk,
            _ => Self::Directory,
        }
    }
}

impl VolumeSpec {
    /// Create a directory-backed volume spec with default options.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: VolumeKind::Directory,
            quota_mib: None,
            capacity_mib: None,
            labels: Vec::new(),
        }
    }
}

impl NamedVolumeCreate {
    /// Creation behavior for this named volume mount.
    pub fn mode(&self) -> NamedVolumeMode {
        self.mode
    }

    /// Volume name to create or ensure exists.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Storage kind to create or ensure exists.
    pub fn kind(&self) -> VolumeKind {
        self.kind
    }

    /// Directory quota in MiB, if configured.
    pub fn quota_mib(&self) -> Option<u32> {
        self.quota_mib
    }

    /// Disk capacity in MiB, if configured.
    pub fn capacity_mib(&self) -> Option<u32> {
        self.capacity_mib
    }

    /// Labels to attach to newly-created volumes.
    pub fn labels(&self) -> &[(String, String)] {
        &self.labels
    }
}

impl VolumeMount {
    /// The absolute path where this mount appears inside the guest.
    pub fn guest(&self) -> &str {
        match self {
            Self::Bind { guest, .. }
            | Self::Owned { guest, .. }
            | Self::Named { guest, .. }
            | Self::Tmpfs { guest, .. }
            | Self::DiskImage { guest, .. } => guest,
        }
    }

    fn guest_mut(&mut self) -> &mut String {
        match self {
            Self::Bind { guest, .. }
            | Self::Owned { guest, .. }
            | Self::Named { guest, .. }
            | Self::Tmpfs { guest, .. }
            | Self::DiskImage { guest, .. } => guest,
        }
    }

    /// Return named-volume creation metadata when this mount provisions a named volume.
    pub fn named_create(&self) -> Option<&NamedVolumeCreate> {
        match self {
            Self::Named { create, .. } => create.as_ref(),
            _ => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Volume Mounts
//--------------------------------------------------------------------------------------------------

/// Portable private-volume identity derived from an already canonical guest path.
/// The ASCII hint is diagnostic; the suffix keeps distinct paths distinct.
pub fn owned_volume_mount_id(guest: &str) -> String {
    use std::fmt::Write as _;
    let slug: String = guest
        .trim_start_matches('/')
        .chars()
        .take(11)
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    let mut id = if slug.is_empty() {
        String::new()
    } else {
        format!("{slug}_")
    };
    for byte in Sha256::digest(guest.as_bytes()).iter().take(4) {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// Canonicalizes guest paths and orders mounts from parent to child.
///
/// All SDKs and runtimes share this ordering contract so an enclosing mount
/// can never hide a nested mount merely because the caller used an unordered
/// collection. Paths at the same depth are ordered lexicographically to keep
/// serialized configurations deterministic.
pub fn canonicalize_volume_mounts(mounts: &mut [VolumeMount]) -> TypesResult<()> {
    for mount in mounts.iter_mut() {
        let canonical = canonical_guest_mount_path(mount.guest())?;
        *mount.guest_mut() = canonical;
    }

    mounts.sort_by_cached_key(|mount| guest_mount_order_key(mount.guest()));

    for pair in mounts.windows(2) {
        if pair[0].guest() == pair[1].guest() {
            return Err(TypesError::invalid_config(format!(
                "multiple volumes cannot mount the same guest path: {}",
                pair[0].guest()
            )));
        }
    }

    Ok(())
}

fn canonical_guest_mount_path(guest: &str) -> TypesResult<String> {
    let path = Utf8UnixPath::new(guest);

    if !path.is_valid() {
        return Err(TypesError::invalid_config(format!(
            "guest mount path must be a valid Unix path: {guest}"
        )));
    }
    if !path.is_absolute() {
        return Err(TypesError::invalid_config(format!(
            "guest mount path must be absolute: {guest}"
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, Utf8UnixComponent::ParentDir))
    {
        return Err(TypesError::invalid_config(format!(
            "guest mount path must not contain '..': {guest}"
        )));
    }
    if guest.contains(':') || guest.contains(';') || guest.contains(',') {
        return Err(TypesError::invalid_config(format!(
            "guest mount path must not contain ':', ';', or ',': {guest}"
        )));
    }

    let canonical = path.normalize().to_string();
    if canonical == "/" {
        return Err(TypesError::invalid_config(
            "cannot mount a volume at guest root /",
        ));
    }

    Ok(canonical)
}

fn guest_mount_order_key(guest: &str) -> (usize, String) {
    let path = Utf8UnixPath::new(guest);
    let depth = path.components().filter(Utf8Component::is_normal).count();
    (depth, guest.to_owned())
}

impl RlimitResource {
    /// Returns the lowercase string representation used on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Fsize => "fsize",
            Self::Data => "data",
            Self::Stack => "stack",
            Self::Core => "core",
            Self::Rss => "rss",
            Self::Nproc => "nproc",
            Self::Nofile => "nofile",
            Self::Memlock => "memlock",
            Self::As => "as",
            Self::Locks => "locks",
            Self::Sigpending => "sigpending",
            Self::Msgqueue => "msgqueue",
            Self::Nice => "nice",
            Self::Rtprio => "rtprio",
            Self::Rttime => "rttime",
        }
    }
}

impl LogSource {
    /// Apply the empty-means-default rule used by log readers.
    pub fn effective(requested: &[Self]) -> Vec<Self> {
        if requested.is_empty() {
            vec![Self::Stdout, Self::Stderr, Self::Output]
        } else {
            let mut sources = requested.to_vec();
            sources.sort_by_key(|src| match src {
                Self::Stdout => 0,
                Self::Stderr => 1,
                Self::Output => 2,
                Self::System => 3,
            });
            sources.dedup();
            sources
        }
    }
}

impl SandboxLogLevel {
    /// Return the lowercase string representation for this level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for DiskImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DiskImageFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "qcow2" => Ok(Self::Qcow2),
            "raw" => Ok(Self::Raw),
            "vmdk" => Ok(Self::Vmdk),
            _ => Err(format!("unknown disk image format: {s}")),
        }
    }
}

impl fmt::Display for TransparentHugePagePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransparentHugePagePolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "always" => Ok(Self::Always),
            "madvise" => Ok(Self::Madvise),
            "never" => Ok(Self::Never),
            _ => Err(format!(
                "unknown transparent huge-page policy: {value}; expected always, madvise, or never"
            )),
        }
    }
}

impl fmt::Display for GuestClockPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GuestClockPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sync" => Ok(Self::Sync),
            "off" => Ok(Self::Off),
            _ => Err(format!(
                "unknown guest clock policy: {value}; expected sync or off"
            )),
        }
    }
}

impl Default for RootfsSource {
    fn default() -> Self {
        Self::oci(String::new())
    }
}

impl Default for SandboxResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_SANDBOX_CPUS,
            memory_mib: DEFAULT_SANDBOX_MEMORY_MIB,
            max_cpus: DEFAULT_SANDBOX_CPUS,
            max_memory_mib: DEFAULT_SANDBOX_MEMORY_MIB,
            cpu_placement: CpuPlacement::Inherit,
            placement_profile: None,
            thp: TransparentHugePagePolicy::Madvise,
        }
    }
}

impl<'de> Deserialize<'de> for SandboxResources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawResources {
            #[serde(default = "default_sandbox_cpus")]
            cpus: u8,
            #[serde(default = "default_sandbox_memory_mib")]
            memory_mib: u32,
            max_cpus: Option<u8>,
            max_memory_mib: Option<u32>,
            #[serde(default)]
            cpu_placement: CpuPlacement,
            #[serde(default)]
            placement_profile: Option<String>,
            #[serde(default)]
            thp: TransparentHugePagePolicy,
        }

        let raw = RawResources::deserialize(deserializer)?;
        Ok(Self {
            cpus: raw.cpus,
            memory_mib: raw.memory_mib,
            // Legacy configs predate boot-capacity fields. Treat their effective
            // resources as their maximum capacity so old sandboxes do not
            // deserialize into an impossible cpus > max_cpus state.
            max_cpus: raw.max_cpus.unwrap_or(raw.cpus),
            max_memory_mib: raw.max_memory_mib.unwrap_or(raw.memory_mib),
            cpu_placement: raw.cpu_placement,
            placement_profile: raw.placement_profile,
            thp: raw.thp,
        })
    }
}

impl CpuPlacement {
    /// Returns whether this policy preserves the inherited host placement.
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

impl std::fmt::Display for CpuPlacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inherit => "inherit",
            Self::Auto => "auto",
            Self::Spread => "spread",
            Self::Compact => "compact",
        })
    }
}

impl FromStr for CpuPlacement {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "auto" => Ok(Self::Auto),
            "spread" => Ok(Self::Spread),
            "compact" => Ok(Self::Compact),
            _ => Err(format!(
                "unknown CPU placement: {value} (expected: inherit, auto, spread, compact)"
            )),
        }
    }
}

impl Default for SandboxRuntimeOptions {
    fn default() -> Self {
        Self {
            workdir: None,
            shell: None,
            scripts: BTreeMap::new(),
            entrypoint: None,
            cmd: None,
            hostname: None,
            user: None,
            log_level: None,
            metrics_sample_interval_ms: Some(DEFAULT_METRICS_SAMPLE_INTERVAL_MS),
            disable_metrics_sample: false,
            guest_clock: None,
        }
    }
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: None,
            ports: Vec::new(),
            policy: None,
            dns: None,
            tls: None,
            strict: true,
            secrets: None,
            max_tcp_connections: None,
            max_udp_connections: None,
            tcp_accept_queue_size: None,
            rate_limiter: None,
            nat64_prefixes: default_nat64_prefixes(),
            trust_host_cas: false,
            outbound_proxy: None,
            http: HttpConfig::default(),
        }
    }
}

pub(crate) fn default_nat64_prefixes() -> Vec<Ipv6Network> {
    vec![
        WELL_KNOWN_NAT64_PREFIX
            .parse()
            .expect("well-known NAT64 prefix must be valid"),
    ]
}

impl Default for PublishedPortSpec {
    fn default() -> Self {
        Self {
            host_port: 0,
            guest_port: 0,
            protocol: PortProtocol::Tcp,
            host_bind: "127.0.0.1".into(),
        }
    }
}

impl From<(String, String)> for EnvVar {
    fn from((key, value): (String, String)) -> Self {
        Self { key, value }
    }
}

impl From<EnvVar> for (String, String) {
    fn from(var: EnvVar) -> Self {
        (var.key, var.value)
    }
}

impl FromStr for SandboxLogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(format!("unknown sandbox log level: {s}")),
        }
    }
}

impl std::fmt::Display for SandboxLogLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for VolumeMount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::Owned {
                guest,
                storage,
                options,
                stat_virtualization,
                host_permissions,
            } => {
                // A distinct tag is intentional: older runtimes must reject ownership,
                // not reinterpret a private mount as an external or named volume.
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "Owned")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("storage", storage)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.end()
            }
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => {
                let mut map = serializer.serialize_map(Some(8))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.serialize_entry("follow_root_symlinks", follow_root_symlinks)?;
                map.serialize_entry("quota_mib", quota_mib)?;
                map.end()
            }
            Self::Named {
                name,
                guest,
                create: _,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => {
                let mut map = serializer.serialize_map(Some(7))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.serialize_entry("follow_root_symlinks", follow_root_symlinks)?;
                map.end()
            }
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Tmpfs")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("size_mib", size_mib)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "DiskImage")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("format", format)?;
                map.serialize_entry("fstype", fstype)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fn default_strict() -> StatVirtualization {
            StatVirtualization::Strict
        }

        fn default_private() -> HostPermissions {
            HostPermissions::Private
        }

        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum VolumeMountHelper {
            Owned {
                guest: String,
                storage: OwnedVolumeStorage,
                #[serde(default)]
                options: MountOptions,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
            },
            Bind {
                host: PathBuf,
                guest: String,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
                #[serde(default)]
                follow_root_symlinks: bool,
                #[serde(default)]
                quota_mib: Option<u32>,
            },
            Named {
                name: String,
                guest: String,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
                #[serde(default)]
                follow_root_symlinks: bool,
            },
            Tmpfs {
                guest: String,
                #[serde(default)]
                size_mib: Option<u32>,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
            },
            DiskImage {
                host: PathBuf,
                guest: String,
                format: DiskImageFormat,
                #[serde(default)]
                fstype: Option<String>,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
            },
        }

        let helper = VolumeMountHelper::deserialize(deserializer)?;
        Ok(match helper {
            VolumeMountHelper::Owned {
                guest,
                storage,
                options,
                stat_virtualization,
                host_permissions,
            } => Self::Owned {
                guest,
                storage,
                options,
                stat_virtualization,
                host_permissions,
            },
            VolumeMountHelper::Bind {
                host,
                guest,
                options,
                readonly,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => Self::Bind {
                host,
                guest,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                options,
                readonly,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => Self::Named {
                name,
                guest,
                create: None,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            },
            VolumeMountHelper::Tmpfs {
                guest,
                size_mib,
                options,
                readonly,
            } => Self::Tmpfs {
                guest,
                size_mib,
                options: decode_mount_options(options, readonly),
            },
            VolumeMountHelper::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
                readonly,
            } => Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options: decode_mount_options(options, readonly),
            },
        })
    }
}

impl fmt::Debug for VolumeMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owned {
                guest,
                storage,
                options,
                stat_virtualization,
                host_permissions,
            } => f
                .debug_struct("Owned")
                .field("guest", guest)
                .field("storage", storage)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .finish(),
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .field("follow_root_symlinks", follow_root_symlinks)
                .field("quota_mib", quota_mib)
                .finish(),
            Self::Named {
                name,
                guest,
                create,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("create", create)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .field("follow_root_symlinks", follow_root_symlinks)
                .finish(),
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => f
                .debug_struct("Tmpfs")
                .field("guest", guest)
                .field("size_mib", size_mib)
                .field("options", options)
                .finish(),
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => f
                .debug_struct("DiskImage")
                .field("host", host)
                .field("guest", guest)
                .field("format", format)
                .field("fstype", fstype)
                .field("options", options)
                .finish(),
        }
    }
}

/// Case-insensitive string to [`RlimitResource`] conversion.
impl TryFrom<&str> for RlimitResource {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "cpu" => Ok(Self::Cpu),
            "fsize" => Ok(Self::Fsize),
            "data" => Ok(Self::Data),
            "stack" => Ok(Self::Stack),
            "core" => Ok(Self::Core),
            "rss" => Ok(Self::Rss),
            "nproc" => Ok(Self::Nproc),
            "nofile" => Ok(Self::Nofile),
            "memlock" => Ok(Self::Memlock),
            "as" => Ok(Self::As),
            "locks" => Ok(Self::Locks),
            "sigpending" => Ok(Self::Sigpending),
            "msgqueue" => Ok(Self::Msgqueue),
            "nice" => Ok(Self::Nice),
            "rtprio" => Ok(Self::Rtprio),
            "rttime" => Ok(Self::Rttime),
            _ => Err(format!("unknown rlimit resource: {s}")),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_sandbox_cpus() -> u8 {
    DEFAULT_SANDBOX_CPUS
}

fn default_sandbox_memory_mib() -> u32 {
    DEFAULT_SANDBOX_MEMORY_MIB
}

fn decode_mount_options(options: Option<MountOptions>, readonly: bool) -> MountOptions {
    options.unwrap_or(MountOptions {
        readonly,
        ..MountOptions::default()
    })
}

fn merge_env_vars(base: &mut Vec<EnvVar>, higher: Vec<EnvVar>) {
    for value in higher {
        match base.iter_mut().find(|current| current.key == value.key) {
            Some(current) => *current = value,
            None => base.push(value),
        }
    }
}

fn merge_secret_entries(base: &mut Vec<SecretEntry>, higher: Vec<SecretEntry>) {
    for value in higher {
        match base
            .iter_mut()
            .find(|current| current.env_var == value.env_var)
        {
            Some(current) => *current = value,
            None => base.push(value),
        }
    }
}

/// Default stat-virtualization policy (`Strict`) for a deserialized volume mount.
pub(crate) fn default_strict() -> StatVirtualization {
    StatVirtualization::Strict
}

/// Default host-permission policy (`Private`) for a deserialized volume mount.
pub(crate) fn default_private() -> HostPermissions {
    HostPermissions::Private
}

/// Maximum supported secret placeholder length in bytes.
pub const MAX_SECRET_PLACEHOLDER_BYTES: usize = 1024;

/// Maximum supported OAuth sentinel length in bytes.
///
/// Sentinels may be JWT-shaped: the real token's header and payload copied
/// verbatim with only the signature replaced, so that a client which decodes
/// the token to read its claims keeps working. Such a sentinel is as long as
/// the token whose claims it mirrors, which is far longer than the opaque
/// sentinels this bound was first written for.
pub const MAX_OAUTH_SENTINEL_BYTES: usize = 8 * 1024;

/// Placeholder-based secret substitution for a sandbox's TLS-intercepted egress.
///
/// The sandbox only ever sees each secret's `placeholder`; the local network
/// engine substitutes the real `value` into outbound requests bound for an
/// allowed host (and blocks/forwards per [`SecretViolationAction`] otherwise). Carried
/// in [`NetworkSpec::secrets`](NetworkSpec).
///
/// When constructing directly, use `..Default::default()` for unspecified fields.
/// The global `passthrough_hosts` field preserves historical defaults; its addition
/// requires updating older exhaustive struct literals and patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretsConfig {
    /// Default hosts allowed to receive placeholders unchanged.
    /// A per-secret violation action overrides this default.
    #[doc(hidden)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(skip))]
    #[cfg_attr(feature = "utoipa", schema(ignore))]
    pub passthrough_hosts: Option<Vec<HostPattern>>,

    /// List of secrets to inject.
    #[serde(default)]
    #[config_patch(merge_with = merge_secret_entries)]
    pub secrets: Vec<SecretEntry>,

    /// OAuth grants whose token material is held by a host broker.
    #[serde(default)]
    pub oauth: Vec<OAuthSecret>,

    /// Default action when a placeholder leaks to a disallowed host.
    #[serde(default)]
    pub violation_action: SecretViolationAction,
}

/// Provider-neutral OAuth token handling configuration.
///
/// This durable value contains only routing metadata and an opaque grant ID.
/// Access and refresh tokens are loaded from the broker at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct OAuthSecret {
    /// Host broker Unix-domain socket path.
    pub broker_endpoint: String,
    /// Opaque grant identifier understood by the broker.
    pub grant_id: String,
    /// Exact HTTPS token endpoint, including path and optional query.
    pub token_endpoint: String,
    /// Require `X-Distributed-OAuth-Grant` with an exact known access or refresh
    /// sentinel for exchanges carrying no sentinel. The header is removed before
    /// forwarding. False allows unmarked exchanges only when exactly one matching
    /// grant allows them. Refresh sentinels remain authoritative without a header.
    #[serde(default)]
    pub require_grant_marker: bool,
    /// Exact HTTPS device-code endpoint (RFC 8628), when the grant is obtained
    /// by a device flow.
    ///
    /// Requests to it carry no grant material and are forwarded unmodified;
    /// the endpoint only has to be known so the grant is loaded for the
    /// connection that carries the rest of the device flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code_endpoint: Option<String>,
    /// Exact HTTPS device-code polling endpoint (RFC 8628).
    ///
    /// A `POST` here is a token request: a response carrying
    /// [`access_token_field`](Self::access_token_field) is committed to the
    /// broker and sanitized like a token-endpoint response, while the
    /// `authorization_pending`, `slow_down`, `expired_token` and
    /// `access_denied` errors are forwarded untouched. May be the same URL as
    /// [`token_endpoint`](Self::token_endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_endpoint: Option<String>,
    /// Extra secret JSON fields in a poll response, such as the proprietary
    /// `authorization_code` and `code_verifier` some providers return before
    /// the real token exchange.
    ///
    /// Each is replaced with a sentinel before the guest sees it, and
    /// substituted back on a later token request. The real values are held in
    /// memory for the life of the connection that received them, so the
    /// exchange has to happen on that connection.
    ///
    /// Only top-level string fields of the response object are inspected: a
    /// secret nested inside another object, or under a field name that is not
    /// listed here, stays on the verbatim path and reaches the sandbox.
    #[serde(default)]
    pub poll_secret_fields: Vec<String>,
    /// Endpoints that mint a new long-lived secret in their response.
    ///
    /// A token endpoint hands back the grant's own tokens; these hand back
    /// something else. Anthropic's console mode, for instance, `POST`s to
    /// `https://api.anthropic.com/api/oauth/claude_cli/create_api_key` with
    /// the access token and gets a fresh API key in `raw_key`. Nothing about
    /// that key is known to the broker beforehand, so without an entry here
    /// it reaches the sandbox in the clear.
    ///
    /// A `POST` to an exact host and path listed here whose 2xx JSON response
    /// carries [`field`](MintEndpoint::field) as a top-level string is minted:
    /// the broker stores the value and names a sentinel, the sandbox is handed
    /// the sentinel instead, and later requests to this grant's inject hosts
    /// have the sentinel substituted back.
    ///
    /// The host must be one of [`inject_hosts`](Self::inject_hosts) or the
    /// token endpoint's host: a mint endpoint is loaded for its own host and
    /// port, so one naming a host the grant says nothing else about is a
    /// grant reaching somewhere it never declared.
    ///
    /// It is the endpoint's own host *and port* that load the grant, so an
    /// endpoint served anywhere but 443 has to name its port in
    /// [`port`](MintEndpoint::port) or the connection carrying it is never
    /// recognised.
    #[serde(default)]
    pub mint_endpoints: Vec<MintEndpoint>,
    /// Hosts where the access sentinel may be substituted.
    #[serde(default)]
    pub inject_hosts: Vec<HostPattern>,
    /// JSON field carrying the access token in successful token responses.
    pub access_token_field: String,
    /// JSON field carrying the refresh token in successful token responses.
    ///
    /// May be the same field as
    /// [`access_token_field`](Self::access_token_field): a device flow without
    /// a refresh grant hands the same value back for both.
    pub refresh_token_field: String,
    /// Environment variable exposing the access sentinel to the guest.
    pub access_env_var: String,
    /// Environment variable exposing the refresh sentinel to the guest.
    pub refresh_env_var: String,
    /// Per-sandbox access-token sentinel, the value the guest starts with.
    ///
    /// It may be opaque, or JWT-shaped for a client that decodes the token to
    /// read its claims: the real token's header and payload copied verbatim
    /// with only the signature replaced. A JWT-shaped sentinel mirrors claims
    /// that change on every login and refresh, so the broker may hand back a
    /// replacement with the tokens it loads or commits, and that replacement
    /// supersedes this value for the connection that received it.
    ///
    /// Must be non-empty, at most 8192 bytes (`MAX_OAUTH_SENTINEL_BYTES`),
    /// and must not contain NUL, CR, or LF. No two sentinels, whether on this
    /// grant or another, may be equal or contain one another.
    pub access_sentinel: String,
    /// Per-sandbox refresh-token sentinel, under the same rules as the access
    /// sentinel above.
    pub refresh_sentinel: String,
}

/// One exact endpoint whose response mints a new secret.
///
/// Carried in [`OAuthSecret::mint_endpoints`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct MintEndpoint {
    /// Exact hostname the request is addressed to, matched case-insensitively
    /// against the TLS SNI. Bare host only: no scheme, port, path or userinfo.
    pub host: String,

    /// Exact request path, with no query string of its own.
    ///
    /// A request is matched on its path alone: whatever query the sandbox
    /// appends, the endpoint it reached is this one. Must start with `/`.
    pub path: String,

    /// TCP port the endpoint is reached on. `None` is 443.
    ///
    /// The other endpoints carry their port in their URL and match on it;
    /// this one is a host and a path, so it says its port here. A grant whose
    /// inject host is served on another port names that port, or its mint
    /// endpoint quietly never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Top-level JSON field of the response that carries the minted secret.
    pub field: String,
}

/// A single secret entry.
///
/// `value` is the sensitive material — it never enters the sandbox and is
/// redacted by the [`Debug`](fmt::Debug) impl.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    ///
    /// Must be non-empty and must not contain `=` or NUL. microsandbox does
    /// not require shell-identifier syntax because Linux environment entries
    /// only require a `NAME=value` shape.
    pub env_var: String,

    /// The actual secret value (never enters the sandbox).
    ///
    /// Empty when the entry carries a [`source`](Self::source) reference
    /// instead: reference-model entries resolve the value host-side at spawn
    /// time so the durable sandbox config never stores raw secret material.
    ///
    /// Wrapped in [`Zeroizing`] so the owned plaintext copy is wiped when the
    /// entry drops.
    #[serde(default = "empty_secret_value")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub value: Zeroizing<String>,

    /// Host-side source reference resolved into [`value`](Self::value) at
    /// spawn time. `None` means `value` already carries the material (the
    /// inline model used by value-based secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SecretSource>,

    /// Placeholder string the sandbox sees instead of the real value.
    ///
    /// Must be non-empty, no longer than [`MAX_SECRET_PLACEHOLDER_BYTES`], and
    /// must not contain NUL, CR, or LF.
    pub placeholder: String,

    /// Hosts allowed to receive the substituted secret value.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Request locations where the placeholder can be substituted.
    #[serde(default)]
    pub substitution: SecretSubstitution,

    /// Hosts allowed to receive the placeholder unchanged.
    #[serde(default)]
    pub passthrough_hosts: Vec<HostPattern>,

    /// Action on a violation for this secret (overrides the config default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<SecretViolationAction>,

    /// Require verified TLS identity before substituting (default: true).
    ///
    /// When true, the secret is only substituted if the connection uses TLS
    /// interception (not bypass) and the SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for a secret allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum HostPattern {
    /// Exact hostname match.
    #[serde(alias = "Exact")]
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    #[serde(alias = "Wildcard")]
    Wildcard(String),
    /// Any host (dangerous — secret can be exfiltrated).
    #[serde(alias = "Any")]
    Any,
}

/// Request locations where a placeholder can be substituted with its secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretSubstitution {
    /// Substitute in HTTP headers (default: true).
    #[serde(default = "default_true")]
    pub headers: bool,

    /// Substitute in URL query parameters (default: false).
    #[serde(default)]
    pub query: bool,

    /// Substitute in request body (default: false).
    ///
    /// Fixed-length HTTP/1 bodies up to 16 MiB update `Content-Length`;
    /// larger fixed-length bodies are blocked. Chunked HTTP/1 bodies are
    /// decoded and re-encoded with fresh chunk sizes. Encoded bodies pass
    /// through unchanged. HTTP/2 DATA-frame body substitution is not
    /// supported; matching body placeholders are blocked.
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret placeholder is not allowed to leave the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum SecretViolationAction {
    /// Block the request silently.
    #[serde(alias = "Block")]
    Block,
    /// Block and log (default).
    #[default]
    #[serde(alias = "BlockAndLog", alias = "block_and_log")]
    BlockAndLog,
    /// Block and terminate the sandbox.
    #[serde(alias = "BlockAndTerminate", alias = "block_and_terminate")]
    BlockAndTerminate,
}

/// Invalid secret configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretConfigError {
    /// The environment variable name is empty.
    #[error("secret #{secret_index}: env_var must not be empty")]
    EmptyEnvVar {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains `=`.
    #[error("secret #{secret_index}: env_var must not contain `=`")]
    EnvVarContainsEquals {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains NUL.
    #[error("secret #{secret_index}: env_var must not contain NUL")]
    EnvVarContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// No allowed hosts were configured for a secret.
    #[error("secret #{secret_index}: at least one allowed host is required")]
    MissingAllowedHosts {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// No request locations were enabled for substitution.
    #[error("secret #{secret_index}: at least one substitution location is required")]
    MissingSubstitutionLocation {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder is empty.
    #[error("secret #{secret_index}: placeholder must not be empty")]
    EmptyPlaceholder {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder exceeds the supported byte length.
    #[error(
        "secret #{secret_index}: placeholder must be at most {max_bytes} bytes, got {actual_bytes}"
    )]
    PlaceholderTooLong {
        /// Index of the invalid secret entry.
        secret_index: usize,
        /// Actual placeholder length in bytes.
        actual_bytes: usize,
        /// Maximum supported placeholder length in bytes.
        max_bytes: usize,
    },

    /// The placeholder contains NUL.
    #[error("secret #{secret_index}: placeholder must not contain NUL")]
    PlaceholderContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder contains a line break.
    #[error("secret #{secret_index}: placeholder must not contain CR or LF")]
    PlaceholderContainsLineBreak {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// An OAuth configuration value is invalid.
    #[error("oauth grant #{grant_index}: {reason}")]
    InvalidOAuth {
        /// Index of the invalid OAuth grant.
        grant_index: usize,
        /// Non-sensitive reason the configuration is invalid.
        reason: &'static str,
    },
}

impl SecretsConfig {
    /// Whether any configured secret requires verified TLS identity.
    pub fn has_tls_identity_secrets(&self) -> bool {
        self.secrets
            .iter()
            .any(|secret| secret.require_tls_identity)
    }

    /// Whether a secret is configured for the given environment variable.
    pub fn contains_env_var(&self, env_var: &str) -> bool {
        self.secrets.iter().any(|secret| secret.env_var == env_var)
    }

    /// Validate all configured secret entries.
    pub fn validate(&self) -> Result<(), SecretConfigError> {
        for (index, secret) in self.secrets.iter().enumerate() {
            secret.validate(index)?;
        }
        for (index, oauth) in self.oauth.iter().enumerate() {
            oauth.validate(index)?;
            // A sentinel shared by two grants would be substituted with
            // whichever grant the proxy reached first, so one grant's token
            // would leave under the other's name. Containment is no safer than
            // equality, so it is rejected on the same terms.
            let overlapping = self.oauth[..index].iter().any(|earlier| {
                [&earlier.access_sentinel, &earlier.refresh_sentinel]
                    .into_iter()
                    .any(|held| {
                        sentinels_overlap(held, &oauth.access_sentinel)
                            || sentinels_overlap(held, &oauth.refresh_sentinel)
                    })
            });
            if overlapping {
                return Err(SecretConfigError::InvalidOAuth {
                    grant_index: index,
                    reason: "sentinels must not overlap another grant's sentinels",
                });
            }
        }
        Ok(())
    }
}

impl OAuthSecret {
    /// Validate durable OAuth metadata without contacting the broker.
    pub fn validate(&self, grant_index: usize) -> Result<(), SecretConfigError> {
        let invalid = |reason| SecretConfigError::InvalidOAuth {
            grant_index,
            reason,
        };
        if self.broker_endpoint.is_empty() {
            return Err(invalid("broker_endpoint must not be empty"));
        }
        if self.grant_id.is_empty() {
            return Err(invalid("grant_id must not be empty"));
        }
        validate_oauth_endpoint(
            &self.token_endpoint,
            "token_endpoint must be HTTPS",
            "token_endpoint must include a host and path",
            grant_index,
        )?;
        if let Some(endpoint) = &self.device_code_endpoint {
            validate_oauth_endpoint(
                endpoint,
                "device_code_endpoint must be HTTPS",
                "device_code_endpoint must include a host and path",
                grant_index,
            )?;
            // A device code request is forwarded as it stands; sharing a URL
            // with an endpoint whose responses hold token material would let
            // one past unsanitized.
            if *endpoint == self.token_endpoint || self.poll_endpoint.as_ref() == Some(endpoint) {
                return Err(invalid(
                    "device_code_endpoint must differ from the token and poll endpoints",
                ));
            }
        }
        if let Some(endpoint) = &self.poll_endpoint {
            validate_oauth_endpoint(
                endpoint,
                "poll_endpoint must be HTTPS",
                "poll_endpoint must include a host and path",
                grant_index,
            )?;
        }
        if self.inject_hosts.is_empty() {
            return Err(invalid("at least one inject host is required"));
        }
        if self.access_token_field.is_empty() || self.refresh_token_field.is_empty() {
            return Err(invalid("token response fields must not be empty"));
        }
        if !self.poll_secret_fields.is_empty() && self.poll_endpoint.is_none() {
            return Err(invalid("poll_secret_fields requires a poll_endpoint"));
        }
        for field in &self.poll_secret_fields {
            if field.is_empty() {
                return Err(invalid("poll secret fields must not be empty"));
            }
            if *field == self.access_token_field || *field == self.refresh_token_field {
                return Err(invalid("poll secret fields must not be token fields"));
            }
        }
        for mint in &self.mint_endpoints {
            validate_mint_endpoint(mint, self, grant_index)?;
        }
        validate_env_var(&self.access_env_var, grant_index)?;
        validate_env_var(&self.refresh_env_var, grant_index)?;
        validate_sentinel(&self.access_sentinel, grant_index)?;
        validate_sentinel(&self.refresh_sentinel, grant_index)?;
        if sentinels_overlap(&self.access_sentinel, &self.refresh_sentinel) {
            return Err(invalid("access and refresh sentinels must not overlap"));
        }
        Ok(())
    }
}

impl SecretEntry {
    /// Validate this secret entry.
    pub fn validate(&self, secret_index: usize) -> Result<(), SecretConfigError> {
        validate_env_var(&self.env_var, secret_index)?;

        if self.allowed_hosts.is_empty() {
            return Err(SecretConfigError::MissingAllowedHosts { secret_index });
        }

        if !self.substitution.headers && !self.substitution.query && !self.substitution.body {
            return Err(SecretConfigError::MissingSubstitutionLocation { secret_index });
        }

        validate_placeholder(&self.placeholder, secret_index)
    }
}

// The secret value must never reach a log line or an error message.
impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEntry")
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .field("placeholder", &self.placeholder)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("substitution", &self.substitution)
            .field("passthrough_hosts", &self.passthrough_hosts)
            .field("violation_action", &self.violation_action)
            .field("require_tls_identity", &self.require_tls_identity)
            .finish()
    }
}

impl HostPattern {
    /// Parse a user-facing host string: `*` is any host, `*.`-prefixed
    /// strings are wildcards, everything else matches exactly.
    pub fn parse(host: &str) -> Self {
        if host == "*" {
            HostPattern::Any
        } else if host.starts_with("*.") {
            HostPattern::Wildcard(host.to_string())
        } else {
            HostPattern::Exact(host.to_string())
        }
    }

    /// Check if a hostname matches this pattern.
    ///
    /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
    /// allocations (DNS hostnames are ASCII per RFC 4343).
    pub fn matches(&self, hostname: &str) -> bool {
        match self {
            HostPattern::Exact(h) => hostname.eq_ignore_ascii_case(h),
            HostPattern::Wildcard(pattern) => {
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    hostname.eq_ignore_ascii_case(suffix)
                        || (hostname.len() > suffix.len() + 1
                            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
                            && hostname[hostname.len() - suffix.len()..]
                                .eq_ignore_ascii_case(suffix))
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
                }
            }
            HostPattern::Any => true,
        }
    }
}

impl Default for SecretSubstitution {
    fn default() -> Self {
        Self {
            headers: true,
            query: false,
            body: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn validate_env_var(env_var: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    if env_var.is_empty() {
        return Err(SecretConfigError::EmptyEnvVar { secret_index });
    }
    if env_var.contains('=') {
        return Err(SecretConfigError::EnvVarContainsEquals { secret_index });
    }
    if env_var.contains('\0') {
        return Err(SecretConfigError::EnvVarContainsNul { secret_index });
    }
    Ok(())
}

fn validate_oauth_endpoint(
    endpoint: &str,
    not_https: &'static str,
    missing_path: &'static str,
    grant_index: usize,
) -> Result<(), SecretConfigError> {
    let invalid = |reason| SecretConfigError::InvalidOAuth {
        grant_index,
        reason,
    };
    let authority_and_path = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| invalid(not_https))?;
    if !authority_and_path.contains('/') || authority_and_path.starts_with('/') {
        return Err(invalid(missing_path));
    }
    Ok(())
}

/// Check one minting endpoint.
///
/// The host is a bare hostname rather than a URL: it is compared with the TLS
/// SNI, which carries no scheme, port or path. It has to be a host the grant
/// otherwise names — an inject host, or the token endpoint's own host. The
/// connection loads the grant for the mint endpoint's own host and port, so
/// this is not what makes the endpoint reachable; it keeps a grant's hosts to
/// the ones it declares, rather than letting one entry quietly extend the
/// grant to a host nothing else in it mentions.
fn validate_mint_endpoint(
    mint: &MintEndpoint,
    oauth: &OAuthSecret,
    grant_index: usize,
) -> Result<(), SecretConfigError> {
    let invalid = |reason| SecretConfigError::InvalidOAuth {
        grant_index,
        reason,
    };
    if mint.host.is_empty() {
        return Err(invalid("mint endpoint host must not be empty"));
    }
    if mint.host.contains("://")
        || mint
            .host
            .contains(['/', '@', ':', '?', '#', ' ', '\0', '\r', '\n'])
    {
        return Err(invalid("mint endpoint host must be a bare hostname"));
    }
    if !mint.path.starts_with('/') {
        return Err(invalid("mint endpoint path must start with `/`"));
    }
    // The request's query is dropped before the comparison, so a configured
    // one could never match anything.
    if mint.path.contains('?') {
        return Err(invalid(
            "mint endpoint path must not contain a query string",
        ));
    }
    if mint.path.contains([' ', '\0', '\r', '\n']) {
        return Err(invalid("mint endpoint path must not contain whitespace"));
    }
    if mint.field.is_empty() {
        return Err(invalid("mint endpoint field must not be empty"));
    }
    if mint.port == Some(0) {
        return Err(invalid("mint endpoint port must not be zero"));
    }
    let token_host = oauth_endpoint_host(&oauth.token_endpoint);
    let declared = token_host.is_some_and(|host| host.eq_ignore_ascii_case(&mint.host))
        || oauth
            .inject_hosts
            .iter()
            .any(|pattern| pattern.matches(&mint.host));
    if !declared {
        return Err(invalid(
            "mint endpoint host must be an inject host or the token endpoint host",
        ));
    }
    Ok(())
}

/// The bare hostname of an `https://host[:port]/path` endpoint.
fn oauth_endpoint_host(endpoint: &str) -> Option<&str> {
    let authority = endpoint.strip_prefix("https://")?.split('/').next()?;
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then_some(host)
}

fn validate_placeholder(placeholder: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    validate_placeholder_bytes(placeholder, secret_index, MAX_SECRET_PLACEHOLDER_BYTES)
}

/// Validate one OAuth sentinel, which may be JWT-shaped and so far longer than
/// a plain secret placeholder.
fn validate_sentinel(sentinel: &str, grant_index: usize) -> Result<(), SecretConfigError> {
    validate_placeholder_bytes(sentinel, grant_index, MAX_OAUTH_SENTINEL_BYTES)
}

/// Whether either of two sentinels occurs inside the other.
///
/// Substitution walks one sentinel at a time, so an overlapping pair is not
/// merely ambiguous: replacing the longer one first leaves nothing of the
/// shorter, and replacing the shorter one first leaves the rest of the longer
/// wrapped around a real token. The runtime rejects a broker-reported sentinel
/// on these terms, and configuration is held to the same rule.
fn sentinels_overlap(left: &str, right: &str) -> bool {
    !left.is_empty() && !right.is_empty() && (left.contains(right) || right.contains(left))
}

fn validate_placeholder_bytes(
    placeholder: &str,
    secret_index: usize,
    max_bytes: usize,
) -> Result<(), SecretConfigError> {
    if placeholder.is_empty() {
        return Err(SecretConfigError::EmptyPlaceholder { secret_index });
    }

    let actual_bytes = placeholder.len();
    if actual_bytes > max_bytes {
        return Err(SecretConfigError::PlaceholderTooLong {
            secret_index,
            actual_bytes,
            max_bytes,
        });
    }

    if placeholder.contains('\0') {
        return Err(SecretConfigError::PlaceholderContainsNul { secret_index });
    }
    if placeholder.contains('\r') || placeholder.contains('\n') {
        return Err(SecretConfigError::PlaceholderContainsLineBreak { secret_index });
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Types: TLS interception
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration. Carried in [`NetworkSpec::tls`](NetworkSpec).
///
/// The local network engine terminates TCP at its in-process stack, so TLS MITM
/// is handled by proxy tasks — these fields configure which ports/domains are
/// intercepted and how the interception CA is sourced.
#[derive(Debug, Clone, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TlsConfig {
    /// Whether TLS interception is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TCP ports subject to TLS interception (default: `[443]`).
    #[serde(default = "default_intercepted_ports")]
    pub intercepted_ports: Vec<u16>,

    /// Domains to bypass (no MITM). Supports exact match and `*.suffix` wildcards.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// Whether to verify the upstream server's TLS certificate.
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Drop UDP to intercepted ports when TLS interception is active, forcing
    /// QUIC traffic to fall back to TCP/TLS.
    #[serde(default = "default_true")]
    pub block_quic_on_intercept: bool,

    /// CA certificate PEM files to trust for upstream server verification.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
    #[cfg_attr(feature = "ts", ts(type = "Array<string>"))]
    pub upstream_ca_cert: Vec<PathBuf>,

    /// Host-scoped CA certificate PEM files to trust for upstream server verification.
    #[serde(default, alias = "scoped_upstream_ca_certs")]
    pub scoped_upstream_ca_cert: Vec<ScopedUpstreamCaCert>,

    /// Host-scoped upstream verification overrides.
    #[serde(default)]
    pub scoped_verify_upstream: Vec<ScopedVerifyUpstream>,

    /// Interception CA configuration. The TLS proxy uses this CA to sign
    /// per-domain certs it presents to the guest during interception.
    #[serde(default, alias = "ca")]
    pub intercept_ca: InterceptCaConfig,

    /// Per-domain certificate cache configuration.
    #[serde(default)]
    pub cache: CertCacheConfig,
}

/// Certificate authority configuration for TLS interception.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct InterceptCaConfig {
    /// Path to an existing CA certificate PEM file. If `None`, a CA is
    /// auto-generated and persisted.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub cert_path: Option<PathBuf>,

    /// Path to an existing CA private key PEM file. If `None`, a key is
    /// auto-generated and persisted.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub key_path: Option<PathBuf>,
}

/// Per-domain certificate cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CertCacheConfig {
    /// Maximum number of cached certificates. Default: 1000.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,

    /// Certificate validity duration in hours. Default: 24.
    #[serde(default = "default_cert_validity_hours")]
    pub validity_hours: u64,
}

/// A CA certificate PEM file trusted only for matching upstream hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ScopedUpstreamCaCert {
    /// Host pattern this CA applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Path to the CA certificate PEM file.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub path: PathBuf,
}

/// An upstream certificate verification override for matching hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ScopedVerifyUpstream {
    /// Host pattern this override applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Whether to verify matching upstream server certificates.
    pub verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intercepted_ports: default_intercepted_ports(),
            bypass: Vec::new(),
            verify_upstream: true,
            block_quic_on_intercept: true,
            upstream_ca_cert: Vec::new(),
            scoped_upstream_ca_cert: Vec::new(),
            scoped_verify_upstream: Vec::new(),
            intercept_ca: InterceptCaConfig::default(),
            cache: CertCacheConfig::default(),
        }
    }
}

impl Default for CertCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            validity_hours: default_cert_validity_hours(),
        }
    }
}

fn default_intercepted_ports() -> Vec<u16> {
    vec![443]
}

fn default_cache_capacity() -> usize {
    1000
}

fn default_cert_validity_hours() -> u64 {
    24
}

//--------------------------------------------------------------------------------------------------
// Types: Networking — policy
//--------------------------------------------------------------------------------------------------

/// Action to take on traffic matched by a [`Rule`] (or a policy default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the traffic.
    Allow,
    /// Silently drop the traffic.
    Deny,
}

/// Direction a [`Rule`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Outbound: guest → destination.
    Egress,
    /// Inbound: peer → guest.
    Ingress,
    /// Either direction.
    Any,
}

/// Protocol filter for a [`Rule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMPv4.
    Icmpv4,
    /// ICMPv6.
    Icmpv6,
}

/// Pre-defined destination category for a [`Destination::Group`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DestinationGroup {
    /// Public internet — any address not in another category.
    Public,
    /// Loopback addresses (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Private ranges (RFC 1918 / RFC 4193 ULA / CGN).
    Private,
    /// Link-local addresses, excluding the metadata IP.
    LinkLocal,
    /// Cloud metadata endpoint (`169.254.169.254`).
    Metadata,
    /// Multicast addresses (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// The sandbox host, reachable via the gateway IP.
    Host,
}

/// Traffic destination filter for a [`Rule`].
///
/// The `Cidr`, `Domain`, and `DomainSuffix` leaves carry their canonical
/// string form (e.g. `"10.0.0.0/8"`, `"example.com"`); the local network
/// engine re-parses and validates them into its richer internal types at
/// load time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// Match any destination.
    Any,
    /// IP address or CIDR block (e.g. `"1.2.3.4"`, `"10.0.0.0/8"`).
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    Cidr(#[cfg_attr(feature = "ts", ts(type = "string"))] IpNetwork),
    /// Exact domain name (e.g. `"example.com"`).
    Domain(String),
    /// Domain suffix — the apex and any subdomain of it.
    DomainSuffix(String),
    /// A pre-defined destination group.
    Group(DestinationGroup),
}

/// Inclusive guest-side port range for a [`Rule`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct PortRange {
    /// Start port (inclusive).
    pub start: u16,
    /// End port (inclusive).
    pub end: u16,
}

/// A single egress/ingress policy rule. Evaluated first-match-wins per
/// direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Rule {
    /// Direction this rule applies to.
    pub direction: Direction,
    /// Destination filter (direction-dependent interpretation).
    pub destination: Destination,
    /// Protocol set; empty matches any protocol.
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    /// Guest-side port-range set; empty matches any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// Action to take on a match.
    pub action: Action,
}

/// Egress/ingress network policy: an ordered [`Rule`] list plus a
/// per-direction default [`Action`]. Carried in [`NetworkSpec::policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NetworkPolicy {
    /// Default action for egress traffic matching no rule. Default: `Deny`.
    #[serde(default = "action_deny")]
    pub default_egress: Action,
    /// Default action for ingress traffic matching no rule. Default: `Deny`.
    #[serde(default = "action_deny")]
    pub default_ingress: Action,
    /// Ordered rules, evaluated first-match-wins per direction.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Default [`Action`] (`Deny`) for a policy's per-direction defaults, so a
/// partially-specified policy fails closed.
fn action_deny() -> Action {
    Action::Deny
}

//--------------------------------------------------------------------------------------------------
// Types: Networking — DNS & interface
//--------------------------------------------------------------------------------------------------

/// DNS interception and filtering settings. Carried in [`NetworkSpec::dns`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct DnsConfig {
    /// Whether DNS-rebinding protection is enabled. Default: true.
    pub rebind_protection: bool,
    /// Upstream nameservers as `IP`, `IP:PORT`, `HOST`, or `HOST:PORT`
    /// strings. Empty falls back to the host's `/etc/resolv.conf`.
    pub nameservers: Vec<String>,
    /// Per-query timeout in milliseconds. Default: 5000.
    pub query_timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            rebind_protection: true,
            nameservers: Vec::new(),
            query_timeout_ms: 5000,
        }
    }
}

/// Optional guest interface overrides. Unset fields are derived from the
/// sandbox slot by the local network engine. Carried in
/// [`NetworkSpec::interface`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct InterfaceOverrides {
    /// Guest MAC address as six octets. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<[u8; 6]>,
    /// Interface MTU. Default: 1500.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Guest IPv4 address (e.g. `172.16.0.2`). Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv4_address: Option<Ipv4Addr>,
    /// Guest IPv4 pool CIDR (e.g. `"172.16.0.0/12"`). Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv4_pool: Option<Ipv4Network>,
    /// Guest IPv6 address. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv6_address: Option<Ipv6Addr>,
    /// Guest IPv6 pool CIDR. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv6_pool: Option<Ipv6Network>,
}

fn empty_secret_value() -> Zeroizing<String> {
    Zeroizing::new(String::new())
}

//--------------------------------------------------------------------------------------------------
// Types: Networking — rate limits
//--------------------------------------------------------------------------------------------------

/// Sandbox-relative direction governed by a network rate limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRateLimitDirection {
    /// Traffic leaving the sandbox.
    Egress,
    /// Traffic entering the sandbox.
    Ingress,
}

/// Egress and ingress rate limits for a local sandbox network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ConfigPatch)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct NetworkRateLimiterConfig {
    /// Guest-to-runtime (egress) rate limiter. Missing means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<RateLimiterConfig>,

    /// Runtime-to-guest (ingress) rate limiter. Missing means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<RateLimiterConfig>,
}

/// Token-bucket rate limiter for one traffic direction. Carried in
/// [`NetworkRateLimiterConfig::egress`] and [`NetworkRateLimiterConfig::ingress`].
///
/// A limiter caps bandwidth (bytes) and packet rate (operations)
/// independently; a missing bucket leaves that dimension unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct RateLimiterConfig {
    /// Bandwidth bucket. One token is one byte of frame data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucketConfig>,

    /// Operations bucket. One token is one network frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucketConfig>,
}

/// One token bucket of a [`RateLimiterConfig`].
///
/// The bucket starts full and refills continuously at `size` tokens per
/// `refill_time_ms`. `one_time_burst` grants extra startup tokens that are
/// spent before the regular budget and never refill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TokenBucketConfig {
    /// Bucket capacity in tokens. Must be greater than zero.
    pub size: u64,

    /// Time to refill `size` tokens, in milliseconds. Must be greater than
    /// zero.
    pub refill_time_ms: u64,

    /// Extra tokens granted once at startup. Default: 0.
    #[serde(default)]
    pub one_time_burst: u64,
}

/// Invalid rate limiter configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RateLimitConfigError {
    /// The limiter has neither a bandwidth nor an ops bucket.
    #[error("rate limiter must configure at least one of bandwidth or ops")]
    EmptyLimiter,

    /// A bucket capacity is zero.
    #[error("{bucket} bucket: size must be greater than zero")]
    ZeroSize {
        /// Which bucket is invalid (`bandwidth` or `ops`).
        bucket: &'static str,
    },

    /// A bucket refill interval is zero.
    #[error("{bucket} bucket: refill_time_ms must be greater than zero")]
    ZeroRefillTime {
        /// Which bucket is invalid (`bandwidth` or `ops`).
        bucket: &'static str,
    },
}

impl RateLimiterConfig {
    /// Validate the limiter and each configured bucket.
    pub fn validate(&self) -> Result<(), RateLimitConfigError> {
        if self.bandwidth.is_none() && self.ops.is_none() {
            return Err(RateLimitConfigError::EmptyLimiter);
        }
        if let Some(bandwidth) = &self.bandwidth {
            bandwidth.validate("bandwidth")?;
        }
        if let Some(ops) = &self.ops {
            ops.validate("ops")?;
        }
        Ok(())
    }
}

impl TokenBucketConfig {
    /// Validate this bucket. `bucket` names it in error messages.
    pub fn validate(&self, bucket: &'static str) -> Result<(), RateLimitConfigError> {
        if self.size == 0 {
            return Err(RateLimitConfigError::ZeroSize { bucket });
        }
        if self.refill_time_ms == 0 {
            return Err(RateLimitConfigError::ZeroRefillTime { bucket });
        }
        Ok(())
    }
}

impl fmt::Display for NetworkRateLimitDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Egress => f.write_str("egress"),
            Self::Ingress => f.write_str("ingress"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_entry(env_var: &str, require_tls_identity: bool) -> SecretEntry {
        SecretEntry {
            env_var: env_var.to_owned(),
            value: Zeroizing::new("secret".to_owned()),
            source: None,
            placeholder: format!("$MSB_{env_var}"),
            allowed_hosts: vec![HostPattern::Any],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity,
        }
    }

    fn tmpfs_mount(guest: &str) -> VolumeMount {
        VolumeMount::Tmpfs {
            guest: guest.to_owned(),
            size_mib: None,
            options: MountOptions::default(),
        }
    }

    #[test]
    fn mount_options_omit_unset_owner_but_accept_missing_fields() {
        let value = serde_json::to_value(MountOptions::default()).unwrap();
        assert!(value.get("override_uid").is_none());
        assert!(value.get("override_gid").is_none());

        let decoded: MountOptions = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.override_uid, None);
        assert_eq!(decoded.override_gid, None);
    }

    #[test]
    fn volume_mounts_are_canonicalized_and_ordered_parent_first() {
        let mut mounts = vec![
            tmpfs_mount("/workspace//persist/./logs/"),
            tmpfs_mount("/alpha/z"),
            tmpfs_mount("/workspace"),
        ];

        canonicalize_volume_mounts(&mut mounts).unwrap();

        assert_eq!(
            mounts.iter().map(VolumeMount::guest).collect::<Vec<_>>(),
            vec!["/workspace", "/alpha/z", "/workspace/persist/logs"]
        );
    }

    #[test]
    fn secrets_config_queries_entries() {
        let mut config = SecretsConfig {
            secrets: vec![secret_entry("HTTP_TOKEN", false)],
            ..Default::default()
        };

        assert!(!config.has_tls_identity_secrets());
        assert!(config.contains_env_var("HTTP_TOKEN"));
        assert!(!config.contains_env_var("MISSING"));

        config.secrets.push(secret_entry("API_KEY", true));
        assert!(config.has_tls_identity_secrets());
    }

    #[test]
    fn volume_mounts_reject_duplicate_canonical_paths() {
        let mut mounts = vec![tmpfs_mount("/data/cache"), tmpfs_mount("/data//./cache/")];

        let error = canonicalize_volume_mounts(&mut mounts).unwrap_err();

        assert!(error.to_string().contains("same guest path: /data/cache"));
    }

    #[test]
    fn volume_mounts_reject_parent_components_before_normalizing() {
        let mut mounts = vec![tmpfs_mount("/workspace/../secrets")];

        let error = canonicalize_volume_mounts(&mut mounts).unwrap_err();

        assert!(error.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn disk_image_format_from_extension() {
        assert_eq!(
            DiskImageFormat::from_extension("qcow2"),
            Some(DiskImageFormat::Qcow2)
        );
        assert_eq!(
            DiskImageFormat::from_extension("raw"),
            Some(DiskImageFormat::Raw)
        );
        assert_eq!(
            DiskImageFormat::from_extension("vmdk"),
            Some(DiskImageFormat::Vmdk)
        );
        assert_eq!(DiskImageFormat::from_extension("ext4"), None);
        assert_eq!(DiskImageFormat::from_extension(""), None);
    }

    #[test]
    fn sandbox_resources_deserialize_legacy_capacity_from_effective_values() {
        let resources: SandboxResources =
            serde_json::from_str(r#"{"cpus":4,"memory_mib":2048}"#).unwrap();

        assert_eq!(resources.cpus, 4);
        assert_eq!(resources.max_cpus, 4);
        assert_eq!(resources.memory_mib, 2048);
        assert_eq!(resources.max_memory_mib, 2048);
        assert_eq!(resources.cpu_placement, CpuPlacement::Inherit);
        assert_eq!(resources.thp, TransparentHugePagePolicy::Madvise);
        assert_eq!(
            serde_json::to_value(resources).unwrap(),
            serde_json::json!({
                "cpus": 4,
                "memory_mib": 2048,
                "max_cpus": 4,
                "max_memory_mib": 2048
            })
        );
    }

    #[test]
    fn cpu_placement_omits_inherit_and_roundtrips_managed_policies() {
        let inherited = serde_json::to_value(SandboxResources::default()).unwrap();
        assert!(inherited.get("cpu_placement").is_none());

        for policy in [
            CpuPlacement::Auto,
            CpuPlacement::Spread,
            CpuPlacement::Compact,
        ] {
            let resources = SandboxResources {
                cpu_placement: policy,
                ..Default::default()
            };
            let json = serde_json::to_string(&resources).unwrap();
            let decoded: SandboxResources = serde_json::from_str(&json).unwrap();

            assert_eq!(decoded.cpu_placement, policy);
            assert_eq!(policy.to_string().parse::<CpuPlacement>().unwrap(), policy);
        }
    }

    #[test]
    fn guest_clock_policy_is_omitted_until_set_and_roundtrips() {
        let defaults = serde_json::to_value(SandboxRuntimeOptions::default()).unwrap();
        assert!(defaults.get("guest_clock").is_none());

        let legacy: SandboxRuntimeOptions = serde_json::from_str(r#"{"workdir":"/app"}"#).unwrap();
        assert_eq!(legacy.guest_clock, None);

        for policy in [GuestClockPolicy::Sync, GuestClockPolicy::Off] {
            let runtime = SandboxRuntimeOptions {
                guest_clock: Some(policy),
                ..Default::default()
            };
            let json = serde_json::to_value(&runtime).unwrap();
            assert_eq!(json["guest_clock"], serde_json::json!(policy.as_str()));
            let decoded: SandboxRuntimeOptions = serde_json::from_value(json).unwrap();
            assert_eq!(decoded.guest_clock, Some(policy));
            assert_eq!(
                policy.to_string().parse::<GuestClockPolicy>().unwrap(),
                policy
            );
        }

        assert_eq!(GuestClockPolicy::default(), GuestClockPolicy::Sync);
        assert!("host_sync".parse::<GuestClockPolicy>().is_err());
    }

    #[test]
    fn transparent_huge_page_policy_roundtrips_non_default() {
        let resources: SandboxResources = serde_json::from_str(
            r#"{"cpus":2,"memory_mib":8192,"max_cpus":2,"max_memory_mib":8192,"thp":"always"}"#,
        )
        .unwrap();

        assert_eq!(resources.thp, TransparentHugePagePolicy::Always);
        assert_eq!(
            serde_json::to_value(resources).unwrap()["thp"],
            serde_json::json!("always")
        );
        assert_eq!(
            "never".parse::<TransparentHugePagePolicy>().unwrap(),
            TransparentHugePagePolicy::Never
        );
        assert!("auto".parse::<TransparentHugePagePolicy>().is_err());
    }

    #[test]
    fn disk_image_format_display_roundtrip() {
        for format in [
            DiskImageFormat::Qcow2,
            DiskImageFormat::Raw,
            DiskImageFormat::Vmdk,
        ] {
            let rendered = format.to_string();
            let parsed: DiskImageFormat = rendered.parse().unwrap();
            assert_eq!(parsed, format);
        }
    }

    #[test]
    fn disk_image_format_from_str_unknown() {
        assert!("ext4".parse::<DiskImageFormat>().is_err());
    }

    #[test]
    fn log_source_effective_uses_default_user_program_sources() {
        assert_eq!(
            LogSource::effective(&[]),
            vec![LogSource::Stdout, LogSource::Stderr, LogSource::Output]
        );
    }

    #[test]
    fn log_source_effective_sorts_and_deduplicates_requested_sources() {
        assert_eq!(
            LogSource::effective(&[LogSource::System, LogSource::Stdout, LogSource::System]),
            vec![LogSource::Stdout, LogSource::System]
        );
    }

    #[test]
    fn rlimit_resource_parses_case_insensitively() {
        assert_eq!(
            RlimitResource::try_from("NOFILE").unwrap(),
            RlimitResource::Nofile
        );
        assert!(RlimitResource::try_from("bogus").is_err());
    }

    #[test]
    fn sandbox_policy_serde_roundtrip() {
        let policy = SandboxPolicy {
            ephemeral: true,
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(120),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&json).unwrap();

        assert!(decoded.ephemeral);
        assert_eq!(decoded.max_duration_secs, Some(3600));
        assert_eq!(decoded.idle_timeout_secs, Some(120));
    }

    #[test]
    fn sandbox_policy_defaults_to_persistent() {
        assert!(!SandboxPolicy::default().ephemeral);
    }

    #[test]
    fn sandbox_policy_deserializes_missing_ephemeral_as_persistent() {
        // `ephemeral` has a persistent default so partial policy payloads
        // deserialize to the conservative behavior.
        let decoded: SandboxPolicy =
            serde_json::from_str(r#"{"max_duration_secs":60,"idle_timeout_secs":null}"#).unwrap();
        assert!(!decoded.ephemeral);
        assert_eq!(decoded.max_duration_secs, Some(60));
    }

    #[test]
    fn sandbox_spec_default_uses_static_resource_defaults() {
        let spec = SandboxSpec::default();

        assert_eq!(spec.resources.cpus, DEFAULT_SANDBOX_CPUS);
        assert_eq!(spec.resources.memory_mib, DEFAULT_SANDBOX_MEMORY_MIB);
        assert_eq!(
            spec.runtime.metrics_sample_interval_ms,
            Some(DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
        );
        assert_eq!(spec.deployment_profile, DeploymentProfile::SingleTenant);
    }

    #[test]
    fn deployment_profile_uses_stable_snake_case_wire_values() {
        assert_eq!(
            serde_json::to_string(&DeploymentProfile::MultiTenant).unwrap(),
            r#""multi_tenant""#
        );
        assert_eq!(
            serde_json::from_str::<DeploymentProfile>(r#""single_tenant""#).unwrap(),
            DeploymentProfile::SingleTenant
        );
    }

    fn device_flow_oauth() -> OAuthSecret {
        OAuthSecret {
            broker_endpoint: "/run/microsandbox/oauth.sock".into(),
            grant_id: "grant".into(),
            token_endpoint: "https://github.com/login/oauth/access_token".into(),
            require_grant_marker: false,
            device_code_endpoint: Some("https://github.com/login/device/code".into()),
            poll_endpoint: Some("https://github.com/login/oauth/access_token".into()),
            poll_secret_fields: vec![],
            mint_endpoints: vec![],
            inject_hosts: vec![HostPattern::Exact("api.github.com".into())],
            access_token_field: "access_token".into(),
            refresh_token_field: "access_token".into(),
            access_env_var: "ACCESS_TOKEN".into(),
            refresh_env_var: "REFRESH_TOKEN".into(),
            access_sentinel: "$ACCESS".into(),
            refresh_sentinel: "$REFRESH".into(),
        }
    }

    #[test]
    fn oauth_access_and_refresh_token_fields_may_be_the_same() {
        assert_eq!(device_flow_oauth().validate(0), Ok(()));
    }

    #[test]
    fn oauth_grant_marker_wire_policy() {
        let mut value = serde_json::to_value(device_flow_oauth()).unwrap();
        assert_eq!(value["require_grant_marker"], false);
        value
            .as_object_mut()
            .unwrap()
            .remove("require_grant_marker");
        let omitted: OAuthSecret = serde_json::from_value(value.clone()).unwrap();
        assert!(!omitted.require_grant_marker);
        value["require_grant_marker"] = true.into();
        let required: OAuthSecret = serde_json::from_value(value).unwrap();
        assert!(required.require_grant_marker);
        assert_eq!(
            serde_json::to_value(required).unwrap()["require_grant_marker"],
            true
        );
    }

    #[test]
    fn oauth_sentinels_may_not_be_shared_between_grants() {
        let first = device_flow_oauth();
        let mut second = device_flow_oauth();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut config = SecretsConfig {
            oauth: vec![first.clone(), second.clone()],
            ..Default::default()
        };
        assert_eq!(config.validate(), Ok(()));

        // The second grant's refresh sentinel is the first grant's access
        // sentinel.
        second.refresh_sentinel = first.access_sentinel.clone();
        config.oauth = vec![first, second];
        assert_eq!(
            config.validate(),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 1,
                reason: "sentinels must not overlap another grant's sentinels",
            })
        );
    }

    #[test]
    fn oauth_sentinels_may_not_overlap_another_grant() {
        let first = device_flow_oauth();
        let mut second = device_flow_oauth();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();

        // The second grant's access sentinel contains the first grant's.
        second.access_sentinel = format!("{}_2", first.access_sentinel);
        let mut config = SecretsConfig {
            oauth: vec![first.clone(), second.clone()],
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 1,
                reason: "sentinels must not overlap another grant's sentinels",
            })
        );

        // And the other way round: the first grant's refresh sentinel contains
        // the second grant's.
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = first.refresh_sentinel[..3].to_string();
        assert!(!second.refresh_sentinel.is_empty());
        config.oauth = vec![first, second];
        assert_eq!(
            config.validate(),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 1,
                reason: "sentinels must not overlap another grant's sentinels",
            })
        );
    }

    #[test]
    fn oauth_sentinels_may_not_overlap_within_a_grant() {
        let mut oauth = device_flow_oauth();
        oauth.access_sentinel = "$MSB_ACCESS".into();
        oauth.refresh_sentinel = "$MSB_ACCESS_2".into();
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "access and refresh sentinels must not overlap",
            })
        );

        // Contained-by is rejected on the same terms as contains.
        oauth.access_sentinel = "$MSB_ACCESS_2".into();
        oauth.refresh_sentinel = "$MSB_ACCESS".into();
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "access and refresh sentinels must not overlap",
            })
        );
    }

    #[test]
    fn oauth_sentinels_of_equal_length_still_pass() {
        // Distinct sentinels of the same length cannot contain one another, so
        // the overlap rule leaves the ordinary case alone.
        let mut first = device_flow_oauth();
        first.access_sentinel = "$MSB_ACCESS_A".into();
        first.refresh_sentinel = "$MSB_REFRSH_A".into();
        let mut second = device_flow_oauth();
        second.access_sentinel = "$MSB_ACCESS_B".into();
        second.refresh_sentinel = "$MSB_REFRSH_B".into();
        assert_eq!(
            first.access_sentinel.len(),
            second.refresh_sentinel.len(),
            "the sentinels under test must be the same length"
        );
        let config = SecretsConfig {
            oauth: vec![first, second],
            ..Default::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn oauth_sentinels_may_be_jwt_sized() {
        // A JWT-shaped sentinel carries the real token's claims, so it is far
        // longer than a plain secret placeholder is allowed to be.
        let mut oauth = device_flow_oauth();
        oauth.access_sentinel = "e".repeat(MAX_SECRET_PLACEHOLDER_BYTES + 1);
        assert_eq!(oauth.validate(0), Ok(()));

        oauth.access_sentinel = "e".repeat(MAX_OAUTH_SENTINEL_BYTES);
        assert_eq!(oauth.validate(0), Ok(()));

        oauth.access_sentinel = "e".repeat(MAX_OAUTH_SENTINEL_BYTES + 1);
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::PlaceholderTooLong {
                secret_index: 0,
                actual_bytes: MAX_OAUTH_SENTINEL_BYTES + 1,
                max_bytes: MAX_OAUTH_SENTINEL_BYTES,
            })
        );
    }

    #[test]
    fn oauth_device_endpoints_must_be_https_with_a_path() {
        let mut oauth = device_flow_oauth();
        oauth.device_code_endpoint = Some("http://github.com/login/device/code".into());
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "device_code_endpoint must be HTTPS",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.poll_endpoint = Some("https://github.com".into());
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "poll_endpoint must include a host and path",
            })
        );
    }

    #[test]
    fn oauth_device_code_endpoint_may_not_be_a_token_bearing_endpoint() {
        let mut oauth = device_flow_oauth();
        oauth.device_code_endpoint = Some(oauth.token_endpoint.clone());
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "device_code_endpoint must differ from the token and poll endpoints",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.poll_endpoint = Some("https://github.com/login/device/code".into());
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "device_code_endpoint must differ from the token and poll endpoints",
            })
        );
    }

    #[test]
    fn oauth_mint_endpoints_take_a_bare_host_an_absolute_path_and_a_field() {
        let mint = |host: &str, path: &str, field: &str| MintEndpoint {
            host: host.into(),
            path: path.into(),
            field: field.into(),
            port: None,
        };

        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![mint("api.github.com", "/api/keys", "raw_key")];
        assert_eq!(oauth.validate(0), Ok(()));

        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![mint("https://api.github.com", "/api/keys", "raw_key")];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "mint endpoint host must be a bare hostname",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![mint("api.github.com", "api/keys", "raw_key")];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "mint endpoint path must start with `/`",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![mint("api.github.com", "/api/keys?scope=all", "raw_key")];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "mint endpoint path must not contain a query string",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![mint("api.github.com", "/api/keys", "")];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "mint endpoint field must not be empty",
            })
        );
    }

    #[test]
    fn a_mint_endpoint_host_the_grant_does_not_name_is_refused() {
        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![MintEndpoint {
            host: "keys.example.com".into(),
            path: "/api/keys".into(),
            field: "raw_key".into(),
            port: None,
        }];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "mint endpoint host must be an inject host or the token endpoint host",
            })
        );

        // The token endpoint's own host is one the grant already names, so a
        // mint endpoint may sit on it.
        let mut oauth = device_flow_oauth();
        oauth.mint_endpoints = vec![MintEndpoint {
            host: "github.com".into(),
            path: "/api/keys".into(),
            field: "raw_key".into(),
            port: None,
        }];
        assert_eq!(oauth.validate(0), Ok(()));
    }

    #[test]
    fn oauth_poll_secret_fields_need_a_poll_endpoint_and_may_not_be_token_fields() {
        let mut oauth = device_flow_oauth();
        oauth.poll_endpoint = None;
        oauth.poll_secret_fields = vec!["authorization_code".into()];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "poll_secret_fields requires a poll_endpoint",
            })
        );

        let mut oauth = device_flow_oauth();
        oauth.poll_secret_fields = vec!["access_token".into()];
        assert_eq!(
            oauth.validate(0),
            Err(SecretConfigError::InvalidOAuth {
                grant_index: 0,
                reason: "poll secret fields must not be token fields",
            })
        );
    }

    #[test]
    fn sandbox_log_level_roundtrips_lowercase_values() {
        for (input, expected) in [
            ("error", SandboxLogLevel::Error),
            ("warn", SandboxLogLevel::Warn),
            ("info", SandboxLogLevel::Info),
            ("debug", SandboxLogLevel::Debug),
            ("trace", SandboxLogLevel::Trace),
        ] {
            let parsed: SandboxLogLevel = input.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), input);
        }
    }
}
