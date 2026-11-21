//! Local OAuth lifecycle regressions using an isolated static BusyBox rootfs.
//! Set MSB_HOME inside MSB_TEST_OAUTH_SCRATCH and run these tests serially.

#![cfg(all(target_os = "linux", feature = "local", feature = "net"))]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox::sandbox::{DeploymentProfile, RootfsSource, SandboxBuilder};
use microsandbox::{
    Backend, LocalBackend, MicrosandboxError, Sandbox, SandboxConfig, with_backend,
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::json;

const MISSING_PROXY_ENV: &str = "MSB_TEST_OAUTH_MISSING_PROXY_PASSWORD";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn fixture_config(directory: &Path, name: &str, busybox: &Path) -> SandboxConfig {
    let rootfs = directory.join(name);
    for subdir in [
        "bin", "dev", "etc", "proc", "root", "run", "sys", "tmp", "var",
    ] {
        fs::create_dir_all(rootfs.join(subdir)).unwrap();
    }
    fs::copy(busybox, rootfs.join("bin/busybox")).unwrap();
    symlink("busybox", rootfs.join("bin/sh")).unwrap();
    fs::write(rootfs.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
    fs::write(rootfs.join("etc/group"), "root:x:0:\n").unwrap();

    let mut config = SandboxConfig::default();
    config.spec.name = name.into();
    config.spec.image = RootfsSource::Bind {
        path: rootfs,
        follow_root_symlinks: false,
    };
    config.spec.resources.memory_mib = 256;
    config.spec.resources.max_memory_mib = 256;
    config.spec.network.policy = Some(
        serde_json::from_value(
            json!({"default_egress":"deny","default_ingress":"deny","rules":[]}),
        )
        .unwrap(),
    );
    config
}

fn protect(config: &mut SandboxConfig, directory: &Path) {
    config.spec.network.tls = Some(serde_json::from_value(json!({"enabled":true})).unwrap());
    config.spec.network.secrets = Some(
        serde_json::from_value(json!({
            "oauth": [{
                "broker_endpoint": directory.join("unused.sock"),
                "grant_id": "synthetic",
                "token_endpoint": "https://provider.invalid/token",
                "inject_hosts": [{"exact":"provider.invalid"}],
                "access_token_field": "access_token",
                "refresh_token_field": "refresh_token",
                "access_env_var": "ACCESS",
                "refresh_env_var": "REFRESH",
                "access_sentinel": "synthetic-access",
                "refresh_sentinel": "synthetic-refresh",
                "omit_token_response_fields": ["id_token"]
            }]
        }))
        .unwrap(),
    );
}

async fn catalog_state(backend: &LocalBackend, name: &str) -> (String, String, String, i32, i32) {
    let row = backend
        .db()
        .await
        .unwrap()
        .read()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT sandbox.config, sandbox.active_config, sandbox.status, run.id, run.pid \
             FROM sandbox JOIN run ON run.sandbox_id = sandbox.id \
             WHERE sandbox.name = ? ORDER BY run.id DESC LIMIT 1",
            [name.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    (
        row.try_get("", "config").unwrap(),
        row.try_get("", "active_config").unwrap(),
        row.try_get("", "status").unwrap(),
        row.try_get("", "id").unwrap(),
        row.try_get("", "pid").unwrap(),
    )
}

fn fixture_inputs() -> (tempfile::TempDir, PathBuf) {
    let busybox =
        PathBuf::from(std::env::var_os("MSB_TEST_OAUTH_BUSYBOX").expect("static BusyBox"));
    let scratch =
        PathBuf::from(std::env::var_os("MSB_TEST_OAUTH_SCRATCH").expect("private scratch parent"));
    assert!(
        runtime_home().starts_with(&scratch),
        "MSB_HOME must be inside the test scratch"
    );
    let fixture = tempfile::Builder::new()
        .prefix("oauth-")
        .tempdir_in(scratch)
        .unwrap();
    (fixture, busybox)
}

fn runtime_home() -> PathBuf {
    PathBuf::from(std::env::var_os("MSB_HOME").expect("isolated runtime home"))
}

fn fixture_backend(directory: &Path, profile: DeploymentProfile) -> Arc<LocalBackend> {
    let home = directory.join("msb");
    Arc::new(
        LocalBackend::builder()
            .home(&home)
            .config_path(home.join("user.json"))
            .deployment_profile(profile)
            .build_lazy()
            .unwrap(),
    )
}

async fn assert_join_refused(builder: SandboxBuilder, message: &str) {
    let error = builder
        .connect_or_create()
        .await
        .err()
        .expect("invalid request must not join");
    assert!(error.to_string().contains(message), "{error}");
}

async fn assert_restart_refused(
    backend: &Arc<LocalBackend>,
    sandbox: &Sandbox,
    error_fragment: &str,
) {
    let name = sandbox.name();
    let before = catalog_state(backend, name).await;
    let scoped: Arc<dyn Backend> = backend.clone();
    let handle = with_backend(scoped, Sandbox::get(name)).await.unwrap();
    let error = Box::pin(handle.restart())
        .await
        .err()
        .expect("invalid launch input must refuse restart");
    assert!(error.to_string().contains(error_fragment), "{error}");
    assert_eq!(catalog_state(backend, name).await, before);
    let error = Box::pin(handle.modify().max_memory(384u32).restart().apply())
        .await
        .unwrap_err();
    assert!(error.to_string().contains(error_fragment), "{error}");
    assert_eq!(catalog_state(backend, name).await, before);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Linux KVM, MSB_PATH, MSB_LIBKRUNFW_PATH, and a static MSB_TEST_OAUTH_BUSYBOX"]
async fn oauth_omission_preflights_restart_profile_and_host_sources() {
    let (fixture, busybox) = fixture_inputs();
    let single = fixture_backend(fixture.path(), DeploymentProfile::SingleTenant);
    let single_scope: Arc<dyn Backend> = single.clone();
    let multi: Arc<dyn Backend> = fixture_backend(fixture.path(), DeploymentProfile::MultiTenant);

    let mut config = fixture_config(fixture.path(), "protected", &busybox);
    protect(&mut config, fixture.path());
    let protected = with_backend(single_scope.clone(), SandboxBuilder::from(config).create())
        .await
        .unwrap();
    let before = catalog_state(&single, "protected").await;
    let handle = with_backend(multi, Sandbox::get("protected"))
        .await
        .unwrap();
    let result = Box::pin(handle.modify().max_memory(384u32).restart().apply()).await;
    let after = catalog_state(&single, "protected").await;
    assert!(
        matches!(
            &result,
            Err(MicrosandboxError::InvalidConfig(message))
                if message.contains("token response field omission is not supported in the multi-tenant profile")
        ),
        "{result:?}"
    );
    assert_eq!(after, before);

    // Simulate a pending launch input in the desired row without changing the live VM.
    assert!(std::env::var_os(MISSING_PROXY_ENV).is_none());
    let proxy = json!({
        "protocol":"http_connect", "address":"127.0.0.1:9",
        "credentials":{"username":"fixture","password":{"kind":"env","var":MISSING_PROXY_ENV}}
    });
    single.db().await.unwrap().write().execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE sandbox SET config = json_set(config, '$.network.outbound_proxy', json(?)) WHERE name = 'protected'",
        [proxy.to_string().into()],
    )).await.unwrap();
    let missing =
        format!("HTTP CONNECT proxy: host environment variable {MISSING_PROXY_ENV} is not set");
    Box::pin(assert_restart_refused(&single, &protected, &missing)).await;
    let output = protected
        .exec("/bin/sh", ["-c", "printf '%s' \"$ACCESS\""])
        .await;
    protected.stop().await.unwrap();
    assert_eq!(output.unwrap().stdout().unwrap(), "synthetic-access");
}

#[tokio::test]
#[ignore = "requires Linux KVM, MSB_PATH, MSB_LIBKRUNFW_PATH, and a static MSB_TEST_OAUTH_BUSYBOX"]
async fn oauth_omission_preflights_explicit_interception_signer() {
    let (fixture, busybox) = fixture_inputs();
    let single = fixture_backend(fixture.path(), DeploymentProfile::SingleTenant);
    let scoped: Arc<dyn Backend> = single.clone();
    let mut config = fixture_config(fixture.path(), "protected", &busybox);
    protect(&mut config, fixture.path());
    let protected = with_backend(scoped, SandboxBuilder::from(config).create())
        .await
        .unwrap();

    let default = runtime_home().join("tls");
    let default_cert = fs::read(default.join("ca.crt")).unwrap();
    let default_key = fs::read(default.join("ca.key")).unwrap();
    let cert = fixture.path().join("explicit.crt");
    let key = fixture.path().join("explicit.key");
    fs::write(&cert, &default_cert).unwrap();
    let explicit = json!({"cert_path":cert,"key_path":key});
    single.db().await.unwrap().write().execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE sandbox SET config = json_set(config, '$.network.tls.intercept_ca', json(?)) WHERE name = 'protected'",
        [explicit.to_string().into()],
    )).await.unwrap();

    Box::pin(assert_restart_refused(
        &single,
        &protected,
        "failed to read intercept CA key",
    ))
    .await;
    assert!(!key.exists());
    fs::write(&key, b"not a PEM signing key").unwrap();
    Box::pin(assert_restart_refused(
        &single,
        &protected,
        "failed to parse CA key",
    ))
    .await;
    assert_eq!(fs::read(&key).unwrap(), b"not a PEM signing key");
    assert_eq!(fs::read(&cert).unwrap(), default_cert);
    assert_eq!(fs::read(default.join("ca.crt")).unwrap(), default_cert);
    assert_eq!(fs::read(default.join("ca.key")).unwrap(), default_key);

    let output = protected
        .exec("/bin/sh", ["-c", "printf '%s' \"$ACCESS\""])
        .await
        .unwrap();
    protected.stop().await.unwrap();
    assert_eq!(output.stdout().unwrap(), "synthetic-access");
}

#[tokio::test]
#[ignore = "requires Linux KVM, MSB_PATH, MSB_LIBKRUNFW_PATH, and a static MSB_TEST_OAUTH_BUSYBOX"]
async fn oauth_omission_refuses_invalid_and_concrete_join() {
    let (fixture, busybox) = fixture_inputs();
    let single = fixture_backend(fixture.path(), DeploymentProfile::SingleTenant);
    let single_scope: Arc<dyn Backend> = single.clone();
    let ordinary = fixture_config(fixture.path(), "ordinary", &busybox);
    with_backend(
        single_scope,
        Box::pin(async {
            let running = SandboxBuilder::from(ordinary.clone())
                .create()
                .await
                .unwrap();
            let before = catalog_state(&single, "ordinary").await;
            let mut requested = ordinary.clone();
            protect(&mut requested, fixture.path());
            let mut invalid = requested.spec.network.secrets.as_ref().unwrap().oauth[0].clone();
            invalid.omit_token_response_fields = vec!["access_token".into()];
            assert_join_refused(
                SandboxBuilder::from(ordinary.clone()).oauth_secret(invalid.clone()),
                "cannot omit mapped access or refresh token fields",
            )
            .await;
            assert_join_refused(
                SandboxBuilder::from(ordinary.clone())
                    .network(|network| network.oauth_secret(invalid)),
                "cannot omit mapped access or refresh token fields",
            )
            .await;
            assert_join_refused(
                SandboxBuilder::from(requested),
                "requires create, not connect_or_create",
            )
            .await;
            let mut invalid_base = ordinary.clone();
            invalid_base.spec.network.tcp_accept_queue_size = Some(0);
            let closure_called = std::cell::Cell::new(false);
            let unevaluated = SandboxBuilder::from(invalid_base.clone()).network(|net| {
                closure_called.set(true);
                net
            });
            assert!(!closure_called.get());
            assert_join_refused(unevaluated, "TCP accept queue size must be between").await;

            // Without an attempted network closure, unused create options still do not affect a join.
            let ignored_base = SandboxBuilder::from(invalid_base)
                .connect_or_create()
                .await
                .unwrap();
            assert_eq!(ignored_base.id(), running.id());
            let ordinary_join = SandboxBuilder::from(ordinary)
                .network(|net| {
                    closure_called.set(true);
                    net
                })
                .connect_or_create()
                .await
                .unwrap();
            let after = catalog_state(&single, "ordinary").await;
            assert!(closure_called.get());
            assert_eq!(ordinary_join.id(), running.id());
            running.stop().await.unwrap();

            assert_eq!(after, before);
        }),
    )
    .await;
}
