//! Local OAuth lifecycle regression using an isolated static BusyBox rootfs.

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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Linux KVM, MSB_PATH, MSB_LIBKRUNFW_PATH, and a static MSB_TEST_OAUTH_BUSYBOX"]
async fn oauth_omission_respects_restart_profile_and_rejects_concrete_join() {
    let busybox =
        PathBuf::from(std::env::var_os("MSB_TEST_OAUTH_BUSYBOX").expect("static BusyBox"));
    let scratch =
        PathBuf::from(std::env::var_os("MSB_TEST_OAUTH_SCRATCH").expect("private scratch parent"));
    let fixture = tempfile::Builder::new()
        .prefix("oauth-")
        .tempdir_in(scratch)
        .unwrap();
    let home = fixture.path().join("msb");
    let backend = |profile| {
        Arc::new(
            LocalBackend::builder()
                .home(&home)
                .config_path(home.join("user.json"))
                .deployment_profile(profile)
                .build_lazy()
                .unwrap(),
        )
    };
    let single = backend(DeploymentProfile::SingleTenant);
    let single_scope: Arc<dyn Backend> = single.clone();
    let multi: Arc<dyn Backend> = backend(DeploymentProfile::MultiTenant);

    let mut config = fixture_config(fixture.path(), "protected", &busybox);
    protect(&mut config, fixture.path());
    let protected = with_backend(single_scope.clone(), SandboxBuilder::from(config).create())
        .await
        .unwrap();
    let before = catalog_state(&single, "protected").await;
    let handle = with_backend(multi, Sandbox::get("protected"))
        .await
        .unwrap();
    let result = handle.modify().max_memory(384u32).restart().apply().await;
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
    let before = catalog_state(&single, "protected").await;
    let handle = with_backend(single_scope.clone(), Sandbox::get("protected"))
        .await
        .unwrap();
    let missing =
        format!("HTTP CONNECT proxy: host environment variable {MISSING_PROXY_ENV} is not set");
    let restart_error = handle
        .restart()
        .await
        .err()
        .expect("missing launch source must refuse restart");
    assert!(
        restart_error.to_string().contains(&missing),
        "{restart_error}"
    );
    assert_eq!(catalog_state(&single, "protected").await, before);
    let modify_error = handle
        .modify()
        .max_memory(384u32)
        .restart()
        .apply()
        .await
        .unwrap_err();
    assert!(
        modify_error.to_string().contains(&missing),
        "{modify_error}"
    );
    assert_eq!(catalog_state(&single, "protected").await, before);
    let output = protected
        .exec("/bin/sh", ["-c", "printf '%s' \"$ACCESS\""])
        .await;
    protected.stop().await.unwrap();
    assert_eq!(output.unwrap().stdout().unwrap(), "synthetic-access");

    let ordinary = fixture_config(fixture.path(), "ordinary", &busybox);
    with_backend(single_scope, async {
        let running = SandboxBuilder::from(ordinary.clone())
            .create()
            .await
            .unwrap();
        let before = catalog_state(&single, "ordinary").await;
        let mut requested = ordinary.clone();
        protect(&mut requested, fixture.path());
        let mut invalid = requested.spec.network.secrets.as_ref().unwrap().oauth[0].clone();
        invalid.omit_token_response_fields = vec!["access_token".into()];
        let rejected_setter = SandboxBuilder::from(ordinary.clone())
            .oauth_secret(invalid.clone())
            .connect_or_create()
            .await;
        let rejected_network = SandboxBuilder::from(ordinary.clone())
            .network(|network| network.oauth_secret(invalid))
            .connect_or_create()
            .await;
        let protected_join = SandboxBuilder::from(requested).connect_or_create().await;
        let ordinary_join = SandboxBuilder::from(ordinary)
            .connect_or_create()
            .await
            .unwrap();
        let after = catalog_state(&single, "ordinary").await;
        assert_eq!(ordinary_join.id(), running.id());
        running.stop().await.unwrap();

        for rejected in [rejected_setter, rejected_network] {
            let error = rejected
                .err()
                .expect("invalid omission intent must not join");
            assert!(error.to_string().contains("omit"), "{error}");
        }
        let error = protected_join
            .err()
            .expect("protected concrete config must not join");
        assert!(
            matches!(
                &error,
                MicrosandboxError::InvalidConfig(message)
                    if message.contains("requires create, not connect_or_create")
            ),
            "{error}"
        );
        assert_eq!(after, before);
    })
    .await;
}
