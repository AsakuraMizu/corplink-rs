use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, Display, EnumString};
use tokio::fs;

use crate::state::State;
use crate::utils;

const DEFAULT_DEVICE_NAME: &str = "DollarOS";
const DEFAULT_INTERFACE_NAME: &str = "corplink";

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum SelectStrategy {
    #[serde(rename = "latency")]
    Latency,
    #[serde(rename = "default")]
    Default,
}

#[derive(
    Serialize, Deserialize, Display, EnumString, AsRefStr, Copy, Clone, Debug, Eq, PartialEq,
)]
pub enum Platform {
    #[serde(rename = "ldap")]
    #[strum(serialize = "ldap")]
    Ldap,
    #[serde(rename = "feilian")]
    #[strum(serialize = "feilian")]
    Corplink,
    #[serde(rename = "feilian_v1")]
    #[strum(serialize = "feilian_v1")]
    CorplinkV1,
    #[serde(rename = "OIDC")]
    #[strum(serialize = "OIDC")]
    Oidc,
    #[serde(rename = "lark")]
    #[strum(serialize = "lark")]
    Lark,
    #[serde(rename = "weixin")]
    #[strum(serialize = "weixin")]
    Weixin,
    #[serde(rename = "dingtalk")]
    #[strum(serialize = "dingtalk")]
    DingTalk,
    #[serde(rename = "aad")]
    #[strum(serialize = "aad")]
    Aad,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum RouteMode {
    /// Only intranet routes returned by the server (mimics official split mode).
    #[default]
    #[serde(rename = "split")]
    Split,
    /// Full-tunnel routes from the server (typically 0.0.0.0/0, ::/0).
    #[serde(rename = "full")]
    Full,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    pub portal: PortalConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub device: DeviceConfig,
    #[serde(default)]
    pub wireguard: WireguardConfig,
    #[serde(default)]
    pub vpn: VpnConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub socks5: Socks5Config,
    #[serde(default)]
    pub session: SessionConfig,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string_pretty(self) {
            Ok(s) => write!(f, "{}", s),
            Err(e) => write!(f, "<invalid config: {e}>"),
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PortalConfig {
    pub company_name: String,
    pub server: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthConfig {
    pub username: String,
    pub password: Option<String>,
    pub platform: Option<Platform>,
    pub code: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(from = "DeviceConfigInput")]
pub struct DeviceConfig {
    pub name: String,
    pub id: String,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        let name = DEFAULT_DEVICE_NAME.to_owned();
        let id = device_id(&name);
        Self { name, id }
    }
}

impl From<DeviceConfigInput> for DeviceConfig {
    fn from(input: DeviceConfigInput) -> Self {
        let id = input.id.unwrap_or_else(|| device_id(&input.name));
        Self {
            name: input.name,
            id,
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct DeviceConfigInput {
    name: String,
    id: Option<String>,
}

impl Default for DeviceConfigInput {
    fn default() -> Self {
        Self {
            name: DEFAULT_DEVICE_NAME.to_owned(),
            id: None,
        }
    }
}

fn device_id(name: &str) -> String {
    format!("{:x}", md5::compute(name))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(try_from = "WireguardConfigInput")]
pub struct WireguardConfig {
    pub interface_name: String,
    pub public_key: String,
    pub private_key: String,
    pub debug: bool,
}

impl Default for WireguardConfig {
    fn default() -> Self {
        let (public_key, private_key) = utils::gen_wg_keypair();
        Self {
            interface_name: DEFAULT_INTERFACE_NAME.to_owned(),
            public_key,
            private_key,
            debug: false,
        }
    }
}

impl TryFrom<WireguardConfigInput> for WireguardConfig {
    type Error = anyhow::Error;

    fn try_from(input: WireguardConfigInput) -> std::result::Result<Self, Self::Error> {
        let (public_key, private_key) = match (input.public_key, input.private_key) {
            (Some(public_key), Some(private_key)) => (public_key, private_key),
            (None, Some(private_key)) => {
                let public_key = utils::gen_public_key_from_private(&private_key)?;
                (public_key, private_key)
            }
            _ => utils::gen_wg_keypair(),
        };

        Ok(Self {
            interface_name: input.interface_name,
            public_key,
            private_key,
            debug: input.debug,
        })
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct WireguardConfigInput {
    interface_name: String,
    public_key: Option<String>,
    private_key: Option<String>,
    debug: bool,
}

impl Default for WireguardConfigInput {
    fn default() -> Self {
        Self {
            interface_name: DEFAULT_INTERFACE_NAME.to_owned(),
            public_key: None,
            private_key: None,
            debug: false,
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct VpnConfig {
    pub server_name: Option<String>,
    pub select_strategy: Option<SelectStrategy>,
    pub auto_setup_routes: bool,
    pub route_mode: RouteMode,
    pub disallowed_routes: Option<Vec<String>>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            select_strategy: None,
            auto_setup_routes: true,
            route_mode: RouteMode::default(),
            disallowed_routes: None,
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub backup_filename: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Socks5Config {
    pub listen: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct SessionConfig {
    pub state: Option<State>,
}

#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    config: Config,
}

impl Deref for ConfigStore {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl ConfigStore {
    pub async fn load(file: impl Into<PathBuf>) -> Result<Self> {
        let path = file.into();
        let conf_str = fs::read_to_string(&path)
            .await
            .with_context(|| format!("failed to read config file {}", path.display()))?;

        let raw: Value = serde_json::from_str(&conf_str)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        let (config, needs_save) = Config::from_value(raw)?;

        let store = Self { path, config };
        if needs_save {
            store.save().await?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn update<R>(&mut self, update: impl FnOnce(&mut Config) -> R) -> Result<R> {
        let result = update(&mut self.config);
        self.save().await?;
        Ok(result)
    }

    async fn save(&self) -> Result<()> {
        let data = format!("{}", &self.config);
        fs::write(&self.path, data)
            .await
            .with_context(|| format!("failed to write config file {}", self.path.display()))?;
        Ok(())
    }
}

enum ConfigSchema {
    Current,
    Legacy,
}

const CURRENT_CONFIG_ROOT_KEYS: &[&str] = &["portal", "auth"];
const LEGACY_CONFIG_ROOT_KEYS: &[&str] = &[
    "company_name",
    "username",
    "password",
    "platform",
    "code",
    "device_name",
    "device_id",
    "public_key",
    "private_key",
    "server",
    "interface_name",
    "debug_wg",
    "state",
    "vpn_server_name",
    "vpn_select_strategy",
    "use_vpn_dns",
    "auto_setup_routes",
    "route_mode",
    "vpn_disallowed_routes",
    "socks5_listen",
    "socks5_username",
    "socks5_password",
];

fn config_schema(value: &Value) -> ConfigSchema {
    let Some(fields) = value.as_object() else {
        return ConfigSchema::Current;
    };

    if CURRENT_CONFIG_ROOT_KEYS
        .iter()
        .any(|key| fields.contains_key(*key))
    {
        return ConfigSchema::Current;
    }

    if LEGACY_CONFIG_ROOT_KEYS
        .iter()
        .any(|key| fields.contains_key(*key))
    {
        return ConfigSchema::Legacy;
    }

    ConfigSchema::Current
}

impl Config {
    fn from_value(value: Value) -> Result<(Self, bool)> {
        match config_schema(&value) {
            ConfigSchema::Current => {
                let config: Self = serde_json::from_value(value.clone())
                    .context("failed to parse current config schema")?;
                let normalized = serde_json::to_value(&config)
                    .context("failed to serialize normalized config")?;
                Ok((config, normalized != value))
            }
            ConfigSchema::Legacy => {
                let legacy: LegacyConfig = serde_json::from_value(value)
                    .context("failed to parse legacy config schema")?;
                let current_value = legacy.into_current_value();
                let config: Self = serde_json::from_value(current_value)
                    .context("failed to normalize legacy config")?;

                Ok((config, true))
            }
        }
    }
}

#[derive(Deserialize)]
struct LegacyConfig {
    company_name: String,
    username: String,
    password: Option<String>,
    platform: Option<Platform>,
    code: Option<String>,
    device_name: Option<String>,
    device_id: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    server: Option<String>,
    interface_name: Option<String>,
    debug_wg: Option<bool>,
    state: Option<State>,
    vpn_server_name: Option<String>,
    vpn_select_strategy: Option<SelectStrategy>,
    use_vpn_dns: Option<bool>,
    dns_backup_filename: Option<String>,
    auto_setup_routes: Option<bool>,
    route_mode: Option<RouteMode>,
    vpn_disallowed_routes: Option<Vec<String>>,
    socks5_listen: Option<String>,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
}

impl LegacyConfig {
    fn into_current_value(self) -> Value {
        let mut value = serde_json::json!({
            "portal": {
                "company_name": self.company_name,
                "server": self.server,
            },
            "auth": {
                "username": self.username,
                "password": self.password,
                "platform": self.platform.as_ref().map(AsRef::as_ref),
                "code": self.code,
            },
            "device": {
                "name": self.device_name,
                "id": self.device_id,
            },
            "wireguard": {
                "interface_name": self.interface_name,
                "public_key": self.public_key,
                "private_key": self.private_key,
                "debug": self.debug_wg,
            },
            "vpn": {
                "server_name": self.vpn_server_name,
                "select_strategy": self.vpn_select_strategy,
                "auto_setup_routes": self.auto_setup_routes,
                "route_mode": self.route_mode,
                "disallowed_routes": self.vpn_disallowed_routes,
            },
            "dns": {
                "enabled": self.use_vpn_dns,
                "backup_filename": self.dns_backup_filename,
            },
            "socks5": {
                "listen": self.socks5_listen,
                "username": self.socks5_username,
                "password": self.socks5_password,
            },
            "session": {
                "state": self.state,
            },
        });
        strip_null_fields(&mut value);
        value
    }
}

fn strip_null_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|_, value| {
                strip_null_fields(value);
                !value.is_null()
            });
        }
        Value::Array(values) => values.iter_mut().for_each(strip_null_fields),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "corplink-rs-{name}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn migrates_legacy_root_config_to_nested_schema() {
        let path = temp_config_path("legacy-migration");
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "company_name": "acme",
                "username": "alice",
                "password": "secret",
                "platform": "ldap",
                "code": "otp-secret",
                "device_name": "workstation",
                "device_id": "device-1",
                "public_key": "public-key",
                "private_key": "private-key",
                "server": "https://vpn.example.com",
                "interface_name": "wg-acme",
                "debug_wg": true,
                "state": "Login",
                "vpn_server_name": "HK-1",
                "vpn_select_strategy": "latency",
                "use_vpn_dns": true,
                "dns_backup_filename": "resolv.conf.backup",
                "auto_setup_routes": false,
                "route_mode": "full",
                "vpn_disallowed_routes": ["192.168.1.0/24"],
                "socks5_listen": "127.0.0.1:1080",
                "socks5_username": "proxy-user",
                "socks5_password": "proxy-pass"
            }))
            .expect("legacy config should serialize"),
        )
        .expect("legacy config should be written");

        let config_store = ConfigStore::load(&path)
            .await
            .expect("legacy config should migrate");
        let config = &*config_store;

        assert_eq!(config.portal.company_name, "acme");
        assert_eq!(config.auth.username, "alice");
        assert_eq!(config.auth.platform, Some(Platform::Ldap));
        assert_eq!(config.device.name, "workstation");
        assert_eq!(config.wireguard.interface_name, "wg-acme");
        assert_eq!(config.vpn.route_mode, RouteMode::Full);
        assert_eq!(config.vpn.select_strategy, Some(SelectStrategy::Latency));
        assert!(!config.vpn.auto_setup_routes);
        assert_eq!(
            config.dns.backup_filename.as_deref(),
            Some("resolv.conf.backup")
        );
        assert_eq!(config.socks5.listen.as_deref(), Some("127.0.0.1:1080"));
        assert_eq!(config.session.state, Some(State::Login));

        let migrated: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("migrated config should be readable"),
        )
        .expect("migrated config should be valid JSON");

        assert!(migrated.get("company_name").is_none());
        assert!(migrated.get("username").is_none());
        assert!(migrated.get("debug_wg").is_none());
        assert_eq!(migrated["portal"]["company_name"], "acme");
        assert_eq!(migrated["auth"]["username"], "alice");
        assert_eq!(migrated["auth"]["platform"], "ldap");
        assert_eq!(migrated["wireguard"]["interface_name"], "wg-acme");
        assert_eq!(migrated["vpn"]["route_mode"], "full");
        assert_eq!(migrated["vpn"]["select_strategy"], "latency");
        assert_eq!(migrated["dns"]["enabled"], true);
        assert_eq!(migrated["socks5"]["listen"], "127.0.0.1:1080");

        std::fs::remove_file(path).expect("temporary config should be removed");
    }

    #[test]
    fn minimal_legacy_config_uses_current_defaults_without_nulls() {
        let (config, needs_save) = Config::from_value(json!({
            "company_name": "acme",
            "username": "alice"
        }))
        .expect("minimal legacy config should normalize");

        assert!(needs_save);
        assert_eq!(config.portal.company_name, "acme");
        assert_eq!(config.auth.username, "alice");
        assert_eq!(config.device.name, DEFAULT_DEVICE_NAME);
        assert_eq!(config.device.id, device_id(DEFAULT_DEVICE_NAME));
        assert_eq!(config.wireguard.interface_name, DEFAULT_INTERFACE_NAME);
        assert!(!config.wireguard.public_key.is_empty());
        assert!(!config.wireguard.private_key.is_empty());
        assert!(config.vpn.auto_setup_routes);
        assert_eq!(config.vpn.route_mode, RouteMode::Split);
        assert!(!config.dns.enabled);
        assert!(config.dns.backup_filename.is_none());

        let legacy = LegacyConfig {
            company_name: "acme".to_owned(),
            username: "alice".to_owned(),
            password: None,
            platform: None,
            code: None,
            device_name: None,
            device_id: None,
            public_key: None,
            private_key: None,
            server: None,
            interface_name: None,
            debug_wg: None,
            state: None,
            vpn_server_name: None,
            vpn_select_strategy: None,
            use_vpn_dns: None,
            dns_backup_filename: None,
            auto_setup_routes: None,
            route_mode: None,
            vpn_disallowed_routes: None,
            socks5_listen: None,
            socks5_username: None,
            socks5_password: None,
        };
        let current_value = legacy.into_current_value();
        assert!(!contains_null(&current_value));
    }

    #[test]
    fn legacy_private_key_derives_public_key_through_current_parser() {
        let private_key = "uLJcKErgyRq2Px3/g6nrHL3vAcBNlfBIRLpjisAa+Vc=".to_owned();
        let (config, _) = Config::from_value(json!({
            "company_name": "acme",
            "username": "alice",
            "private_key": private_key
        }))
        .expect("legacy private key should normalize");

        assert_eq!(config.wireguard.private_key, private_key);
        assert_eq!(
            config.wireguard.public_key,
            utils::gen_public_key_from_private(&private_key)
                .expect("test private key should derive a public key")
        );
    }

    #[test]
    fn missing_platform_deserializes_as_default() {
        let (config, needs_save) = Config::from_value(json!({
            "portal": {
                "company_name": "nested-company"
            },
            "auth": {
                "username": "nested-user"
            }
        }))
        .expect("missing platform should mean default platform selection");

        assert_eq!(config.auth.platform, None);
        assert!(needs_save);
    }

    #[test]
    fn current_markers_win_over_legacy_root_fields() {
        let raw = json!({
            "portal": {
                "company_name": "nested-company"
            },
            "auth": {
                "username": "nested-user"
            },
            "company_name": "legacy-company",
            "username": "legacy-user"
        });

        let (config, needs_save) =
            Config::from_value(raw).expect("current marker should select current schema");
        assert_eq!(config.portal.company_name, "nested-company");
        assert_eq!(config.auth.username, "nested-user");
        assert!(needs_save);
    }

    #[test]
    fn malformed_current_with_legacy_fields_does_not_fallback() {
        let error = Config::from_value(json!({
            "portal": {
                "company_name": 42
            },
            "company_name": "legacy-company",
            "username": "legacy-user"
        }))
        .expect_err("current marker should force current schema parsing");

        let message = format!("{error:#}");
        assert!(message.contains("failed to parse current config schema"));
        assert!(!message.contains("failed to parse legacy config schema"));
    }

    #[test]
    fn auth_marker_with_legacy_fields_does_not_fallback() {
        let error = Config::from_value(json!({
            "auth": {
                "username": "nested-user"
            },
            "company_name": "legacy-company",
            "username": "legacy-user"
        }))
        .expect_err("auth marker should force current schema parsing");

        let message = format!("{error:#}");
        assert!(message.contains("failed to parse current config schema"));
        assert!(!message.contains("failed to parse legacy config schema"));
    }

    #[test]
    fn malformed_legacy_reports_legacy_schema_failure() {
        let error = Config::from_value(json!({
            "company_name": "legacy-company",
            "username": 42
        }))
        .expect_err("legacy-shaped config should be parsed as legacy schema");

        let message = format!("{error:#}");
        assert!(message.contains("failed to parse legacy config schema"));
        assert!(!message.contains("failed to parse current config schema"));
    }

    #[test]
    fn unrecognized_object_reports_current_schema_failure() {
        let error = Config::from_value(json!({
            "unknown": "field"
        }))
        .expect_err("unrecognized objects should default to current schema parsing");

        let message = format!("{error:#}");
        assert!(message.contains("failed to parse current config schema"));
        assert!(!message.contains("failed to parse legacy config schema"));
    }

    #[test]
    fn non_object_reports_current_schema_failure() {
        let error = Config::from_value(json!(null))
            .expect_err("non-object values should default to current schema parsing");

        let message = format!("{error:#}");
        assert!(message.contains("failed to parse current config schema"));
        assert!(!message.contains("failed to parse legacy config schema"));
    }

    fn contains_null(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => true,
            serde_json::Value::Array(values) => values.iter().any(contains_null),
            serde_json::Value::Object(fields) => fields.values().any(contains_null),
            _ => false,
        }
    }
}
