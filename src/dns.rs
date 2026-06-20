use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use setdns::{Config as SetDnsConfig, SetDns};

use crate::config::{DnsConfig, DnsMode};
use crate::wg::WgConf;

const DNS_OWNER: &str = "corplink-rs";

pub struct Handle {
    _inner: SetDns,
}

pub fn apply_vpn_dns(wg_conf: &WgConf, dns: &DnsConfig, device: &str) -> Option<Handle> {
    match build_setdns_config(wg_conf, dns, device) {
        Ok(Some(plan)) => {
            log::info!(
                "applying vpn dns: mode={}, servers={:?}, domains={:?}",
                plan.mode.as_str(),
                plan.config.servers,
                plan.config.domains
            );
            match SetDns::apply(plan.config) {
                Ok(handle) => Some(Handle { _inner: handle }),
                Err(err) => {
                    log::warn!("failed to set dns: {err}");
                    None
                }
            }
        }
        Ok(None) => {
            log::warn!(
                "dns.mode=split but no split dns domains were provided; skipping system dns"
            );
            None
        }
        Err(err) => {
            log::warn!("failed to prepare vpn dns config: {err:#}");
            None
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DnsApplyMode {
    Global,
    Split,
}

impl DnsApplyMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Split => "split",
        }
    }
}

struct DnsApplyPlan {
    mode: DnsApplyMode,
    config: SetDnsConfig,
}

fn build_setdns_config(
    wg_conf: &WgConf,
    dns: &DnsConfig,
    device: &str,
) -> Result<Option<DnsApplyPlan>> {
    let servers = wg_conf
        .dns_servers
        .iter()
        .filter(|server| !server.is_empty())
        .map(|server| {
            server
                .parse::<IpAddr>()
                .with_context(|| format!("failed to parse vpn dns {:?}", server))
        })
        .collect::<Result<Vec<_>>>()?;
    if servers.is_empty() {
        bail!("vpn dns server list is empty");
    }

    let domains = match dns.mode {
        DnsMode::Auto | DnsMode::Split => {
            let mut domains = wg_conf.dns_domains.clone();
            domains.extend(dns.domains.iter().cloned());
            domains
        }
        DnsMode::Global => Vec::new(),
    };

    if domains.is_empty() && dns.mode == DnsMode::Split {
        return Ok(None);
    }

    let mode = if domains.is_empty() {
        DnsApplyMode::Global
    } else {
        DnsApplyMode::Split
    };

    Ok(Some(DnsApplyPlan {
        mode,
        config: SetDnsConfig {
            owner: DNS_OWNER.to_owned(),
            servers,
            domains,
            device: Some(device.to_owned()),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg_conf(dns_servers: &[&str], dns_domains: &[&str]) -> WgConf {
        WgConf {
            address: "10.0.0.2/32".to_owned(),
            address6: String::new(),
            peer_address: "198.51.100.1:51820".to_owned(),
            mtu: 1420,
            public_key: "public".to_owned(),
            private_key: "private".to_owned(),
            peer_key: "peer".to_owned(),
            allowed_ips: Vec::new(),
            routes: Vec::new(),
            dns_servers: dns_servers
                .iter()
                .map(|server| (*server).to_owned())
                .collect(),
            dns_domains: dns_domains
                .iter()
                .map(|domain| (*domain).to_owned())
                .collect(),
            protocol: 0,
        }
    }

    fn dns_config(mode: DnsMode, domains: &[&str]) -> DnsConfig {
        DnsConfig {
            enabled: true,
            mode,
            domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
        }
    }

    fn plan(wg_conf: &WgConf, dns: &DnsConfig) -> DnsApplyPlan {
        build_setdns_config(wg_conf, dns, "utun4")
            .expect("dns config should build")
            .expect("dns config should be applied")
    }

    #[test]
    fn auto_without_domains_uses_global_dns() {
        let wg_conf = wg_conf(&["10.0.0.53"], &[]);
        let plan = plan(&wg_conf, &dns_config(DnsMode::Auto, &[]));

        assert_eq!(plan.mode, DnsApplyMode::Global);
        assert!(plan.config.domains.is_empty());
        assert_eq!(plan.config.device.as_deref(), Some("utun4"));
        assert_eq!(
            plan.config.servers,
            vec!["10.0.0.53".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn auto_merges_upstream_and_user_domains_for_split_dns() {
        let wg_conf = wg_conf(&["10.0.0.53"], &["corp.example"]);
        let plan = plan(
            &wg_conf,
            &dns_config(DnsMode::Auto, &["dev.example", "corp.example"]),
        );

        assert_eq!(plan.mode, DnsApplyMode::Split);
        assert_eq!(
            plan.config.domains,
            vec!["corp.example", "dev.example", "corp.example"]
        );
    }

    #[test]
    fn global_ignores_upstream_domains() {
        let wg_conf = wg_conf(&["10.0.0.53"], &["corp.example"]);
        let plan = plan(&wg_conf, &dns_config(DnsMode::Global, &[]));

        assert_eq!(plan.mode, DnsApplyMode::Global);
        assert!(plan.config.domains.is_empty());
    }

    #[test]
    fn split_without_domains_skips_dns_apply() {
        let wg_conf = wg_conf(&["10.0.0.53"], &[]);
        let config = dns_config(DnsMode::Split, &[]);

        assert!(build_setdns_config(&wg_conf, &config, "utun4")
            .expect("dns config should build")
            .is_none());
    }

    #[test]
    fn backup_dns_server_is_included_after_primary() {
        let wg_conf = wg_conf(&["10.0.0.53", "10.0.0.54"], &[]);
        let plan = plan(&wg_conf, &dns_config(DnsMode::Auto, &[]));

        assert_eq!(
            plan.config.servers,
            vec![
                "10.0.0.53".parse::<IpAddr>().unwrap(),
                "10.0.0.54".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn invalid_dns_server_is_rejected_before_apply() {
        let wg_conf = wg_conf(&["not-an-ip"], &[]);
        let config = dns_config(DnsMode::Auto, &[]);

        assert!(build_setdns_config(&wg_conf, &config, "utun4").is_err());
    }
}
