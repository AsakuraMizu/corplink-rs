use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;

pub(crate) fn parse_server_route(route: &str) -> std::result::Result<IpNet, String> {
    match route.parse::<IpNet>() {
        Ok(route) => Ok(route),
        Err(cidr_err) => match route.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(IpNet::from(ip)),
            Err(ip_err) => Err(format!("not CIDR ({cidr_err}) or IP ({ip_err})")),
        },
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteSet {
    v4: IpRange<Ipv4Net>,
    v6: IpRange<Ipv6Net>,
}

impl RouteSet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add(&mut self, route: IpNet) -> &mut Self {
        match route {
            IpNet::V4(route) => {
                self.v4.add(route);
            }
            IpNet::V6(route) => {
                self.v6.add(route);
            }
        }
        self
    }

    pub(crate) fn remove(&mut self, route: IpNet) -> &mut Self {
        match route {
            IpNet::V4(route) => {
                self.v4.remove(route);
            }
            IpNet::V6(route) => {
                self.v6.remove(route);
            }
        }
        self
    }

    pub(crate) fn merge(&self, other: &Self) -> Self {
        Self {
            v4: self.v4.merge(&other.v4),
            v6: self.v6.merge(&other.v6),
        }
    }

    pub(crate) fn exclude(&self, other: &Self) -> Self {
        Self {
            v4: self.v4.exclude(&other.v4),
            v6: self.v6.exclude(&other.v6),
        }
    }

    pub(crate) fn simplify(&mut self) {
        self.v4.simplify();
        self.v6.simplify();
    }

    pub(crate) fn contains(&self, route: &IpNet) -> bool {
        match route {
            IpNet::V4(route) => self.v4.contains(route),
            IpNet::V6(route) => self.v6.contains(route),
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.v4
            .iter()
            .map(IpNet::from)
            .chain(self.v6.iter().map(IpNet::from))
    }
}

impl FromIterator<IpNet> for RouteSet {
    fn from_iter<T: IntoIterator<Item = IpNet>>(iter: T) -> Self {
        let mut routes = Self::new();
        for route in iter {
            routes.add(route);
        }
        routes.simplify();
        routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(route: &str) -> IpNet {
        route.parse().unwrap()
    }

    fn host(addr: &str) -> IpNet {
        IpNet::from(addr.parse::<std::net::IpAddr>().unwrap())
    }

    #[test]
    fn mixed_v4_v6_exclude_and_extra_routes_preserve_expected_membership() {
        let server: RouteSet = [route("0.0.0.0/0"), route("::/0")].into_iter().collect();
        let disallowed: RouteSet = [route("10.0.0.0/8"), route("fd00::/8")]
            .into_iter()
            .collect();
        let extra: RouteSet = [route("10.1.2.0/24"), route("fd00:1234::/48")]
            .into_iter()
            .collect();

        let allowed = server.exclude(&disallowed).merge(&extra);

        assert!(allowed.contains(&host("8.8.8.8")));
        assert!(allowed.contains(&host("2001:4860:4860::8888")));
        assert!(!allowed.contains(&host("10.2.3.4")));
        assert!(!allowed.contains(&host("fd00:ffff::1")));
        assert!(allowed.contains(&host("10.1.2.99")));
        assert!(allowed.contains(&host("fd00:1234::1")));
    }

    #[test]
    fn peer_endpoint_is_carved_after_extra_routes() {
        let server: RouteSet = [route("0.0.0.0/0")].into_iter().collect();
        let disallowed: RouteSet = [route("10.0.0.0/8")].into_iter().collect();
        let extra: RouteSet = [route("10.1.2.3/32")].into_iter().collect();
        let peer = host("10.1.2.3");

        let mut allowed = server.exclude(&disallowed).merge(&extra);
        assert!(allowed.contains(&peer));

        allowed.remove(peer);
        allowed.simplify();

        assert!(!allowed.contains(&host("10.1.2.3")));
        assert!(allowed.contains(&host("8.8.8.8")));
    }

    #[test]
    fn server_route_parser_accepts_host_routes() {
        assert_eq!(
            parse_server_route("10.2.2.25").unwrap().to_string(),
            "10.2.2.25/32"
        );
        assert_eq!(
            parse_server_route("fd00::25").unwrap().to_string(),
            "fd00::25/128"
        );
        assert_eq!(
            parse_server_route("10.2.2.0/24").unwrap().to_string(),
            "10.2.2.0/24"
        );
    }
}
