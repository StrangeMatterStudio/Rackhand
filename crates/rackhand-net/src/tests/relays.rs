use crate::relays::RelayConfig;

#[test]
fn default_config_has_no_n0_services() {
    let config = RelayConfig::default();
    assert!(config.relays.is_empty(), "no relays unless configured");
    assert!(!config.n0_relays && !config.n0_discovery, "n0's public relays and DNS discovery are off by default");
    let mode = config.relay_mode().unwrap();
    assert!(matches!(mode, iroh::RelayMode::Disabled), "{mode:?}");

    let own = RelayConfig { relays: vec!["https://relay.example.net".into()], ..RelayConfig::default() };
    match own.relay_mode().unwrap() {
        iroh::RelayMode::Custom(map) => {
            assert_eq!(map.len(), 1);
            assert!(map.urls::<Vec<_>>().iter().all(|u| !u.to_string().contains("iroh.link")), "no n0 relay");
        }
        other => panic!("expected the hub's own relays, got {other:?}"),
    }
}

#[test]
fn listed_relays_come_after_own_and_never_get_the_key() {
    let config = RelayConfig {
        relays: vec!["https://own.example.net".into()],
        listed: vec!["https://listed.example.org".into(), "https://own.example.net".into()],
        auth_token: Some("rk1.key".into()),
        ..RelayConfig::default()
    };
    assert_eq!(config.ordered(), ["https://own.example.net", "https://listed.example.org", "https://own.example.net"]);
    let iroh::RelayMode::Custom(map) = config.relay_mode().unwrap() else { panic!("expected custom relays") };
    assert_eq!(map.len(), 2, "a listed relay that is also one of ours is ours, once");
    for config in map.relays::<Vec<_>>() {
        let own = config.url.to_string().contains("own.example.net");
        assert_eq!(config.auth_token.is_some(), own, "{}: only the operator's own relays get the key", config.url);
    }
}
