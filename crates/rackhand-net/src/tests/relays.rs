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
