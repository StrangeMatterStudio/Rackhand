//! The command wrapper behind sudo (7.3.7, AC57), in a container.

mod runcmd {
    use crate::support::{Container, container_binary};

    fn text(out: &std::process::Output) -> String {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn sudo_entry_runs_wrapper_only() {
        let probe = container_binary("rackhand-probe", "rackhand-probe");
        let c = Container::start("runcmd");
        c.copy_in(&probe, "/usr/local/lib/rackhand/run");
        assert!(
            c.root("chown root:root /usr/local/lib/rackhand/run && chmod 0755 /usr/local/lib/rackhand/run")
                .status
                .success()
        );
        let list = serde_json::json!({
            "version": 1,
            "commands": [
                {"runbook": "t", "step": "whoami", "args": [{"literal": "/usr/bin/id"}, {"literal": "-u"}]},
                {"runbook": "t", "step": "touch", "args": [{"literal": "/usr/bin/touch"},
                    {"param": "name", "regex": "^(?:/tmp/allowed-[a-z]+)$", "allow_leading_dash": false}]}
            ]
        });
        let w = c.exec(None, &["sh", "-c", "cat > /etc/rackhand/commands.json"], Some(list.to_string().as_bytes()));
        assert!(w.status.success());
        let run = |args: &[&str]| {
            let mut all = vec!["sudo", "-n", "/usr/local/lib/rackhand/run"];
            all.extend_from_slice(args);
            c.exec(Some("rackhand"), &all, None)
        };
        // Allowed: runs as root, through the wrapper.
        let id = run(&["/usr/bin/id", "-u"]);
        assert!(id.status.success(), "{}", String::from_utf8_lossy(&id.stderr));
        assert_eq!(text(&id), "0");
        assert!(run(&["/usr/bin/touch", "/tmp/allowed-ok"]).status.success());
        assert!(c.root("test -e /tmp/allowed-ok").status.success());
        // Not in the list: refused, nothing created.
        let refused = run(&["/usr/bin/touch", "/tmp/other"]);
        assert_eq!(refused.status.code(), Some(126), "{}", String::from_utf8_lossy(&refused.stderr));
        assert!(!c.root("test -e /tmp/other").status.success());
        assert_eq!(run(&["/usr/bin/id"]).status.code(), Some(126), "fewer arguments");
        // sudo itself allows nothing but the wrapper.
        for other in [&["/usr/bin/id"][..], &["/bin/sh", "-c", "id"], &["/usr/local/lib/rackhand/../rackhand/run2"]] {
            let mut all = vec!["sudo", "-n"];
            all.extend_from_slice(other);
            let out = c.exec(Some("rackhand"), &all, None);
            assert!(!out.status.success(), "sudo {other:?} worked");
        }
        // install-commands through sudo refuses a payload that isn't signed by the pinned hub.
        c.root("printf '[hub]\\nid = \"%064d\"\\n' 0 > /etc/rackhand-probe/probe.toml");
        let before = text(&c.root("sha256sum /etc/rackhand/commands.json"));
        let install = ["sudo", "-n", "/usr/local/lib/rackhand/run", "install-commands"];
        let out = c.exec(Some("rackhand"), &install, Some(b"garbage"));
        assert!(!out.status.success());
        assert_eq!(text(&c.root("sha256sum /etc/rackhand/commands.json")), before);
    }
}
