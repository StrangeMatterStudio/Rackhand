//! Who calls out (7.5.5 step 4, D47): when several healthy hubs see a peer down, only the one whose site name sorts first does,
//! so one dead hub is one callout and not one from each of its peers. A hub that isn't healthy itself is never elected: it may be
//! the one that is cut off.

/// Another hub as this one knows it from its latest summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub site: String,
    /// It sent a summary lately and says it is well (database, notifiers and self-check).
    pub healthy: bool,
    /// Its summary says it hasn't heard from the peer in question for as long as the down limit.
    pub sees_down: bool,
}

/// Whether `me` calls out for a peer it sees down.
pub fn elected(me: &str, i_am_healthy: bool, others: &[Candidate]) -> bool {
    if !i_am_healthy {
        return false;
    }
    others.iter().filter(|c| c.healthy && c.sees_down).all(|c| me < c.site.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(site: &str, healthy: bool, sees_down: bool) -> Candidate {
        Candidate { site: site.into(), healthy, sees_down }
    }

    #[test]
    fn first_sorted_healthy_reporter_calls_out() {
        // (me, others, expected)
        let cases = [
            ("alpha", vec![c("beta", true, true), c("gamma", true, true)], true),
            ("beta", vec![c("alpha", true, true), c("gamma", true, true)], false),
            ("gamma", vec![c("alpha", true, true), c("beta", true, true)], false),
            // a hub that doesn't see it down isn't a reporter: the dead one's neighbors decide among themselves
            ("beta", vec![c("alpha", true, false), c("gamma", true, true)], true),
            // alone, a hub calls out
            ("beta", vec![], true),
            // a hub that has the same name sorts equal and is not first
            ("alpha", vec![c("alpha", true, true)], false),
        ];
        for (me, others, expected) in cases {
            assert_eq!(elected(me, true, &others), expected, "{me} among {others:?}");
        }
    }

    #[test]
    fn unhealthy_hub_never_elected() {
        // a healthy first hub is passed over when it is the unhealthy one that sorts first
        assert!(!elected("alpha", false, &[]), "an unhealthy hub never calls out, even alone");
        assert!(!elected("alpha", false, &[c("beta", true, true)]));
        // an unhealthy other is not a candidate, so the next healthy one is elected
        assert!(elected("beta", true, &[c("alpha", false, true), c("gamma", true, true)]));
        // and one that sent nothing lately is not a candidate either
        assert!(elected("beta", true, &[c("alpha", false, false)]));
    }
}
