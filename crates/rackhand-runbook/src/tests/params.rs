use crate::params::{Param, ParamError, ParamType, check_value};

fn string(pattern: &str) -> Param {
    Param { kind: ParamType::String, pattern: Some(pattern.into()), allow_leading_dash: false, description: None }
}

#[test]
fn pattern_must_match_whole_value() {
    let p = string("^[a-z]+");
    assert_eq!(check_value(&p, "abc"), Ok(()));
    assert_eq!(check_value(&p, "abc;rm"), Err(ParamError::NoMatch), "anchored at both ends");
    let unanchored = string("[a-z]+");
    assert_eq!(check_value(&unanchored, "x abc y"), Err(ParamError::NoMatch));
    let alternation = string("ab|cd");
    assert_eq!(check_value(&alternation, "abcd"), Err(ParamError::NoMatch), "the anchors wrap the whole alternation");
    let int = Param { kind: ParamType::Int, pattern: None, allow_leading_dash: false, description: None };
    assert_eq!(check_value(&int, "42"), Ok(()));
    assert_eq!(check_value(&int, "4 2"), Err(ParamError::WrongType));
    let bool_ = Param { kind: ParamType::Bool, pattern: None, allow_leading_dash: false, description: None };
    assert_eq!(check_value(&bool_, "true"), Ok(()));
    assert_eq!(check_value(&bool_, "yes"), Err(ParamError::WrongType));
}

#[test]
fn leading_dash_refused_unless_allowed() {
    let p = string(".*");
    assert_eq!(check_value(&p, "-f"), Err(ParamError::LeadingDash));
    assert_eq!(check_value(&p, "--force"), Err(ParamError::LeadingDash));
    let allowed = Param { allow_leading_dash: true, ..string(".*") };
    assert_eq!(check_value(&allowed, "-f"), Ok(()));
    let int = Param { kind: ParamType::Int, pattern: None, allow_leading_dash: false, description: None };
    assert_eq!(check_value(&int, "-1"), Err(ParamError::LeadingDash), "a negative number is an option too");
}
