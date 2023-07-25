use std::str::FromStr;

use crate::Holdstate;

#[test]
fn test_direct_conversion() {
    let open_str = Holdstate::Open.to_string();
    let open_state = Holdstate::from_str(&open_str).unwrap();
    assert_eq!(open_state, Holdstate::Open);

    let settled_str = Holdstate::Settled.to_string();
    let settled_state = Holdstate::from_str(&settled_str).unwrap();
    assert_eq!(settled_state, Holdstate::Settled);

    let canceled_str = Holdstate::Canceled.to_string();
    let canceled_state = Holdstate::from_str(&canceled_str).unwrap();
    assert_eq!(canceled_state, Holdstate::Canceled);

    let accepted_str = Holdstate::Accepted.to_string();
    let accepted_state = Holdstate::from_str(&accepted_str).unwrap();
    assert_eq!(accepted_state, Holdstate::Accepted);
}

#[test]
fn test_to_string() {
    assert_eq!(Holdstate::Open.to_string(), "open");
    assert_eq!(Holdstate::Settled.to_string(), "settled");
    assert_eq!(Holdstate::Canceled.to_string(), "canceled");
    assert_eq!(Holdstate::Accepted.to_string(), "accepted");
}

#[test]
fn test_from_str() {
    assert_eq!(Holdstate::from_str("open").unwrap(), Holdstate::Open);
    assert_eq!(Holdstate::from_str("settled").unwrap(), Holdstate::Settled);
    assert_eq!(
        Holdstate::from_str("canceled").unwrap(),
        Holdstate::Canceled
    );
    assert_eq!(
        Holdstate::from_str("accepted").unwrap(),
        Holdstate::Accepted
    );

    assert!(Holdstate::from_str("invalid").is_err());
}

#[test]
fn test_as_i32() {
    assert_eq!(Holdstate::Open.as_i32(), 0);
    assert_eq!(Holdstate::Settled.as_i32(), 1);
    assert_eq!(Holdstate::Canceled.as_i32(), 2);
    assert_eq!(Holdstate::Accepted.as_i32(), 3);
}

#[test]
fn test_is_valid_transition() {
    assert!(Holdstate::Open.is_valid_transition(&Holdstate::Open));
    assert!(Holdstate::Open.is_valid_transition(&Holdstate::Accepted));
    assert!(!Holdstate::Open.is_valid_transition(&Holdstate::Settled));
    assert!(Holdstate::Open.is_valid_transition(&Holdstate::Canceled));

    assert!(Holdstate::Settled.is_valid_transition(&Holdstate::Settled));
    assert!(!Holdstate::Settled.is_valid_transition(&Holdstate::Open));
    assert!(!Holdstate::Settled.is_valid_transition(&Holdstate::Accepted));
    assert!(!Holdstate::Settled.is_valid_transition(&Holdstate::Canceled));

    assert!(Holdstate::Canceled.is_valid_transition(&Holdstate::Canceled));
    assert!(!Holdstate::Canceled.is_valid_transition(&Holdstate::Open));
    assert!(!Holdstate::Canceled.is_valid_transition(&Holdstate::Settled));
    assert!(!Holdstate::Canceled.is_valid_transition(&Holdstate::Accepted));

    assert!(Holdstate::Accepted.is_valid_transition(&Holdstate::Open));
    assert!(Holdstate::Accepted.is_valid_transition(&Holdstate::Settled));
    assert!(Holdstate::Accepted.is_valid_transition(&Holdstate::Canceled));
    assert!(Holdstate::Accepted.is_valid_transition(&Holdstate::Accepted));
}

#[test]
fn test_display_trait() {
    assert_eq!(format!("{}", Holdstate::Open), "open");
    assert_eq!(format!("{}", Holdstate::Settled), "settled");
    assert_eq!(format!("{}", Holdstate::Canceled), "canceled");
    assert_eq!(format!("{}", Holdstate::Accepted), "accepted");
}
