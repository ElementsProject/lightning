use crate::Hodlstate;

#[test]
fn test_direct_conversion() {
    let open_str = Hodlstate::Open.to_string();
    let open_state = Hodlstate::from_str(&open_str).unwrap();
    assert_eq!(open_state, Hodlstate::Open);

    let settled_str = Hodlstate::Settled.to_string();
    let settled_state = Hodlstate::from_str(&settled_str).unwrap();
    assert_eq!(settled_state, Hodlstate::Settled);

    let canceled_str = Hodlstate::Canceled.to_string();
    let canceled_state = Hodlstate::from_str(&canceled_str).unwrap();
    assert_eq!(canceled_state, Hodlstate::Canceled);

    let accepted_str = Hodlstate::Accepted.to_string();
    let accepted_state = Hodlstate::from_str(&accepted_str).unwrap();
    assert_eq!(accepted_state, Hodlstate::Accepted);
}

#[test]
fn test_to_string() {
    assert_eq!(Hodlstate::Open.to_string(), "open");
    assert_eq!(Hodlstate::Settled.to_string(), "settled");
    assert_eq!(Hodlstate::Canceled.to_string(), "canceled");
    assert_eq!(Hodlstate::Accepted.to_string(), "accepted");
}

#[test]
fn test_from_str() {
    assert_eq!(Hodlstate::from_str("open").unwrap(), Hodlstate::Open);
    assert_eq!(Hodlstate::from_str("settled").unwrap(), Hodlstate::Settled);
    assert_eq!(
        Hodlstate::from_str("canceled").unwrap(),
        Hodlstate::Canceled
    );
    assert_eq!(
        Hodlstate::from_str("accepted").unwrap(),
        Hodlstate::Accepted
    );

    assert!(Hodlstate::from_str("invalid").is_err());
}

#[test]
fn test_as_i32() {
    assert_eq!(Hodlstate::Open.as_i32(), 0);
    assert_eq!(Hodlstate::Settled.as_i32(), 1);
    assert_eq!(Hodlstate::Canceled.as_i32(), 2);
    assert_eq!(Hodlstate::Accepted.as_i32(), 3);
}

#[test]
fn test_is_valid_transition() {
    assert!(Hodlstate::Open.is_valid_transition(&Hodlstate::Open));
    assert!(Hodlstate::Open.is_valid_transition(&Hodlstate::Accepted));
    assert!(!Hodlstate::Open.is_valid_transition(&Hodlstate::Settled));
    assert!(Hodlstate::Open.is_valid_transition(&Hodlstate::Canceled));

    assert!(Hodlstate::Settled.is_valid_transition(&Hodlstate::Settled));
    assert!(!Hodlstate::Settled.is_valid_transition(&Hodlstate::Open));
    assert!(!Hodlstate::Settled.is_valid_transition(&Hodlstate::Accepted));
    assert!(!Hodlstate::Settled.is_valid_transition(&Hodlstate::Canceled));

    assert!(Hodlstate::Canceled.is_valid_transition(&Hodlstate::Canceled));
    assert!(!Hodlstate::Canceled.is_valid_transition(&Hodlstate::Open));
    assert!(!Hodlstate::Canceled.is_valid_transition(&Hodlstate::Settled));
    assert!(!Hodlstate::Canceled.is_valid_transition(&Hodlstate::Accepted));

    assert!(Hodlstate::Accepted.is_valid_transition(&Hodlstate::Open));
    assert!(Hodlstate::Accepted.is_valid_transition(&Hodlstate::Settled));
    assert!(Hodlstate::Accepted.is_valid_transition(&Hodlstate::Canceled));
    assert!(Hodlstate::Accepted.is_valid_transition(&Hodlstate::Accepted));
}

#[test]
fn test_display_trait() {
    assert_eq!(format!("{}", Hodlstate::Open), "open");
    assert_eq!(format!("{}", Hodlstate::Settled), "settled");
    assert_eq!(format!("{}", Hodlstate::Canceled), "canceled");
    assert_eq!(format!("{}", Hodlstate::Accepted), "accepted");
}
