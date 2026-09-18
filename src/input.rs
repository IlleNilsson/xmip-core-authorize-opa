//! The input: one identity attempting one thing, as the document a Rego
//! policy reads under `input`.

use authorize::Attempt;
use context::{AuthenticatedIdentity, IdentityFacts, Verified};
use serde_json::{Map, Value, json};
use xcore::Assurance;

/// The request body for the data API: `{"input": ...}`.
///
/// ```text
/// input.identity   mechanism, class, assurance, value, verified,
///                  party (where resolved), evidence (an object by name)
/// input.message    the same for the message identity (where there is one)
/// input.action     receive, process or send
/// input.artifact   input.contract   input.path   (the last two where carried)
/// input.at         unix seconds (where the attempt says when)
/// ```
///
/// No proof is in it, because no proof is on the record (ADR-0050,
/// amendment 2026-09-16): what leaves the node is what may be recorded.
#[must_use]
pub fn input(identity: &IdentityFacts, attempt: &Attempt) -> Value {
    let mut input = Map::new();

    input.insert("identity".into(), held(identity.accountable()));
    if let Some(message) = &identity.message {
        input.insert("message".into(), held(message));
    }
    input.insert("action".into(), attempt.action.to_string().into());
    input.insert("artifact".into(), attempt.artifact.clone().into());
    if let Some(contract) = &attempt.contract {
        input.insert("contract".into(), contract.clone().into());
    }
    if let Some(path) = &attempt.path {
        input.insert("path".into(), path.clone().into());
    }
    // Zero means the attempt did not say when, and JSON numbers that stay
    // exact everywhere are the ones that fit 53 bits: seconds do.
    if let Some(seconds) = i64::try_from(attempt.at / 1_000_000_000)
        .ok()
        .filter(|seconds| *seconds != 0)
    {
        input.insert("at".into(), seconds.into());
    }

    json!({ "input": input })
}

fn held(identity: &AuthenticatedIdentity) -> Value {
    let mut evidence = Map::new();
    for (name, value) in &identity.evidence {
        // The first entry under a name is the one a policy reads.
        evidence
            .entry(name.clone())
            .or_insert_with(|| value.clone().into());
    }

    let mut record = Map::new();
    record.insert("mechanism".into(), identity.mechanism.name().into());
    record.insert("class".into(), identity.class().to_string().into());
    record.insert(
        "assurance".into(),
        match identity.mechanism.assurance() {
            Assurance::Identifies => "identifies",
            Assurance::Authenticates => "authenticates",
        }
        .into(),
    );
    record.insert("value".into(), identity.value.clone().into());
    record.insert(
        "verified".into(),
        match identity.verified {
            Verified::Proven => "proven",
            Verified::Claimed => "claimed",
            Verified::Refused => "refused",
        }
        .into(),
    );
    if let Some(party) = identity.party_id {
        record.insert("party".into(), party.to_string().into());
    }
    record.insert("evidence".into(), Value::Object(evidence));

    Value::Object(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::Alignment;
    use xcore::{Established, PartyId, mechanism};

    #[test]
    fn the_input_is_the_record_and_the_attempt_and_nothing_that_proves_anything() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::jwt(),
                "sub=alice",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("department", "billing"),
            Some(AuthenticatedIdentity::new(
                mechanism::edi_x12_interchange(),
                "ISA06=PARTNERX",
                Established::Detected,
                Verified::Claimed,
            )),
        );
        let attempt = Attempt::new(Action::Send, "Billing")
            .on_contract("X12-810")
            .at(1_700_000_000 * 1_000_000_000);

        let body = input(&facts, &attempt);
        let input = &body["input"];

        assert_eq!(input["identity"]["mechanism"], "jwt");
        assert_eq!(input["identity"]["value"], "sub=alice");
        assert_eq!(input["identity"]["verified"], "proven");
        assert_eq!(
            input["identity"]["party"],
            "00000000-0000-0000-0000-000000000007"
        );
        assert_eq!(input["identity"]["evidence"]["department"], "billing");
        assert_eq!(input["message"]["assurance"], "identifies");
        assert_eq!(input["message"]["verified"], "claimed");
        assert_eq!(input["action"], "send");
        assert_eq!(input["artifact"], "Billing");
        assert_eq!(input["contract"], "X12-810");
        assert_eq!(input["at"], 1_700_000_000_i64);
        assert!(input.get("path").is_none());
    }
}
