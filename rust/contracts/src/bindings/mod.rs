//! Hand-written `alloy::sol!` bindings, kept in lockstep with the Solidity
//! sources in `solidity/contracts`. One module per contract directory.

pub mod ceremony;
pub mod circuits;
pub mod ens;
pub mod escrow;
pub mod factory;
pub mod identity;
pub mod proxy;

/// The drift check the hand-written bindings are held to.
#[cfg(test)]
pub(crate) mod drift {
    use std::collections::BTreeMap;

    use alloy::json_abi::{
        Event,
        Function,
        JsonAbi,
    };

    use crate::Artifacts;

    /// A function as the check compares it: its selector's signature, its
    /// output types and its state mutability. A selector alone would miss a
    /// binding that decodes the wrong return.
    fn function(f: &Function) -> (String, String) {
        (
            format!(
                "function {} {}",
                f.signature_with_outputs(),
                f.state_mutability.as_json_str()
            ),
            format!("function {}", f.signature()),
        )
    }

    /// An event with which of its parameters are indexed: the topic hash
    /// alone would miss a binding that decodes an indexed field from data.
    fn event(e: &Event) -> (String, String) {
        let params: Vec<String> = e
            .inputs
            .iter()
            .map(|p| {
                if p.indexed {
                    format!("{} indexed", p.ty)
                } else {
                    p.ty.clone()
                }
            })
            .collect();
        (
            format!("event {}({})", e.name, params.join(",")),
            format!("event {}", e.signature()),
        )
    }

    /// Every item of an ABI, keyed by what the check compares, with the
    /// plain signature `omitted` names it by.
    fn items(abi: &JsonAbi) -> BTreeMap<String, String> {
        abi.functions()
            .map(function)
            .chain(abi.events().map(event))
            .chain(abi.errors().map(|e| {
                (
                    format!("error {}", e.signature()),
                    format!("error {}", e.signature()),
                )
            }))
            .collect()
    }

    /// Every item in the vendored artifact ABI is bound identically (inputs,
    /// outputs, mutability, indexing) or listed in `omitted`, and the binding
    /// has nothing extra.
    pub(crate) fn assert_binding_matches_artifact(
        file: &str,
        contract: &str,
        bound: &JsonAbi,
        omitted: &[&str],
    ) {
        assert_shared_binding_matches_artifact(file, contract, bound, omitted, &[]);
    }

    /// The same, for a binding one interface shares between contracts:
    /// `elsewhere` lists the bound items, by full signature, that this
    /// contract lacks and a sibling has.
    pub(crate) fn assert_shared_binding_matches_artifact(
        file: &str,
        contract: &str,
        bound: &JsonAbi,
        omitted: &[&str],
        elsewhere: &[&str],
    ) {
        // The crate embeds no ABI; the check reads forge's build output.
        let out = concat!(env!("CARGO_MANIFEST_DIR"), "/../../solidity/out");
        let json = Artifacts::from_dir(out)
            .raw(file, contract)
            .expect("no forge build output; run `forge build` in solidity/");
        let compiled: JsonAbi = serde_json::from_value(json["abi"].clone())
            .expect("the forge artifact has no ABI");
        let compiled = items(&compiled);
        let bound = items(bound);

        let mut unbound: Vec<&str> = compiled
            .iter()
            .filter(|(full, _)| !bound.contains_key(*full))
            .map(|(_, short)| short.as_str())
            .collect();
        unbound.sort_unstable();
        unbound.dedup();
        let mut omitted = omitted.to_vec();
        omitted.sort_unstable();
        assert_eq!(
            unbound, omitted,
            "{contract}: the artifact has items the binding does not bind as compiled, or the \
             omitted list is stale"
        );

        let extra: Vec<&str> = bound
            .keys()
            .filter(|full| !compiled.contains_key(*full))
            .map(String::as_str)
            .filter(|full| !elsewhere.contains(full))
            .collect();
        assert!(
            extra.is_empty(),
            "{contract}: the binding has items the contract does not: {extra:?}"
        );
    }
}
