# libid-identity

The libid identity keys off chain: handle normalization, the id rules and,
with the `node` feature, the nodes a binding is stored under.

`normalize(raw, rules)` turns a platform handle into the form the identity
system hashes into a node, matching the circuits' `lib/identity` byte for
byte. It folds `A-Z` to `a-z` and changes nothing else, so `" @Alice_1 "` is
`" @alice_1 "`, not `alice_1`. The handle must be one JSON string as the
platform sent it, printable ASCII without `"` or `\`, within the circuit's
buffer. It is not Unicode case folding or UTS-46.

```rust
use libid_identity::{normalize, HandleError, Rules};

assert_eq!(normalize("Alice_1", Rules::X), Ok("alice_1".to_string()));
assert_eq!(normalize("Ali\"ce", Rules::X), Err(HandleError::BadCharacter));
```

`check_id(id, rules)` accepts an id exactly as the platform sent it (digits for
X and GitHub, a JSON string's bytes for Google), or says why no circuit would
hash it. Ids are never normalized.

With the `node` feature, a table platform computes `SHA256(tag || value)`:
`handle_node(raw)` and `id_node(id)` give the node the platform's circuit
outputs and `IdentityRegistry` and `HandleEscrow` key by, and
`folded_handle_node(text)` is the registry's `handleNodeOf`: it folds A-Z and
hashes, checking no byte. `platforms::platform(key)` finds a platform by its
key, or `None`:

```toml
libid-identity = { version = "0.17", features = ["node"] }
```

```rust
use libid_identity::platforms::platform;

let github = platform("github").unwrap();
// hashlib.sha256(b"libid.github.handleoctocat"): what HandleEscrow.deposit takes.
let node = github.handle_node("OctoCat").unwrap();
assert_eq!(node[..4], [0x38, 0x1f, 0xb9, 0xd7]);
// hashlib.sha256(b"libid.github.user-id583231"): what resolveId takes.
let id = github.id_node("583231").unwrap();
assert_eq!(id[..4], [0x47, 0x59, 0x02, 0xb2]);
assert!(platform("myspace").is_none());
```

`scripts/regen-identity-handles.py` generates the per-platform buffers
(`Rules::X`, `Rules::GITHUB`, `Rules::GOOGLE`), the node tags and the shared
vector table from the pinned libID-circuits release's `platforms.json` and
`handles.json`, vendored into `solidity/contracts/circuits/`. Rust,
TypeScript and Noir run the same table, so a normalizer that drifts from the
circuits fails a test. On chain only the fold runs. The `test-helpers`
feature exposes the table as `vectors`; each row's `expected` is the
`Result` the transform returns.

`platforms` also carries each platform key (`PLATFORM_X_KEY`, …) and the
`HandleError` and `IdError` refusals, and `rules_for` returns a platform's
buffers by its key; `keccak256` of the key is the platform id the contracts
take.

## Dependencies

None by default. The `node` feature adds `sha2`.
