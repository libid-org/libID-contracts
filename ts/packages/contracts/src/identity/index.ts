/// Identity helpers: handle normalization, node derivation, and resolvers over
/// the `IdentityRegistry` view calls.
///
/// Normalization applies the token check and the fold the circuits enforce;
/// the chain only folds A-Z. Calldata for the writes is in `../calls`.

export * from './handle.js'
export * from './platforms.js'
export * from './node.js'
export * from './resolve.js'
