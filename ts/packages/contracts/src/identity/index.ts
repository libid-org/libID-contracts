/// The wallet-agnostic identity system, TypeScript half.
///
/// Handle normalization applies the token check and the fold the circuits
/// enforce; the chain only folds A-Z. The resolvers wrap the `IdentityRegistry` view calls.
/// Everything on-chain-shaped comes from the generated ABIs in `../abis`, so
/// this layer and the contracts cannot drift apart silently. Calldata for the
/// writes is generated in `../calls`.

export * from './handle.js'
export * from './platforms.js'
export * from './node.js'
export * from './resolve.js'
