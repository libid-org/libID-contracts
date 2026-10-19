/// The platform table, the checks the identity circuits apply to handles and
/// ids (normalization, the id check and the refusals they throw) and the node
/// derivation. Loads without viem; the registry reads are in `../identity`.

export * from './handle.js'
export * from './id.js'
export * from './node.js'
export * from './platforms.js'
