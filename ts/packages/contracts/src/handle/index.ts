/// Handle normalization on its own, with no dependency on viem.
///
/// `@libid/contracts/identity` also carries the resolvers and node hashing,
/// which import viem when the module loads. A consumer that only normalizes a
/// handle, or reads the generated rules and vectors or the ENS Parent Name,
/// imports this instead. `index.test.ts` keeps it that way.

export * from '../identity/ens.js'
export * from '../identity/handle.js'
export * from '../identity/handleVectors.js'
