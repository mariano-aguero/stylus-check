# deprecated-reentrancy-guard

**Medium.** The SDK's own reentrancy guard was deprecated in stylus-sdk 0.10.5.

Both the `reentrant` cargo feature and the `deny_reentrant` entrypoint guard are on their way out. The high level call functions now flush the storage cache themselves, which is what the guard existed for, and the feature blocks legitimate reentrant calls.

This rule exists because the advice most people bring from Solidity is to add a guard, and here that means adopting an API that is being removed.

### Reported

```toml
stylus-sdk = { version = "0.10", features = ["reentrant"] }
```

```rust
#[entrypoint]
#[deny_reentrant]
pub struct Account;
```

### What to do instead

Nothing, for cache coherence: it is handled. For reentrancy itself, keep writing state before you call out, which is what [state-write-after-call](state-write-after-call.md) checks. Cache flushing protects the cache, not your invariants.
