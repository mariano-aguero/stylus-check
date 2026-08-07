# unwrap-in-entrypoint

**High.** A panic on Stylus is a WASM trap. The caller gets no reason back and loses the gas it sent, which is worse than a revert in every way.

The rule fires when a panic can be caused by whoever called: an `unwrap` or `expect` on a lookup, on checked arithmetic, or on a cross contract call, where the value flowing in came from a parameter or from storage. It also fires on `panic!`, `todo!`, `unimplemented!` and `unreachable!`, which trap unconditionally.

### Reported

```rust
pub fn element_at(&self, index: U256) -> U256 {
    self.items.get(index).unwrap()   // an index past the end traps
}
```

### Not reported

```rust
pub fn element_at(&self, index: U256) -> Result<U256, Vec<u8>> {
    self.items.get(index).ok_or_else(|| b"NO_SUCH_INDEX".to_vec())
}
```

### When it stays quiet

Nothing a caller controls reaches the operation, so it either always works or fails the first time anybody runs it:

```rust
let limit = I256::try_from(20_003_000).unwrap();
```

Conversions between sizes the contract already fixed are not reported either, because four bytes always fit in four bytes:

```rust
let selector: [u8; 4] = interface.as_slice().try_into().unwrap();
```
