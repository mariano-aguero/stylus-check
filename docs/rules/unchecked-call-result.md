# unchecked-call-result

**High.** A token that reports failure by returning `false` rather than by reverting will look like it paid.

The rule fires when a call to another contract sits in statement position and its answer is dropped, and only when `sol_interface!` said that function returns something. A call declared to return nothing has no result to discard.

### Reported

```rust
token.transfer(&vm, Call::new_mutating(self), recipient, amount)?;
// the `?` handles a revert. It does not handle `Ok(false)`.
```

### Not reported

```rust
let moved = token.transfer(&vm, Call::new_mutating(self), recipient, amount)?;
if !moved {
    return Err(b"TRANSFER_FAILED".to_vec());
}
```

### When it stays quiet

The interface declares no return value, so there is nothing to check:

```rust
// function poke(address who) external;
registry.poke(&vm, ctx, who)?;
```
