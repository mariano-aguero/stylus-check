# state-write-after-call

**High.** Checks effects interactions, checked against the code.

The rule fires when storage is written after the function has already made a call that could come back in. The storage cache is flushed for you on every high level call, which keeps cached reads honest, but it does not stop the callee calling back and finding state that has not been updated yet.

### Reported

```rust
let moved = token.transfer(&vm, Call::new_mutating(self), to, amount)?;
self.available.set(remaining);   // a reentrant call already saw the old value
```

### Not reported

```rust
self.available.set(remaining);
let moved = token.transfer(&vm, Call::new_mutating(self), to, amount)?;
```

### When it stays quiet

A static call cannot write state and cannot make a state changing call, so nothing it does can reenter. Reading a balance before deciding what to spend is the ordinary shape of a payment:

```rust
let balance = token.balance_of(self.vm(), Call::new(), this)?;
self.available.set(remaining);
```

Releasing a hand rolled lock is the one write that has to come last, and is not reported:

```rust
self.entered.set(false);
```
