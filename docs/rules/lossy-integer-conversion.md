# lossy-integer-conversion

**High** when the loss is silent, **medium** when it panics.

The rule reads the width a field was declared with in `sol_storage!` and compares it against the width being converted to. That declaration is the whole reason the rule can be quiet on correct code: the same line is exact or lossy depending on a type the contract already wrote down.

### Reported

```rust
sol_storage! { pub struct A { uint256 budget; } }

let n = self.budget.get().wrapping_to::<u64>();  // the top bits vanish silently
let m = self.budget.get() as u32;                // same
let p = self.budget.get().to::<u64>();           // panics, and a panic is a trap
```

### Not reported

```rust
sol_storage! { pub struct A { uint64 last_refill; } }

let n = self.last_refill.get().to::<u64>();      // declared 64 bits, converted to 64
```

### When it stays quiet

Once a value has been through arithmetic the declaration no longer bounds it, and claiming otherwise would be a guess:

```rust
let n = (self.budget.get() * factor).to::<u64>();
```
