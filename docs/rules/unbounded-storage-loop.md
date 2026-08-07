# unbounded-storage-loop

**Medium.** A loop as long as a collection that callers can grow.

Once it is long enough the call runs out of gas, and whatever it protects is stuck for everyone. This is a denial of service with no attacker required: ordinary use gets there on its own.

### Reported

```rust
sol_storage! { pub struct A { address[] holders; } }

pub fn sweep(&mut self) {
    for i in 0..self.holders.len() {   // grows every time somebody joins
        pay(self.holders.get(i));
    }
}
```

### Not reported

```rust
pub fn sweep(&mut self, from: usize, count: usize) {
    for i in from..(from + count).min(self.holders.len()) {
        pay(self.holders.get(i));
    }
}
```

Better still, let each holder claim their own entry, so the work is paid for by whoever benefits.

### When it stays quiet

Loops with a fixed bound, and loops over anything the contract did not declare as a dynamic collection.
