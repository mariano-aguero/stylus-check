# missing-access-control

**Medium.** A public function changes storage without asking who called.

The rule fires only when the contract itself declares something that decides who may act, an `owner`, an `admin`, a role mapping. A contract with no such field is either deliberately open or is a different kind of mistake, and flagging every setter in it would be noise.

### Reported

```rust
sol_storage! { pub struct A { address owner; uint256 budget; } }

#[public]
impl A {
    pub fn set_budget(&mut self, v: U256) {
        self.budget.set(v);   // anyone at all
    }
}
```

### Not reported

```rust
pub fn set_budget(&mut self, v: U256) -> Result<(), Vec<u8>> {
    self.only_owner()?;
    self.budget.set(v);
    Ok(())
}
```

### Handing over the authority itself

The worst version of this gets its own sentence, because it is the one nobody notices:

```rust
pub fn set_owner(&mut self, next: Address) {
    self.owner.set(next);   // anyone can walk off with the contract
}
```

*Writing* the owner is not *consulting* the owner. Treating those as the same thing is how a checker misses the only function that matters.

### When it stays quiet

Reading the authority counts as consulting it, even without a visible comparison, because a function that loads the owner is doing it for a reason. Calls to anything named `only_*`, `require_*`, `assert_*` or `ensure_*` count too, as does any comparison against `msg_sender`. Read only functions are never reported, and neither is a `#[constructor]`: the SDK runs it once at deployment, so a guard there is a guard against a caller that cannot exist.
