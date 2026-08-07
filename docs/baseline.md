# Baseline

A checker that reports things nobody will fix gets uninstalled after one run, and then it catches nothing at all. So the rules are measured against code that is known good before they are measured against code that is known bad.

Two baselines are kept, and both are run before any rule changes.

## An audited contract, which should be silent

[agent-smart-account](https://github.com/mariano-aguero/agent-smart-account) is a Stylus contract that has been through two security reviews. It reports **nothing**, at every severity.

Silence is only worth something if the rules would have spoken. Four defects were introduced into a copy of that contract, one per rule, and each was reported at the right line:

| Introduced | Reported as |
| --- | --- |
| dropped the result of a token transfer | `unchecked-call-result` |
| removed the owner check from `set_limits` | `missing-access-control` |
| narrowed a `uint256` budget to `u64` | `lossy-integer-conversion` |
| moved a storage write below the transfer | `state-write-after-call` |
| removed the guard from an ownership handover | `missing-access-control` |

## The stylus-sdk examples, which should be honest

The [official examples](https://github.com/OffchainLabs/stylus-sdk-rs/tree/main/examples), 95 files, produce **12 findings**. They are listed here rather than tuned away, because every one of them is a decision somebody should be able to check.

**Ten are real.** Nine are `self.collection.get(index).unwrap()` in a public function whose `index` comes from the caller: an index past the end traps, taking the caller's gas and giving back no reason. They are in `arrays`, `storage_data_types` and `caller`. The tenth is a loop over a storage array that a public `push` can grow, in `arrays`.

**One is deliberate.** `callee` contains `panic!("This function is designed to fail")`, which is the point of that example.

**One is a limit of the rules.** `nested_structs` unwraps a lookup whose index is bounded by the collection's own length, so it cannot fail. Proving that needs range analysis, which this checker does not do and is not going to: the rule reports lookups whose key comes from outside, and here the key is a loop variable that happens to be safe.

That ratio is the target. Ten true, one intentional, one wrong is a tool worth running; the same rules before they were narrowed produced 29 findings on the same code, and most of the extra were noise.

## What narrowing them cost and bought

Each of these came from running against real code, not from thinking about it:

- **Static calls are not interactions.** A `Call::new()` is a staticcall and cannot come back in, so a write after one is not out of order. Before this, reading a token balance and then recording a spend was reported as a reentrancy bug. Three false positives on the audited contract, all gone.
- **A contract model belongs to one crate.** Building it across a whole tree merged the storage of every example into one imaginary contract, and functions were reported for not consulting an owner that belonged to somebody else's code.
- **Panics only matter if a caller can cause one.** `I256::try_from(20_003_000).unwrap()` cannot fail at run time. Reporting it halved the signal and taught the reader to skim.
- **Writing the authority is not reading it.** `set_owner` writes `owner`, and counting that as consulting `owner` made the rule silent on the single most dangerous function a contract can expose. Found by reviewing the rule against a contract written for the purpose, not by the baselines, which had no such function in them.
- **A constructor has no caller to check.** The SDK runs it once at deployment. Requiring a guard there was a finding on the SDK's own `constructor` example.
- **Documented fields are still fields.** `sol_storage!` arrives as an opaque token stream, and a documented field carries its doc comment as an attribute. Discarding attributes discarded the field with them, so every storage aware rule went quiet while still looking like it had run. This was the worst of the four, because it failed silently.

## Reproducing

```bash
git clone --depth 1 https://github.com/OffchainLabs/stylus-sdk-rs
cargo run --release -- stylus-sdk-rs/examples --fail-on low
```
