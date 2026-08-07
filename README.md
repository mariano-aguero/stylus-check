# stylus-check

[![CI](https://github.com/mariano-aguero/stylus-check/actions/workflows/ci.yml/badge.svg)](https://github.com/mariano-aguero/stylus-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Arbitrum](https://img.shields.io/badge/Arbitrum-Stylus-28a0f0)](https://arbitrum.io/stylus)

Static security checks for Arbitrum Stylus contracts, written for the stylus-sdk rather than for Solidity.

```bash
cargo install stylus-check
stylus-check ./src
```

```
src/lib.rs:462:9 high [unchecked-call-result]
  the result of `transfer` is discarded, and the interface says it returns one
  bind the result and act on it. A token that reports failure by returning false
  rather than reverting will otherwise look like it paid.
```

Slither does not read Rust, and clippy does not know that a panic on Stylus is a trap that eats the caller's gas, that a write after an external call is a reentrancy problem, or that a `uint256` narrowed to a `u64` is somebody's balance being silently rounded off. This reads what the contract already declared about itself and checks the rest against it.

## What it reads that a general purpose linter cannot

A Stylus contract writes down more about itself than plain Rust does, and both macros are worth reading.

`sol_storage!` gives the exact width and type of every field. That is what lets one rule be exact where a guess would be useless:

```rust
sol_storage! { pub struct Account { uint256 budget; uint64 last_refill; } }

self.last_refill.get().to::<u64>()   // silence: declared 64 bits, converted to 64
self.budget.get().to::<u64>()        // reported: 256 bits into 64
```

`sol_interface!` says which functions leave the contract, whether they return anything, and whether they are `view`. A view function is reached by a static call, which cannot write state and cannot call back, so writing storage after one is not a reentrancy bug. Not knowing that was three false positives on the first contract this was pointed at.

## The rules

| Rule | | |
| --- | --- | --- |
| [unwrap-in-entrypoint](docs/rules/unwrap-in-entrypoint.md) | high | a panic a caller can cause, which traps instead of reverting |
| [unchecked-call-result](docs/rules/unchecked-call-result.md) | high | a cross contract call whose answer is thrown away |
| [state-write-after-call](docs/rules/state-write-after-call.md) | high | storage written after a call that can come back in |
| [lossy-integer-conversion](docs/rules/lossy-integer-conversion.md) | high | a storage value narrowed into a type too small to hold it |
| [missing-access-control](docs/rules/missing-access-control.md) | medium | a public function changes storage without asking who called |
| [unbounded-storage-loop](docs/rules/unbounded-storage-loop.md) | medium | a loop as long as something callers can grow |
| [deprecated-reentrancy-guard](docs/rules/deprecated-reentrancy-guard.md) | medium | the SDK guard that was deprecated in 0.10.5 |

`stylus-check --explain` prints the same list.

That last rule is the one people find surprising. The advice everyone brings from Solidity is to add a reentrancy guard, and on Stylus that now means adopting a deprecated API: the SDK removed `deny_reentrant` in 0.10.5 because the high level call functions flush the storage cache themselves. That is not the same as being safe from reentrancy, which is why the ordering rule exists.

## Staying quiet

Every rule here is a syntactic pattern over source. There is no type inference, so each rule is written to say nothing when it cannot tell, rather than to guess. A checker that cries wolf gets uninstalled, and then it catches nothing at all.

The rules are measured on an audited contract, where they report nothing, and on the stylus-sdk's own examples, where they report twelve things. Every one of those twelve is classified in [docs/baseline.md](docs/baseline.md), including the one that is wrong and why narrowing it further is not worth what it would cost.

## Output and exit codes

```bash
stylus-check ./src                        # for reading
stylus-check ./src --format json          # for scripting
stylus-check ./src --format sarif         # for code scanning, which annotates pull requests
stylus-check ./src --fail-on high         # only high severity breaks the build
```

Exit `0` when nothing reached the threshold, `1` when something did, `2` when the run could not happen at all. Pointing it at a project with no stylus-sdk dependency is a `2` and a sentence, not a page of findings from rules that do not apply.

A file that does not parse is named as skipped and the rest are still checked, because half a report during a refactor beats no report.

## Configuration

`stylus-check.toml` in the project root:

```toml
disable = ["unbounded-storage-loop"]

[severity]
missing-access-control = "high"
```

A rule id that does not exist is an error rather than something ignored, so a typo cannot leave you believing a rule is off while it is still running.

## What this is not

It is not an audit and it cannot prove anything. A quiet run means these rules found nothing to say about this code, which is a much smaller claim, and the tool prints that on every run so nobody has to remember it.

It does not execute the code either. For the other half of the problem there is [stylus-debug-suite](https://github.com/ILE-Labs/stylus-debug-suite), which runs contracts under `wasmtime` and analyses the traces. It sees what an execution reaches; this sees what is written down. They are complementary.

## Related

- [agent-smart-account](https://github.com/mariano-aguero/agent-smart-account): the Stylus contract these rules were sharpened against
- [stylus-crypto-verify](https://github.com/mariano-aguero/stylus-crypto-verify): Ed25519 and friends, on Stylus

## License

[MIT](LICENSE)
