# Memory Consistency Checking

Ensuring memory access consistency is a critical requirement for any correct ZKVM implementation, and zkMove is no exception.

When we began designing this component, most known ZKVMs — including Scroll and Cairo VM — were based on the *sorting method*. In that approach, the prover collects the complete memory access trace, sorts it by memory address, and uses the sorted table to verify memory consistency. A detailed description of the algorithm can be found in \[1\].

The previous version of zkMove also implemented the sorting method. In practice, however, it performed poorly and could not meet our target of client-side proving. Furthermore, since sorted data is derived from the original trace, maintaining consistency between the two requires additional constraints. This historical dependency also requires the full execution trace before sorting can begin, which is unfriendly to parallelization.

For the current version, we redesigned the memory consistency checking (MCC) mechanism from scratch.

## Algorithm

**Is there a sorting-free MCC algorithm?**

Yes. The paper \[2\] (July 2023) introduces a simple *address cycle* method, inspired by the 1994 paper \[3\]. The same approach is also used in \[4\] (2024).

The idea is straightforward. Start with two multisets, `R` (reads) and `W` (writes):

- **Initialization:** `R` starts empty; `W` starts with an initial tuple `(address, value, counter=0)` for every memory address.
- **On each read:** add the tuple `(a, v, c)` to `R`, and add `(a, v, c+1)` to `W`.
- **On each write:** add the tuple `(a, v, c)` to `R`, and add `(a, v', c+1)` to `W`, where `v'` is the new value.
- **At program termination:** for each memory address, add its final tuple to `R` without a corresponding `W` entry.

If the prover is honest, `R` and `W` will be permutations of each other (i.e., equal as multisets). The asymmetric initialization — `W` starts with values while `R` does not — ensures that `R = W` holds at the end only if no cheating occurred.

### Applying MCC to the Stack

Move programs involve not only memory operations but also stack operations. The same MCC algorithm applies to the stack as well.

Stack operations must follow the order `W → R → W → R → …`, where `W` is a push and `R` is a pop:

- **On stack push:** add `(address=top, value=write_value, timestamp=now)` to `W`.
- **On stack pop:** add `(address=top, value=read_value, timestamp)` to `R`.

At the end of execution, `R = W` holds if and only if the prover is honest.

## Implementation

With these two building blocks, it becomes straightforward to constrain stack and local variable operations in Move.

The stack-related cells were intentionally left unintroduced earlier in the document; the MCC background makes them easier to understand.

**Stack cells:**

| `stack_pop_index` | `stack_pop_sub_index` | `stack_pop_value` | `stack_pop_value_flag` | `stack_pop_version` | `stack_push_index` | `stack_push_sub_index` | `stack_push_value` | `stack_push_value_flag` | `stack_push_version` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

In brief:

- The tuple `(stack_pop_index, stack_pop_sub_index, stack_pop_value, stack_pop_value_flag, stack_pop_version)` represents the **R** set.
- The tuple `(stack_push_index, stack_push_sub_index, stack_push_value, stack_push_value_flag, stack_push_version)` represents the **W** set.

These tuples are 5-tuples rather than 3-tuples because Move supports complex data structures. This is explained in detail in later sections.

zkMove enforces `R = W` using Halo2's [shuffle feature](https://github.com/privacy-scaling-explorations/halo2/pull/185). The implementation is concise:

```rust
meta.shuffle("stack consistency check", |meta| {
    let s_usable = meta.query_selector(s_usable);
    let pop_version = step_curr.state.stack_pop_version.expr();
    // NOTICE: version is also used as a selector to exclude empty operations
    let pop_set = [
        step_curr.state.stack_pop_index.expr(),
        step_curr.state.stack_pop_sub_index.expr(),
        step_curr.state.stack_pop_value_header.expr(),
        pop_version.clone(),
    ]
    .into_iter()
    .chain(step_curr.state.stack_pop_value.exprs())
    .map(|e| s_usable.clone() * pop_version.clone() * e);

    let push_version = step_curr.state.stack_push_version.expr();
    let push_set = [
        step_curr.state.stack_push_index.expr(),
        step_curr.state.stack_push_sub_index.expr(),
        step_curr.state.stack_push_value_header.expr(),
        push_version.clone(),
    ]
    .into_iter()
    .chain(step_curr.state.stack_push_value.exprs())
    .map(|e| s_usable.clone() * push_version.clone() * e);

    pop_set.zip(push_set).collect()
});
```

## References

\[1\] David Wong, *Cairo's Public Memory.*
<https://www.cryptologie.net/article/603/cairos-public-memory>

\[2\] Yibin Yang and David Heath, *Two Shuffles Make a RAM: Improved Constant Overhead Zero-Knowledge RAM* (2023).
<https://eprint.iacr.org/2023/1115>

\[3\] Blum et al., *Checking the Correctness of Memories* (1994).
<https://www.researchgate.net/publication/226386605_Checking_the_correctness_of_memories>

\[4\] Kothapalli et al., *Ceno: Non-uniform, Segment and Parallel Zero-knowledge Virtual Machine* (2024).
<https://eprint.iacr.org/2024/387.pdf>
