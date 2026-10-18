# Atomic P/D admission reservations (Unreleased)

## Fixed

Reserve a bounded prefill slot atomically before dispatch. Each request owns
its Prefill/Decode load units; rollback, retry, cancellation and cleanup return
only those units, including when the admission cap is disabled. A routing hint
alone cannot release another request's Decode unit. Qualify parked FIFO wakes
by the fd generation so cancellation/reuse cannot wake a different request.

## Changed

D3: keep and harden the opt-in legacy P/D FIFO. It remains separate from FC
capacity admission, with the existing default-off settings and bounded wait.
D1 and D2 terminal policies are implemented separately in the terminal PR.
