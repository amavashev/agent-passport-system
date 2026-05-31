# Scope Dimension Registry

A registry of delegation scope dimensions. Each dimension declares a `type`, a
decidable boolean, and an `enforcement_strength` (`strict` or `advisory`).

The registry extends the M6 feasibility module (`src/v2/feasibility`). It does
not duplicate the scope, spend, depth, or temporal constraint emission: those
four dimensions are declared here as strict decidable and routed into
`compileFeasibility`. The registry classifies and describes; M6 emits the
obligation; no solver runs.

## Strict vs advisory

- **Strict decidable** dimensions (`mechanically_enforceable`) route into the
  M6 hard obligation. They may deny, through the M6 obligation.
- **Advisory** dimensions (`evidentially_auditable` / `socially_adjudicated`)
  are removed from the hard check and carried as honest-scope only. An advisory
  dimension can never be the basis of a hard deny.

A non-decidable dimension (free-text `purpose`) is always advisory. A documented
`decidablePath` records how to promote it to a decidable controlled code.

## New dimensions

- **`data_class`**: `enum_set` over a closed vocabulary (`public`, `internal`,
  `confidential`, `pii`, `restricted`). A child grant must be a subset of the
  parent grant: set narrowing only.
- **`destination`**: `string_set` allow-list of permitted egress
  destinations. A child grant must be a subset of the parent allow-list. This is
  the decidable allow-list slot, not a taint analytic: it narrows the permitted
  set, it does not score or classify flows.

## Partial order

Set-valued strict dimensions narrow under the subset relation, reusing the
data-can-only-narrow invariant (`src/core/data-narrowing.ts`) and the
four-valued Belnap `ConstraintStatus` (`src/types/gateway.ts`). A child member
the parent did not grant is a widening and fails the check.

## Proof box

**Proves:** which delegation dimensions are decidably enforced (strict, routed
into the M6 hard obligation) versus advisory (excluded from the hard check). For
a strict decidable set-valued dimension, that a declared child value is a subset
of the parent value, or is rejected as a widening.

**Does NOT prove:** that an advisory free-text purpose was honored. An advisory
dimension is self-declared and not mechanically checkable, which is exactly why
it is excluded from the hard check and can never be the basis of a hard deny.
This module also does not decide the M6 obligation; it routes to the M6 compiler
and classifies the dimensions. No solver runs.
