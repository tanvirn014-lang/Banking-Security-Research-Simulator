# BankSec Lab — Error Handling Conventions

## Codes

`internal/apperr.Code` classifies every error BankSec Lab produces:

| Code | Meaning |
|---|---|
| `validation` | malformed or disallowed input |
| `unauthorized` | a principal attempted an action outside its permissions |
| `not_found` | a referenced account/key/record does not exist |
| `conflict` | a security-mode rejection (replay, tamper, downgrade) or a business-rule conflict (insufficient funds) |
| `internal` | anything else, including errors apperr doesn't recognize |

## When to use `New` vs `Wrap`

- `apperr.New(code, msg)` — a fresh error with no underlying cause (most
  sentinel errors: `var ErrInsufficientFunds = apperr.New(apperr.CodeConflict, "insufficient funds")`).
- `apperr.Wrap(code, msg, err)` — adds context to an existing error (yours
  or a stdlib/library error) while keeping it inspectable via `errors.Is`/`errors.As`.

## Wrapping changes the code

`apperr.CodeOf` returns the **outermost** `*apperr.Error`'s code — wrapping
a cause with a different code reclassifies it, it does not add to it.
`Wrap(CodeInternal, "while loading account", someNotFoundErr)` reports as
`internal`, not `not_found`. If you want to add context without
reclassifying, either use `fmt.Errorf("...: %w", err)` (which `CodeOf`
sees through via `errors.As` to the next `*apperr.Error` in the chain), or
call `Wrap(apperr.CodeOf(err), ...)` to carry the original code forward
explicitly. This matters most for protocol/security rejections (`conflict`)
and lookup failures (`not_found`) — wrapping one with the wrong code at the
wrong layer can make a real rejection or miss look like an internal fault
in results.

## Comparing errors

Always compare with `errors.Is(err, ErrSentinel)`, never by comparing
`.Error()` strings — string comparison breaks the moment a message is
reworded. `apperr.Wrap` preserves `errors.Is` through the chain.

## Mapping to exit codes / response codes

The CLI and protocol server call `apperr.CodeOf(err)` to get a `Code` and
map it generically (e.g. `conflict` -> protocol `ErrConflict` response /
CLI exit code 2) instead of a type switch over every possible error.
`CodeOf` returns `CodeInternal` for any error that isn't (and doesn't
wrap) an `*apperr.Error` — never guess a code for an untyped error.
