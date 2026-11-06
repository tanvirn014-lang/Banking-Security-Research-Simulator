// Package apperr gives every error in BankSec Lab a Code, so the CLI and
// protocol server can map errors to exit codes / response codes generically
// instead of a per-error-type switch. See CONVENTIONS.md for usage rules.
package apperr

import "errors"

// Code classifies an error for CLI exit codes and protocol error responses.
type Code string

const (
	CodeValidation   Code = "validation"
	CodeUnauthorized Code = "unauthorized"
	CodeNotFound     Code = "not_found"
	CodeConflict     Code = "conflict" // e.g. replay/tamper/downgrade rejections
	CodeInternal     Code = "internal"
)

// Error is a Code-classified error, optionally wrapping an underlying cause.
type Error struct {
	Code Code
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// New creates a Code-classified error with no wrapped cause.
func New(code Code, msg string) *Error {
	return &Error{Code: code, Msg: msg}
}

// Wrap creates a Code-classified error wrapping an existing cause, so
// errors.Is against the original cause still succeeds.
func Wrap(code Code, msg string, err error) *Error {
	return &Error{Code: code, Msg: msg, Err: err}
}

// CodeOf returns err's Code, or CodeInternal if err is not (and does not
// wrap) an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}
