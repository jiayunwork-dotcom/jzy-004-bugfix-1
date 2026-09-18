// Package crc implements a parametric cyclic redundancy check (CRC)
// engine. A CRC algorithm is fully described by a Params value: the
// register width, the generator polynomial, the initial register value,
// whether input bytes are reflected, whether the output register is
// reflected, and the final XOR value.
//
// Reflection semantics are defined exactly once, here in the core
// package, and are shared by the bitwise and the table-driven division
// paths as well as by checksum generation and verification:
//
//   - RefIn: each input byte is bit-reversed before it is XORed into
//     the top of the register.
//   - RefOut: the final register is bit-reversed across the full width
//     before the XOR-out value is applied.
package crc

import "fmt"

// Params fully describes one CRC algorithm variant.
type Params struct {
	// Width is the register width in bits. It must be a multiple of 8
	// between 8 and 64 so that check values are byte aligned and can be
	// appended to a message for verification.
	Width int
	// Poly is the generator polynomial, truncated to Width bits (the
	// implicit top bit is not stored). It must be non-zero and fit in
	// Width bits.
	Poly uint64
	// Init is the initial register value. It must fit in Width bits.
	Init uint64
	// RefIn selects bit-reflection of every input byte.
	RefIn bool
	// RefOut selects bit-reflection of the final register.
	RefOut bool
	// XorOut is XORed onto the (possibly reflected) register to produce
	// the check value. It must fit in Width bits.
	XorOut uint64
}

// ParamError describes an invalid parameter set. It is a distinct type
// so callers can map it to a structured "invalid_params" API error.
type ParamError struct {
	Field   string
	Message string
}

func (e *ParamError) Error() string {
	return fmt.Sprintf("invalid parameter %s: %s", e.Field, e.Message)
}

// Mask returns the bitmask covering Width bits.
func (p Params) Mask() uint64 {
	return maskForWidth(p.Width)
}

func maskForWidth(width int) uint64 {
	if width >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(width)) - 1
}

// Validate reports whether the parameter set is usable. Any violation is
// returned as a *ParamError before any computation takes place.
func (p Params) Validate() error {
	if p.Width < 8 || p.Width > 64 || p.Width%8 != 0 {
		return &ParamError{Field: "width", Message: "must be a multiple of 8 between 8 and 64"}
	}
	mask := p.Mask()
	if p.Poly == 0 {
		return &ParamError{Field: "poly", Message: "must be non-zero"}
	}
	if p.Poly > mask {
		return &ParamError{Field: "poly", Message: fmt.Sprintf("exceeds %d-bit width", p.Width)}
	}
	if p.Init > mask {
		return &ParamError{Field: "init", Message: fmt.Sprintf("exceeds %d-bit width", p.Width)}
	}
	if p.XorOut > mask {
		return &ParamError{Field: "xorout", Message: fmt.Sprintf("exceeds %d-bit width", p.Width)}
	}
	return nil
}
