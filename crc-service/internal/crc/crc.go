package crc

import "math/bits"

// reflectBits reverses the low n bits of v. This is the single place in
// the codebase where reflection is defined; both division paths and both
// directions (encode and verify) go through it.
func reflectBits(v uint64, n int) uint64 {
	return bits.Reverse64(v) >> (64 - n)
}

// reflectByte reverses the bits of one byte.
func reflectByte(b byte) byte {
	return byte(bits.Reverse8(b))
}

// checksumBitwise computes the CRC of data one bit at a time. It is the
// reference implementation: simple, obviously correct, and slow.
func checksumBitwise(p Params, data []byte) uint64 {
	mask := p.Mask()
	top := uint64(1) << uint(p.Width-1)
	reg := p.Init & mask
	for _, b := range data {
		if p.RefIn {
			b = reflectByte(b)
		}
		reg ^= uint64(b) << uint(p.Width-8)
		for i := 0; i < 8; i++ {
			if reg&top != 0 {
				reg = (reg << 1) ^ p.Poly
			} else {
				reg <<= 1
			}
			reg &= mask
		}
	}
	if p.RefOut {
		reg = reflectBits(reg, p.Width)
	}
	return (reg ^ p.XorOut) & mask
}

// makeTable builds the 256-entry lookup table for the MSB-first
// division. Entry i is the register state after feeding byte i through
// an initially zero register with no reflection and no XOR-out; input
// and output reflection are applied around the table walk, so one table
// serves both reflected and non-reflected models.
func makeTable(p Params) [256]uint64 {
	base := Params{Width: p.Width, Poly: p.Poly}
	var t [256]uint64
	for i := 0; i < 256; i++ {
		t[i] = checksumBitwise(base, []byte{byte(i)})
	}
	return t
}

// checksumTable computes the CRC of data eight bits at a time using the
// precomputed table. It must agree with checksumBitwise on every input;
// the tests enforce this.
func checksumTable(p Params, table *[256]uint64, data []byte) uint64 {
	mask := p.Mask()
	reg := p.Init & mask
	for _, b := range data {
		if p.RefIn {
			b = reflectByte(b)
		}
		idx := byte(reg>>uint(p.Width-8)) ^ b
		reg = ((reg << 8) & mask) ^ table[idx]
	}
	if p.RefOut {
		reg = reflectBits(reg, p.Width)
	}
	return (reg ^ p.XorOut) & mask
}

// Checksum computes the check value of data under the given parameters
// using the table-driven path. It allocates no state beyond the call and
// is safe for concurrent use.
func Checksum(p Params, data []byte) uint64 {
	table := makeTable(p)
	return checksumTable(p, &table, data)
}

// CheckBytes serialises a check value into the byte order used when the
// check is appended to the message for transmission and verification.
//
// Verification feeds the appended bytes back through the division loop,
// so the serialisation must be the exact inverse of that path: the bytes
// the loop ends up XORing into the register — i.e. after its RefIn
// reflection — must be the raw register bytes in MSB-first order, which
// is the only sequence that cancels the register to a constant residue
// for every message. The check value is the (possibly RefOut-reflected)
// register, so the wire bytes are
//
//	RefIn applied per byte to the big-endian bytes of RefOut(check)
//
// (both reflections are involutions, and XorOut contributes only a
// constant to the residue, so it needs no handling here). When
// RefIn == RefOut this reduces to the familiar convention: reflected
// models transmit least significant byte first, all others most
// significant byte first. When the flags differ, the per-byte RefIn
// pre-reflection is what keeps encode and verify consistent.
func CheckBytes(p Params, check uint64) []byte {
	n := p.Width / 8
	if p.RefOut {
		check = reflectBits(check, p.Width)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		b := byte(check >> uint(8*(n-1-i)))
		if p.RefIn {
			b = reflectByte(b)
		}
		out[i] = b
	}
	return out
}
