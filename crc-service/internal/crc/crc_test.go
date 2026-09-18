package crc

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"
)

// TestStandardVectors pins every registered model to the check value
// published in the CRC catalogue for the ASCII string "123456789".
func TestStandardVectors(t *testing.T) {
	want := map[string]uint64{
		"CRC-8":              0xF4,
		"CRC-8/MAXIM":        0xA1,
		"CRC-16/CCITT-FALSE": 0x29B1,
		"CRC-16/ARC":         0xBB3D,
		"CRC-16/MODBUS":      0x4B37,
	}
	for _, m := range Models() {
		w, ok := want[m.Name]
		if !ok {
			t.Fatalf("no reference value for model %s", m.Name)
		}
		if got := m.Checksum([]byte("123456789")); got != w {
			t.Errorf("%s: check(\"123456789\") = %#X, want %#X", m.Name, got, w)
		}
	}
}

// TestRoundTrip encodes payloads and verifies data+check; every model
// must accept its own output, including for the empty payload.
func TestRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	payloads := [][]byte{nil, {}, []byte("123456789"), []byte{0x00}, []byte{0xFF, 0x00, 0xFF}}
	for i := 0; i < 8; i++ {
		b := make([]byte, rng.Intn(256))
		rng.Read(b)
		payloads = append(payloads, b)
	}
	for _, m := range Models() {
		for _, data := range payloads {
			check := m.Checksum(data)
			ok, residue := m.Verify(data, check)
			if !ok {
				t.Errorf("%s: verify(data, %#X) failed, residue %#X", m.Name, check, residue)
			}
		}
	}
}

// TestSingleBitFlipAlwaysFails flips every single bit of the data and of
// the check value in turn; verification must fail every time.
func TestSingleBitFlipAlwaysFails(t *testing.T) {
	data := []byte("123456789")
	for _, m := range Models() {
		check := m.Checksum(data)

		for i := range data {
			for bit := 0; bit < 8; bit++ {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[i] ^= 1 << uint(bit)
				if ok, _ := m.Verify(tampered, check); ok {
					t.Errorf("%s: flipped data bit %d of byte %d still verified", m.Name, bit, i)
				}
			}
		}
		for bit := 0; bit < m.Params.Width; bit++ {
			if ok, _ := m.Verify(data, check^(1<<uint(bit))); ok {
				t.Errorf("%s: flipped check bit %d still verified", m.Name, bit)
			}
		}
	}
}

// TestMixedReflectionVectors pins the three parameter sets from the
// incident report: mixed RefIn/RefOut switches must keep their published
// encode values AND round-trip through Verify. These values are
// cross-checked against an independent bitwise reference; encode must not
// be "adjusted" to please verify.
func TestMixedReflectionVectors(t *testing.T) {
	data := []byte("123456789")
	cases := []struct {
		name  string
		p     Params
		check uint64
	}{
		{"refin-only-16", Params{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: true, RefOut: false, XorOut: 0x5678}, 0x1BD4},
		{"refout-only-16", Params{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: false, RefOut: true, XorOut: 0x5678}, 0x81CF},
		{"refin-only-8", Params{Width: 8, Poly: 0x07, Init: 0xFF, RefIn: true, RefOut: false, XorOut: 0x00}, 0x0B},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := NewModel(c.name, c.p)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Checksum(data); got != c.check {
				t.Fatalf("check = %#X, want %#X (encoding must not move)", got, c.check)
			}
			if ok, residue := m.Verify(data, c.check); !ok {
				t.Errorf("round trip rejected: residue %#X, want constant %#X", residue, m.Residue())
			}
			// The residue constant computed at construction (empty
			// message) must equal the residue of the real message.
			if _, residue := m.Verify(data, c.check); residue != m.Residue() {
				t.Errorf("residue %#X != model constant %#X", residue, m.Residue())
			}
		})
	}
}

// TestAllReflectionCombinationsRoundTrip exercises every RefIn/RefOut
// combination across several widths, with zero and non-zero XorOut,
// against multiple payload shapes (empty, single byte, the catalogue
// vector, longer random data). Encode followed by verify must always
// pass on both the table and bitwise paths.
func TestAllReflectionCombinationsRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	payloads := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF},
		[]byte("123456789"),
		bytes.Repeat([]byte{0xAB}, 257),
	}
	long := make([]byte, 1000)
	rng.Read(long)
	payloads = append(payloads, long)

	widths := []int{8, 16, 24, 32, 64}
	for _, width := range widths {
		mask := maskForWidth(width)
		// Odd polynomials (constant term set) are exactly the generators
		// capable of detecting every single-bit error.
		poly := (rng.Uint64() & mask) | 1
		init := rng.Uint64() & mask
		for _, xorOut := range []uint64{0, rng.Uint64() & mask} {
			for refin := 0; refin <= 1; refin++ {
				for refout := 0; refout <= 1; refout++ {
					p := Params{
						Width:  width,
						Poly:   poly,
						Init:   init,
						RefIn:  refin == 1,
						RefOut: refout == 1,
						XorOut: xorOut,
					}
					m, err := NewModel("exhaustive", p)
					if err != nil {
						t.Fatalf("params %+v: %v", p, err)
					}
					table := makeTable(p)
					for _, data := range payloads {
						check := m.Checksum(data)
						if want := checksumBitwise(p, data); want != check {
							t.Fatalf("%+v: table %#X != bitwise %#X", p, check, want)
						}
						if want := checksumTable(p, &table, data); want != check {
							t.Fatalf("%+v: rebuilt table disagrees", p)
						}
						if ok, residue := m.Verify(data, check); !ok {
							t.Errorf("%+v len=%d: verify failed, residue %#X != %#X",
								p, len(data), residue, m.Residue())
						}
						if ok, _ := m.Verify(data, m.Residue()); ok && check != m.Residue() {
							t.Errorf("%+v len=%d: a different check value verified", p, len(data))
						}
					}
				}
			}
		}
	}
}

// TestMixedReflectionSingleBitFlip complements the preset-based flip
// test: for every mixed-reflection parameter set, flipping any bit of the
// data or of the check value must make Verify fail, including on empty
// payloads (check-only flips).
func TestMixedReflectionSingleBitFlip(t *testing.T) {
	payloads := [][]byte{nil, {0x42}, []byte("123456789"), bytes.Repeat([]byte{0x01, 0xFE}, 64)}
	sets := []Params{
		{Width: 8, Poly: 0x07, Init: 0xFF, RefIn: true, RefOut: false},
		{Width: 8, Poly: 0x31, Init: 0x00, RefIn: false, RefOut: true, XorOut: 0x5A},
		{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: true, RefOut: false, XorOut: 0x5678},
		{Width: 16, Poly: 0x8005, Init: 0xABCD, RefIn: false, RefOut: true, XorOut: 0xFFFF},
		{Width: 32, Poly: 0x04C11DB7, Init: 0xDEADBEEF, RefIn: true, RefOut: false, XorOut: 0x01020304},
		{Width: 32, Poly: 0x04C11DB7, Init: 0x01020304, RefIn: false, RefOut: true, XorOut: 0xDEADBEEF},
	}
	for _, p := range sets {
		m, err := NewModel("flip", p)
		if err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
		for _, data := range payloads {
			check := m.Checksum(data)
			if ok, _ := m.Verify(data, check); !ok {
				t.Fatalf("%+v: baseline round trip failed for len %d", p, len(data))
			}
			for i := range data {
				for bit := 0; bit < 8; bit++ {
					tampered := make([]byte, len(data))
					copy(tampered, data)
					tampered[i] ^= 1 << uint(bit)
					if ok, _ := m.Verify(tampered, check); ok {
						t.Errorf("%+v len=%d: flipped data bit %d of byte %d verified", p, len(data), bit, i)
					}
				}
			}
			for bit := 0; bit < p.Width; bit++ {
				if ok, _ := m.Verify(data, check^(1<<uint(bit))); ok {
					t.Errorf("%+v len=%d: flipped check bit %d verified", p, len(data), bit)
				}
			}
		}
	}
}

// TestCheckBytesCancellation is the algebraic pin for CheckBytes: for
// every reflection combination and every message, the residue produced by
// appending CheckBytes(check) must be the model's precomputed constant,
// while corrupting any single transmitted byte must leave a different
// residue.
func TestCheckBytesCancellation(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	for _, width := range []int{8, 16, 32, 48, 64} {
		mask := maskForWidth(width)
		basePoly := uint64(0x07)
		if width >= 16 {
			basePoly = 0x1021
		}
		for _, p := range []Params{
			{Width: width, Poly: basePoly, Init: 0, RefIn: false, RefOut: false},
			{Width: width, Poly: mask&^uint64(1) | 1, Init: mask, RefIn: true, RefOut: true, XorOut: mask},
			{Width: width, Poly: (rng.Uint64() & mask) | 1, Init: rng.Uint64() & mask, RefIn: true, RefOut: false, XorOut: rng.Uint64() & mask},
			{Width: width, Poly: (rng.Uint64() & mask) | 1, Init: rng.Uint64() & mask, RefIn: false, RefOut: true, XorOut: rng.Uint64() & mask},
		} {
			m, err := NewModel("cancel", p)
			if err != nil {
				t.Fatalf("%+v: %v", p, err)
			}
			for _, data := range [][]byte{nil, []byte("123456789"), randomBytes(rng, 300)} {
				check := m.Checksum(data)
				wire := append(append([]byte{}, data...), CheckBytes(p, check)...)
				if got := m.Checksum(wire); got != m.Residue() {
					t.Errorf("%+v len=%d: residue %#X, want %#X", p, len(data), got, m.Residue())
				}
				for i := range wire {
					for bit := 0; bit < 8; bit++ {
						broken := make([]byte, len(wire))
						copy(broken, wire)
						broken[i] ^= 1 << uint(bit)
						if m.Checksum(broken) == m.Residue() {
							t.Errorf("%+v: flipping wire bit %d of byte %d still yields residue", p, bit, i)
						}
					}
				}
			}
		}
	}
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// TestDifferentWidthsDiffer ensures the 8-bit and 16-bit models do not
// produce the same check value for the same data.
func TestDifferentWidthsDiffer(t *testing.T) {
	m8, err := Lookup("CRC-8")
	if err != nil {
		t.Fatal(err)
	}
	m16, err := Lookup("CRC-16/CCITT-FALSE")
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{[]byte("123456789"), {}, []byte("a"), []byte("hello world"), {0xDE, 0xAD, 0xBE, 0xEF}}
	for _, data := range inputs {
		if m8.Checksum(data) == m16.Checksum(data) {
			t.Errorf("8-bit and 16-bit checks coincide (%#X) for %q", m8.Checksum(data), data)
		}
	}
}

// TestReflectionConsistency checks that reflected models are handled
// consistently on both sides: the check values match the catalogue
// (proving RefIn/RefOut are applied), round-trip verification passes,
// and presenting the check bytes in the wrong byte order fails.
func TestReflectionConsistency(t *testing.T) {
	data := []byte("123456789")
	for _, name := range []string{"CRC-8/MAXIM", "CRC-16/ARC", "CRC-16/MODBUS"} {
		m, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if !m.Params.RefIn || !m.Params.RefOut {
			t.Fatalf("%s: expected a reflected model", name)
		}
		check := m.Checksum(data)
		if ok, _ := m.Verify(data, check); !ok {
			t.Errorf("%s: round-trip verification failed", name)
		}
		// Byte-swapping the check value must break verification: the
		// serialisation order is part of the reflection convention and
		// cannot silently disagree between encode and verify. (An 8-bit
		// check is a single byte, so swapping is a no-op there.)
		if n := m.Params.Width / 8; n > 1 {
			raw := CheckBytes(m.Params, check)
			for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
				raw[i], raw[j] = raw[j], raw[i]
			}
			var swapped uint64
			for i := 0; i < n; i++ {
				swapped |= uint64(raw[i]) << uint(8*i)
			}
			if ok, _ := m.Verify(data, swapped); ok {
				t.Errorf("%s: byte-swapped check %#X wrongly verified", name, swapped)
			}
		}
	}

	// Same polynomial with and without reflection must differ, proving
	// reflection actually changes the computation.
	reflected, _ := Lookup("CRC-16/ARC")
	plain, err := NewModel("plain-8005", Params{Width: 16, Poly: 0x8005})
	if err != nil {
		t.Fatal(err)
	}
	if reflected.Checksum(data) == plain.Checksum(data) {
		t.Errorf("reflected and non-reflected variants coincide for %q", data)
	}
}

// TestBitwiseEqualsTable feeds identical inputs through the bitwise and
// the table-driven division paths, including random explicit parameter
// sets, and requires identical residues.
func TestBitwiseEqualsTable(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	var paramSets []Params
	for _, m := range Models() {
		paramSets = append(paramSets, m.Params)
	}
	for i := 0; i < 32; i++ {
		width := 8 * (1 + rng.Intn(8)) // 8,16,...,64
		mask := maskForWidth(width)
		p := Params{
			Width:  width,
			Poly:   rng.Uint64()&mask | 1,
			Init:   rng.Uint64() & mask,
			RefIn:  rng.Intn(2) == 0,
			RefOut: rng.Intn(2) == 0,
			XorOut: rng.Uint64() & mask,
		}
		paramSets = append(paramSets, p)
	}

	for _, p := range paramSets {
		table := makeTable(p)
		for i := 0; i < 16; i++ {
			data := make([]byte, rng.Intn(300))
			rng.Read(data)
			gotBitwise := checksumBitwise(p, data)
			gotTable := checksumTable(p, &table, data)
			if gotBitwise != gotTable {
				t.Fatalf("params %+v: bitwise %#X != table %#X for %d bytes", p, gotBitwise, gotTable, len(data))
			}
		}
	}
}

// TestEmptyPayload pins the deterministic check value of an empty
// payload: with no input bytes the register stays at Init, so the check
// is reflect(Init) ^ XorOut. It must never crash or return an error.
func TestEmptyPayload(t *testing.T) {
	want := map[string]uint64{
		"CRC-8":              0x00,
		"CRC-8/MAXIM":        0x00,
		"CRC-16/CCITT-FALSE": 0xFFFF,
		"CRC-16/ARC":         0x0000,
		"CRC-16/MODBUS":      0xFFFF,
	}
	for _, m := range Models() {
		got := m.Checksum(nil)
		if got != want[m.Name] {
			t.Errorf("%s: empty payload check = %#X, want %#X", m.Name, got, want[m.Name])
		}
		if got2 := m.Checksum([]byte{}); got2 != got {
			t.Errorf("%s: nil vs empty slice differ: %#X != %#X", m.Name, got, got2)
		}
		if ok, _ := m.Verify(nil, got); !ok {
			t.Errorf("%s: empty payload does not verify", m.Name)
		}
	}
}

// TestResidueConstant verifies that the CRC of (message || check bytes)
// is the same constant for every message, which is what makes Verify
// sound. All presets have XorOut == 0, so the constant is zero.
func TestResidueConstant(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, m := range Models() {
		if m.Residue() != 0 {
			t.Errorf("%s: residue = %#X, want 0", m.Name, m.Residue())
		}
		for i := 0; i < 8; i++ {
			data := make([]byte, rng.Intn(128))
			rng.Read(data)
			check := m.Checksum(data)
			_, residue := m.Verify(data, check)
			if residue != m.Residue() {
				t.Errorf("%s: residue %#X for message %d, want constant %#X", m.Name, residue, i, m.Residue())
			}
		}
	}
}

// TestConcurrency hammers every model from many goroutines and requires
// every result to match the sequentially precomputed value, proving no
// state leaks between requests.
func TestConcurrency(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	models := Models()

	type job struct {
		model *Model
		data  []byte
		check uint64
	}
	var jobs []job
	for i := 0; i < 256; i++ {
		m := models[rng.Intn(len(models))]
		data := make([]byte, rng.Intn(512))
		rng.Read(data)
		jobs = append(jobs, job{m, data, m.Checksum(data)})
	}

	var wg sync.WaitGroup
	errs := make(chan string, 1024)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				j := jobs[(g+round)%len(jobs)]
				if got := j.model.Checksum(j.data); got != j.check {
					errs <- "checksum mismatch under concurrency"
				}
				if ok, _ := j.model.Verify(j.data, j.check); !ok {
					errs <- "verify failed under concurrency"
				}
				if ok, _ := j.model.Verify(j.data, j.check^1); ok {
					errs <- "tampered check verified under concurrency"
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestParamValidation rejects out-of-range explicit parameters before
// any computation.
func TestParamValidation(t *testing.T) {
	bad := []Params{
		{Width: 0, Poly: 0x07},
		{Width: 7, Poly: 0x07},
		{Width: 9, Poly: 0x07},                // not a multiple of 8
		{Width: 72, Poly: 0x07},               // too wide
		{Width: 8, Poly: 0x00},                // zero polynomial
		{Width: 8, Poly: 0x06},                // even polynomial (x factor): cannot detect single-bit errors
		{Width: 8, Poly: 0x100},               // polynomial exceeds width
		{Width: 8, Poly: 0x07, Init: 0x100},   // init exceeds width
		{Width: 8, Poly: 0x07, XorOut: 0x1FF}, // xorout exceeds width
	}
	for _, p := range bad {
		if _, err := NewModel("bad", p); err == nil {
			t.Errorf("params %+v: expected validation error", p)
		} else if _, ok := err.(*ParamError); !ok {
			t.Errorf("params %+v: error %T is not *ParamError", p, err)
		}
	}
	good := []Params{
		{Width: 8, Poly: 0x07},
		{Width: 64, Poly: 0x42F0E1EBA9EA3693, Init: ^uint64(0), XorOut: ^uint64(0)},
		{Width: 16, Poly: 0x1021, Init: 0xFFFF, RefIn: true, RefOut: false},
	}
	for _, p := range good {
		if _, err := NewModel("good", p); err != nil {
			t.Errorf("params %+v: unexpected error %v", p, err)
		}
	}
}

// TestUnknownModel ensures unknown names are rejected, never guessed.
func TestUnknownModel(t *testing.T) {
	for _, name := range []string{"", "CRC-16", "crc-8", "CRC-32", "nope"} {
		if _, err := Lookup(name); err == nil {
			t.Errorf("Lookup(%q): expected error", name)
		} else if _, ok := err.(*UnknownModelError); !ok {
			t.Errorf("Lookup(%q): error %T is not *UnknownModelError", name, err)
		}
	}
}
