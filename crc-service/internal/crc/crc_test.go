package crc

import (
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

// TestMixedReflectionVectors pins the check values of the reported
// mixed-reflection parameter sets (RefIn != RefOut) and requires each
// one to verify against itself. The check values must not move: the fix
// for the verify side lives in the check serialisation, not in the
// checksum computation.
func TestMixedReflectionVectors(t *testing.T) {
	data := []byte("123456789")
	cases := []struct {
		name   string
		params Params
		check  uint64
	}{
		{"refin-only-16", Params{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: true, RefOut: false, XorOut: 0x5678}, 0x1BD4},
		{"refout-only-16", Params{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: false, RefOut: true, XorOut: 0x5678}, 0x81CF},
		{"refin-only-8", Params{Width: 8, Poly: 0x07, Init: 0xFF, RefIn: true, RefOut: false, XorOut: 0x00}, 0x0B},
	}
	for _, c := range cases {
		m, err := NewModel(c.name, c.params)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Checksum(data); got != c.check {
			t.Errorf("%s: check = %#X, want %#X", c.name, got, c.check)
		}
		if ok, residue := m.Verify(data, c.check); !ok {
			t.Errorf("%s: verify(data, %#X) failed, residue %#X, want %#X", c.name, c.check, residue, m.Residue())
		}
	}
}

// TestAllReflectionCombosRoundTrip encodes payloads of every shape under
// all four RefIn/RefOut combinations and several widths, and requires
// data+check to verify — with the residue equal to the model constant
// every time, which is the invariant Verify relies on.
func TestAllReflectionCombosRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	payloads := [][]byte{nil, {}, {0x00}, {0xFF}, []byte("123456789"), {0xDE, 0xAD, 0xBE, 0xEF}}
	for i := 0; i < 4; i++ {
		b := make([]byte, 1+rng.Intn(300))
		rng.Read(b)
		payloads = append(payloads, b)
	}
	bases := []Params{
		{Width: 8, Poly: 0x07, Init: 0xFF, XorOut: 0x00},
		{Width: 16, Poly: 0x1021, Init: 0x1234, XorOut: 0x5678},
		{Width: 32, Poly: 0x04C11DB7, Init: 0xFFFFFFFF, XorOut: 0xFFFFFFFF},
		{Width: 64, Poly: 0x42F0E1EBA9EA3693, Init: 0x0123456789ABCDEF, XorOut: 0xFEDCBA9876543210},
	}
	for _, base := range bases {
		for _, refin := range []bool{false, true} {
			for _, refout := range []bool{false, true} {
				p := base
				p.RefIn, p.RefOut = refin, refout
				m, err := NewModel("combo", p)
				if err != nil {
					t.Fatal(err)
				}
				for _, data := range payloads {
					check := m.Checksum(data)
					ok, residue := m.Verify(data, check)
					if !ok {
						t.Errorf("params %+v: verify of %d-byte payload failed, residue %#X, want %#X",
							p, len(data), residue, m.Residue())
					}
				}
			}
		}
	}
}

// TestMixedReflectionBitFlipFails flips every single bit of the data and
// of the check value in turn under mixed-reflection parameters;
// verification must fail every time.
func TestMixedReflectionBitFlipFails(t *testing.T) {
	data := []byte("123456789")
	paramSets := []Params{
		{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: true, RefOut: false, XorOut: 0x5678},
		{Width: 16, Poly: 0x1021, Init: 0x1234, RefIn: false, RefOut: true, XorOut: 0x5678},
		{Width: 8, Poly: 0x07, Init: 0xFF, RefIn: true, RefOut: false, XorOut: 0x00},
		{Width: 8, Poly: 0x07, Init: 0xFF, RefIn: false, RefOut: true, XorOut: 0x00},
	}
	for _, p := range paramSets {
		m, err := NewModel("mixed", p)
		if err != nil {
			t.Fatal(err)
		}
		check := m.Checksum(data)
		for i := range data {
			for bit := 0; bit < 8; bit++ {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[i] ^= 1 << uint(bit)
				if ok, _ := m.Verify(tampered, check); ok {
					t.Errorf("params %+v: flipped data bit %d of byte %d still verified", p, bit, i)
				}
			}
		}
		for bit := 0; bit < p.Width; bit++ {
			if ok, _ := m.Verify(data, check^(1<<uint(bit))); ok {
				t.Errorf("params %+v: flipped check bit %d still verified", p, bit)
			}
		}
	}
}

// TestCustomParamsRoundTripRandomised hammers Verify with random valid
// parameter sets — every width, every reflection combination, non-zero
// init and xorout — and requires encode-then-verify to hold for random
// payloads of every length, including empty.
func TestCustomParamsRoundTripRandomised(t *testing.T) {
	rng := rand.New(rand.NewSource(31337))
	for i := 0; i < 64; i++ {
		width := 8 * (1 + rng.Intn(8)) // 8,16,...,64
		mask := maskForWidth(width)
		p := Params{
			Width:  width,
			Poly:   rng.Uint64()&mask | 1, // odd polynomial: every single-bit error is detectable
			Init:   rng.Uint64() & mask,
			RefIn:  rng.Intn(2) == 0,
			RefOut: rng.Intn(2) == 0,
			XorOut: rng.Uint64() & mask,
		}
		m, err := NewModel("random", p)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 8; j++ {
			data := make([]byte, rng.Intn(200))
			rng.Read(data)
			check := m.Checksum(data)
			if ok, residue := m.Verify(data, check); !ok {
				t.Fatalf("params %+v: verify failed for %d-byte payload, residue %#X, want %#X",
					p, len(data), residue, m.Residue())
			}
			if ok, _ := m.Verify(data, check^(1<<uint(rng.Intn(width)))); ok {
				t.Fatalf("params %+v: tampered check verified for %d-byte payload", p, len(data))
			}
		}
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
