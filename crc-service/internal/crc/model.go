package crc

// TestVector is the ASCII string used by the CRC catalogue as the
// standard check input.
const TestVector = "123456789"

// Model is a fully resolved CRC parameter set with its precomputed
// lookup table and derived constants. A Model is immutable after
// construction and safe for concurrent use.
type Model struct {
	Name   string
	Params Params

	table   [256]uint64
	check   uint64 // check value of TestVector under this model
	residue uint64 // expected CRC of (message || check bytes)
}

// NewModel validates the parameters and builds a ready-to-use model.
func NewModel(name string, p Params) (*Model, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m := &Model{Name: name, Params: p}
	m.table = makeTable(p)
	m.check = m.Checksum([]byte(TestVector))
	// The CRC of (message || check bytes) is a constant independent of
	// the message, so compute it once for the empty message. This is the
	// value Verify compares against.
	c := m.Checksum(nil)
	m.residue = m.Checksum(CheckBytes(p, c))
	return m, nil
}

// Checksum returns the check value of data under this model.
func (m *Model) Checksum(data []byte) uint64 {
	return checksumTable(m.Params, &m.table, data)
}

// Check returns the model's check value for the standard TestVector.
func (m *Model) Check() uint64 { return m.check }

// Residue returns the constant the CRC of (message || check bytes) must
// equal for a valid, untampered transmission.
func (m *Model) Residue() uint64 { return m.residue }

// Verify appends the check bytes to data, runs the division again, and
// reports whether the resulting residue equals the model's constant. The
// actual residue is returned for diagnostics.
func (m *Model) Verify(data []byte, check uint64) (bool, uint64) {
	msg := make([]byte, 0, len(data)+m.Params.Width/8)
	msg = append(msg, data...)
	msg = append(msg, CheckBytes(m.Params, check)...)
	residue := m.Checksum(msg)
	return residue == m.residue, residue
}
