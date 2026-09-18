package crc

import "sort"

// presets are the named parameter sets registered at startup. The check
// values are the catalogue values for the ASCII string "123456789" and
// are asserted by the test suite.
var presets = []struct {
	name   string
	params Params
	check  uint64
}{
	{"CRC-8", Params{Width: 8, Poly: 0x07, Init: 0x00, RefIn: false, RefOut: false, XorOut: 0x00}, 0xF4},
	{"CRC-8/MAXIM", Params{Width: 8, Poly: 0x31, Init: 0x00, RefIn: true, RefOut: true, XorOut: 0x00}, 0xA1},
	{"CRC-16/CCITT-FALSE", Params{Width: 16, Poly: 0x1021, Init: 0xFFFF, RefIn: false, RefOut: false, XorOut: 0x0000}, 0x29B1},
	{"CRC-16/ARC", Params{Width: 16, Poly: 0x8005, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0x0000}, 0xBB3D},
	{"CRC-16/MODBUS", Params{Width: 16, Poly: 0x8005, Init: 0xFFFF, RefIn: true, RefOut: true, XorOut: 0x0000}, 0x4B37},
}

// UnknownModelError is returned when a caller names a model that is not
// registered. It is a distinct type so the API layer can map it to a
// structured "unknown_model" error instead of guessing.
type UnknownModelError struct {
	Name string
}

func (e *UnknownModelError) Error() string {
	return "unknown model: " + e.Name
}

var registry = map[string]*Model{}

func init() {
	for _, p := range presets {
		m, err := NewModel(p.name, p.params)
		if err != nil {
			panic("crc: invalid preset " + p.name + ": " + err.Error())
		}
		if m.Check() != p.check {
			panic("crc: preset " + p.name + " check mismatch")
		}
		registry[p.name] = m
	}
}

// Lookup returns the registered model with the given name, or an
// *UnknownModelError. It never guesses or falls back to a default.
func Lookup(name string) (*Model, error) {
	if m, ok := registry[name]; ok {
		return m, nil
	}
	return nil, &UnknownModelError{Name: name}
}

// Models returns all registered models sorted by name.
func Models() []*Model {
	out := make([]*Model, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
