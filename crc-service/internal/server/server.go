// Package server exposes the CRC engine as a small JSON/HTTP service.
//
// Endpoints:
//
//	POST /v1/checksum  compute the check value of a hex-encoded payload
//	POST /v1/verify    verify a payload plus its check value
//	GET  /v1/models    list all registered parameter sets
//	GET  /healthz      liveness and basic counters for monitoring
//
// Payloads are hex-encoded (lowercase or uppercase, optional 0x prefix,
// empty string allowed). All failures are returned as structured errors:
//
//	{"error": {"type": "...", "message": "..."}}
//
// with type one of bad_request, unknown_model, invalid_format,
// invalid_params.
package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/example/crc-service/internal/crc"
)

// Error types returned in structured error responses.
const (
	ErrBadRequest    = "bad_request"
	ErrUnknownModel  = "unknown_model"
	ErrInvalidFormat = "invalid_format"
	ErrInvalidParams = "invalid_params"
)

type apiError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Server is the HTTP front end. It keeps no per-request CRC state; the
// only mutable fields are monitoring counters.
type Server struct {
	mux     *http.ServeMux
	started time.Time
	total   atomic.Int64
	failed  atomic.Int64
}

// New builds a Server with all routes registered.
func New() *Server {
	s := &Server{started: time.Now()}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/checksum", s.handleChecksum)
	mux.HandleFunc("/v1/verify", s.handleVerify)
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/healthz", s.handleHealth)
	s.mux = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.total.Add(1)
	s.mux.ServeHTTP(w, r)
}

// hexUint accepts either a JSON number or a hex string ("0x1F" or "1F").
type hexUint uint64

func (h *hexUint) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return errors.New("empty value")
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		str = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(str)), "0x")
		if str == "" {
			return errors.New("empty hex string")
		}
		v, err := strconv.ParseUint(str, 16, 64)
		if err != nil {
			return fmt.Errorf("invalid hex value %q", str)
		}
		*h = hexUint(v)
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid numeric value %q", s)
	}
	*h = hexUint(v)
	return nil
}

type paramsJSON struct {
	Width  int     `json:"width"`
	Poly   hexUint `json:"poly"`
	Init   hexUint `json:"init"`
	RefIn  bool    `json:"refin"`
	RefOut bool    `json:"refout"`
	XorOut hexUint `json:"xorout"`
}

func (p *paramsJSON) toParams() crc.Params {
	return crc.Params{
		Width:  p.Width,
		Poly:   uint64(p.Poly),
		Init:   uint64(p.Init),
		RefIn:  p.RefIn,
		RefOut: p.RefOut,
		XorOut: uint64(p.XorOut),
	}
}

type checksumRequest struct {
	Model  string      `json:"model"`
	Params *paramsJSON `json:"params"`
	Data   string      `json:"data"`
}

type verifyRequest struct {
	Model  string      `json:"model"`
	Params *paramsJSON `json:"params"`
	Data   string      `json:"data"`
	Check  string      `json:"check"`
}

// resolveModel turns either a model name or an explicit parameter set
// into a ready-to-use model. Exactly one of the two must be given.
func resolveModel(name string, pj *paramsJSON) (*crc.Model, *apiError) {
	switch {
	case name != "" && pj != nil:
		return nil, &apiError{ErrInvalidParams, "specify exactly one of \"model\" or \"params\""}
	case name == "" && pj == nil:
		return nil, &apiError{ErrInvalidParams, "one of \"model\" or \"params\" is required"}
	case name != "":
		m, err := crc.Lookup(name)
		if err != nil {
			return nil, &apiError{ErrUnknownModel, err.Error()}
		}
		return m, nil
	default:
		m, err := crc.NewModel("custom", pj.toParams())
		if err != nil {
			return nil, &apiError{ErrInvalidParams, err.Error()}
		}
		return m, nil
	}
}

// decodePayload decodes the fixed payload encoding: hexadecimal with an
// optional 0x prefix. The empty string is a valid, empty payload.
func decodePayload(s string) ([]byte, *apiError) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if s == "" {
		return nil, nil
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, &apiError{ErrInvalidFormat, "payload is not valid hexadecimal: " + err.Error()}
	}
	return data, nil
}

// parseCheck parses a hex check value and ensures it fits the width.
func parseCheck(s string, width int) (uint64, *apiError) {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if t == "" {
		return 0, &apiError{ErrInvalidFormat, "\"check\" is required and must be hexadecimal"}
	}
	v, err := strconv.ParseUint(t, 16, 64)
	if err != nil {
		return 0, &apiError{ErrInvalidFormat, "\"check\" is not valid hexadecimal: " + err.Error()}
	}
	if width < 64 && v>>(uint(width)) != 0 {
		return 0, &apiError{ErrInvalidParams, fmt.Sprintf("\"check\" exceeds %d-bit width", width)}
	}
	return v, nil
}

func hexStr(width int, v uint64) string {
	return fmt.Sprintf("%0*X", width/4, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, status int, e *apiError) {
	s.failed.Add(1)
	writeJSON(w, status, map[string]any{"error": e})
}

func decodeJSON(r *http.Request, dst any) *apiError {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return &apiError{ErrBadRequest, "malformed JSON body: " + err.Error()}
	}
	return nil
}

func (s *Server) handleChecksum(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErr(w, http.StatusMethodNotAllowed, &apiError{ErrBadRequest, "use POST"})
		return
	}
	var req checksumRequest
	if e := decodeJSON(r, &req); e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	m, e := resolveModel(req.Model, req.Params)
	if e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	data, e := decodePayload(req.Data)
	if e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	check := m.Checksum(data)
	writeJSON(w, http.StatusOK, map[string]any{
		"model":      m.Name,
		"width":      m.Params.Width,
		"data_bytes": len(data),
		"check":      hexStr(m.Params.Width, check),
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErr(w, http.StatusMethodNotAllowed, &apiError{ErrBadRequest, "use POST"})
		return
	}
	var req verifyRequest
	if e := decodeJSON(r, &req); e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	m, e := resolveModel(req.Model, req.Params)
	if e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	data, e := decodePayload(req.Data)
	if e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	check, e := parseCheck(req.Check, m.Params.Width)
	if e != nil {
		s.writeErr(w, http.StatusBadRequest, e)
		return
	}
	valid, residue := m.Verify(data, check)
	writeJSON(w, http.StatusOK, map[string]any{
		"model":            m.Name,
		"width":            m.Params.Width,
		"valid":            valid,
		"residue":          hexStr(m.Params.Width, residue),
		"expected_residue": hexStr(m.Params.Width, m.Residue()),
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErr(w, http.StatusMethodNotAllowed, &apiError{ErrBadRequest, "use GET"})
		return
	}
	models := crc.Models()
	out := make([]map[string]any, 0, len(models))
	for _, m := range models {
		p := m.Params
		out = append(out, map[string]any{
			"name":   m.Name,
			"width":  p.Width,
			"poly":   "0x" + hexStr(p.Width, p.Poly),
			"init":   "0x" + hexStr(p.Width, p.Init),
			"refin":  p.RefIn,
			"refout": p.RefOut,
			"xorout": "0x" + hexStr(p.Width, p.XorOut),
			"test_vector": map[string]string{
				"data_ascii": crc.TestVector,
				"data_hex":   hex.EncodeToString([]byte(crc.TestVector)),
				"check":      hexStr(p.Width, m.Check()),
			},
			"residue": "0x" + hexStr(p.Width, m.Residue()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": out})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErr(w, http.StatusMethodNotAllowed, &apiError{ErrBadRequest, "use GET"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"uptime_seconds":  int64(time.Since(s.started).Seconds()),
		"requests_total":  s.total.Load(),
		"requests_failed": s.failed.Load(),
	})
}
