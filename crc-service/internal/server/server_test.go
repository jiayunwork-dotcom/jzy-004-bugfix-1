package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func do(t *testing.T, s http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: response is not JSON: %v\n%s", method, path, err, rec.Body.String())
	}
	return rec.Code, out
}

func errType(t *testing.T, out map[string]any) string {
	t.Helper()
	e, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error object: %v", out)
	}
	typ, _ := e["type"].(string)
	return typ
}

func TestChecksumEndpoint(t *testing.T) {
	s := New()
	// "123456789" in hex; CRC-16/CCITT-FALSE catalogue value is 0x29B1.
	code, out := do(t, s, "POST", "/v1/checksum",
		`{"model":"CRC-16/CCITT-FALSE","data":"313233343536373839"}`)
	if code != 200 {
		t.Fatalf("status %d: %v", code, out)
	}
	if out["check"] != "29B1" {
		t.Errorf("check = %v, want 29B1", out["check"])
	}
	if out["width"] != 16.0 {
		t.Errorf("width = %v, want 16", out["width"])
	}
}

func TestChecksumExplicitParams(t *testing.T) {
	s := New()
	// The same algorithm as CRC-16/CCITT-FALSE, given explicitly.
	code, out := do(t, s, "POST", "/v1/checksum",
		`{"params":{"width":16,"poly":"0x1021","init":"0xFFFF","refin":false,"refout":false,"xorout":"0x0000"},"data":"313233343536373839"}`)
	if code != 200 {
		t.Fatalf("status %d: %v", code, out)
	}
	if out["check"] != "29B1" {
		t.Errorf("explicit params check = %v, want 29B1", out["check"])
	}
	// Numeric JSON values are accepted too.
	code, out = do(t, s, "POST", "/v1/checksum",
		`{"params":{"width":8,"poly":7,"init":0,"refin":false,"refout":false,"xorout":0},"data":"313233343536373839"}`)
	if code != 200 || out["check"] != "F4" {
		t.Errorf("numeric params: status %d, check %v, want F4", code, out["check"])
	}
}

func TestChecksumEmptyPayload(t *testing.T) {
	s := New()
	code, out := do(t, s, "POST", "/v1/checksum", `{"model":"CRC-16/CCITT-FALSE","data":""}`)
	if code != 200 || out["check"] != "FFFF" {
		t.Errorf("empty payload: status %d, check %v, want FFFF", code, out["check"])
	}
}

func TestChecksumErrors(t *testing.T) {
	s := New()
	cases := []struct {
		name    string
		body    string
		wantTyp string
	}{
		{"unknown model", `{"model":"CRC-32","data":"00"}`, ErrUnknownModel},
		{"model name is case sensitive", `{"model":"crc-8","data":"00"}`, ErrUnknownModel},
		{"bad hex payload", `{"model":"CRC-8","data":"zz"}`, ErrInvalidFormat},
		{"odd length hex", `{"model":"CRC-8","data":"0"}`, ErrInvalidFormat},
		{"width too small", `{"params":{"width":4,"poly":"0x07"},"data":"00"}`, ErrInvalidParams},
		{"width not multiple of 8", `{"params":{"width":12,"poly":"0x07"},"data":"00"}`, ErrInvalidParams},
		{"zero polynomial", `{"params":{"width":8,"poly":"0x00"},"data":"00"}`, ErrInvalidParams},
		{"poly exceeds width", `{"params":{"width":8,"poly":"0x1FF"},"data":"00"}`, ErrInvalidParams},
		{"init exceeds width", `{"params":{"width":8,"poly":"0x07","init":"0x1FF"},"data":"00"}`, ErrInvalidParams},
		{"model and params together", `{"model":"CRC-8","params":{"width":8,"poly":"0x07"},"data":"00"}`, ErrInvalidParams},
		{"neither model nor params", `{"data":"00"}`, ErrInvalidParams},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := do(t, s, "POST", "/v1/checksum", c.body)
			if code != http.StatusBadRequest {
				t.Errorf("status %d, want 400 (%v)", code, out)
			}
			if got := errType(t, out); got != c.wantTyp {
				t.Errorf("error type %q, want %q (%v)", got, c.wantTyp, out)
			}
		})
	}

	code, out := do(t, s, "POST", "/v1/checksum", `{not json`)
	if code != 400 || errType(t, out) != ErrBadRequest {
		t.Errorf("malformed JSON: status %d, out %v", code, out)
	}
}

func TestVerifyEndpoint(t *testing.T) {
	s := New()
	// Encode, then verify the result.
	_, enc := do(t, s, "POST", "/v1/checksum",
		`{"model":"CRC-16/ARC","data":"313233343536373839"}`)
	check := enc["check"].(string) // BB3D

	code, out := do(t, s, "POST", "/v1/verify",
		`{"model":"CRC-16/ARC","data":"313233343536373839","check":"`+check+`"}`)
	if code != 200 || out["valid"] != true {
		t.Fatalf("valid transmission rejected: status %d, out %v", code, out)
	}
	if out["residue"] != out["expected_residue"] {
		t.Errorf("residue %v != expected %v", out["residue"], out["expected_residue"])
	}

	// Flip one bit of the payload.
	code, out = do(t, s, "POST", "/v1/verify",
		`{"model":"CRC-16/ARC","data":"313233343536373838","check":"`+check+`"}`)
	if code != 200 || out["valid"] != false {
		t.Errorf("tampered payload accepted: status %d, out %v", code, out)
	}

	// Flip one bit of the check value.
	code, out = do(t, s, "POST", "/v1/verify",
		`{"model":"CRC-16/ARC","data":"313233343536373839","check":"BB3C"}`)
	if code != 200 || out["valid"] != false {
		t.Errorf("tampered check accepted: status %d, out %v", code, out)
	}
}

// TestVerifyMixedReflectionParams reproduces the reported failure at the
// API level: explicit parameter sets with RefIn != RefOut must encode to
// the pinned check values and then verify; flipping any bit of the data
// or of the check must be rejected. All four reflection combinations are
// exercised, including the empty payload.
func TestVerifyMixedReflectionParams(t *testing.T) {
	s := New()
	cases := []struct {
		name   string
		params string
		check  string // pinned encode result for "123456789"
	}{
		{"refin only", `"width":16,"poly":"0x1021","init":"0x1234","refin":true,"refout":false,"xorout":"0x5678"`, "1BD4"},
		{"refout only", `"width":16,"poly":"0x1021","init":"0x1234","refin":false,"refout":true,"xorout":"0x5678"`, "81CF"},
		{"neither", `"width":16,"poly":"0x1021","init":"0x1234","refin":false,"refout":false,"xorout":"0x5678"`, "BB93"},
		{"both", `"width":16,"poly":"0x1021","init":"0x1234","refin":true,"refout":true,"xorout":"0x5678"`, "63CA"},
		{"refin only 8-bit", `"width":8,"poly":"0x07","init":"0xFF","refin":true,"refout":false,"xorout":"0x00"`, "0B"},
		{"refout only 8-bit", `"width":8,"poly":"0x07","init":"0xFF","refin":false,"refout":true,"xorout":"0x00"`, "DF"},
	}
	const vec = "313233343536373839" // "123456789"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, enc := do(t, s, "POST", "/v1/checksum",
				`{"params":{`+c.params+`},"data":"`+vec+`"}`)
			if code != 200 {
				t.Fatalf("checksum: status %d: %v", code, enc)
			}
			if enc["check"] != c.check {
				t.Errorf("check = %v, want %s", enc["check"], c.check)
			}

			code, out := do(t, s, "POST", "/v1/verify",
				`{"params":{`+c.params+`},"data":"`+vec+`","check":"`+c.check+`"}`)
			if code != 200 || out["valid"] != true {
				t.Fatalf("encode-then-verify rejected: status %d, out %v", code, out)
			}
			if out["residue"] != out["expected_residue"] {
				t.Errorf("residue %v != expected %v", out["residue"], out["expected_residue"])
			}

			// Flip one bit of the payload and of the check value.
			code, out = do(t, s, "POST", "/v1/verify",
				`{"params":{`+c.params+`},"data":"313233343536373838","check":"`+c.check+`"}`)
			if code != 200 || out["valid"] != false {
				t.Errorf("tampered payload accepted: status %d, out %v", code, out)
			}
			code, out = do(t, s, "POST", "/v1/verify",
				`{"params":{`+c.params+`},"data":"`+vec+`","check":"`+flipLastHexBit(c.check)+`"}`)
			if code != 200 || out["valid"] != false {
				t.Errorf("tampered check accepted: status %d, out %v", code, out)
			}

			// The empty payload must round-trip too.
			_, enc = do(t, s, "POST", "/v1/checksum", `{"params":{`+c.params+`},"data":""}`)
			emptyCheck, _ := enc["check"].(string)
			code, out = do(t, s, "POST", "/v1/verify",
				`{"params":{`+c.params+`},"data":"","check":"`+emptyCheck+`"}`)
			if code != 200 || out["valid"] != true {
				t.Errorf("empty payload rejected: status %d, out %v", code, out)
			}
		})
	}
}

// flipLastHexBit returns the hex string with its lowest bit toggled.
func flipLastHexBit(h string) string {
	last := h[len(h)-1]
	var r byte
	if d, err := strconv.ParseUint(string(last), 16, 8); err == nil {
		r = "0123456789ABCDEF"[d^1]
	} else {
		r = last
	}
	return h[:len(h)-1] + string(r)
}

func TestVerifyErrors(t *testing.T) {
	s := New()
	cases := []struct {
		name    string
		body    string
		wantTyp string
	}{
		{"missing check", `{"model":"CRC-8","data":"00"}`, ErrInvalidFormat},
		{"bad check hex", `{"model":"CRC-8","data":"00","check":"xy"}`, ErrInvalidFormat},
		{"check exceeds width", `{"model":"CRC-8","data":"00","check":"1FF"}`, ErrInvalidParams},
		{"unknown model", `{"model":"CRC-7","data":"00","check":"00"}`, ErrUnknownModel},
		{"bad payload", `{"model":"CRC-8","data":"0g","check":"00"}`, ErrInvalidFormat},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := do(t, s, "POST", "/v1/verify", c.body)
			if code != 400 {
				t.Errorf("status %d, want 400 (%v)", code, out)
			}
			if got := errType(t, out); got != c.wantTyp {
				t.Errorf("error type %q, want %q (%v)", got, c.wantTyp, out)
			}
		})
	}
}

func TestModelsEndpoint(t *testing.T) {
	s := New()
	code, out := do(t, s, "GET", "/v1/models", "")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	models, ok := out["models"].([]any)
	if !ok || len(models) < 2 {
		t.Fatalf("expected at least 2 models, got %v", out["models"])
	}
	byName := map[string]map[string]any{}
	for _, m := range models {
		mm := m.(map[string]any)
		byName[mm["name"].(string)] = mm
	}
	c8, ok := byName["CRC-8"]
	if !ok {
		t.Fatal("CRC-8 not registered")
	}
	if c8["poly"] != "0x07" || c8["width"] != 8.0 {
		t.Errorf("CRC-8 params wrong: %v", c8)
	}
	tv := c8["test_vector"].(map[string]any)
	if tv["check"] != "F4" || tv["data_ascii"] != "123456789" {
		t.Errorf("CRC-8 test vector wrong: %v", tv)
	}
	c16, ok := byName["CRC-16/CCITT-FALSE"]
	if !ok {
		t.Fatal("CRC-16/CCITT-FALSE not registered")
	}
	if tv := c16["test_vector"].(map[string]any); tv["check"] != "29B1" {
		t.Errorf("CRC-16/CCITT-FALSE test vector check = %v, want 29B1", tv["check"])
	}
}

func TestHealthEndpoint(t *testing.T) {
	s := New()
	code, out := do(t, s, "GET", "/healthz", "")
	if code != 200 || out["status"] != "ok" {
		t.Fatalf("health: status %d, out %v", code, out)
	}
	if _, ok := out["requests_total"]; !ok {
		t.Error("health response lacks requests_total")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := New()
	code, _ := do(t, s, "GET", "/v1/checksum", "")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/checksum: status %d, want 405", code)
	}
}

// TestConcurrentRequests issues mixed requests from many goroutines and
// requires every answer to be correct, proving requests do not
// contaminate each other.
func TestConcurrentRequests(t *testing.T) {
	s := New()
	want := map[string]string{
		"CRC-8":              "F4",
		"CRC-8/MAXIM":        "A1",
		"CRC-16/CCITT-FALSE": "29B1",
		"CRC-16/ARC":         "BB3D",
		"CRC-16/MODBUS":      "4B37",
	}
	var wg sync.WaitGroup
	errs := make(chan string, 256)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			i := 0
			for model, check := range want {
				body := `{"model":"` + model + `","data":"313233343536373839"}`
				req := httptest.NewRequest("POST", "/v1/checksum", strings.NewReader(body))
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, req)
				var out map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
					errs <- err.Error()
					return
				}
				if out["check"] != check {
					errs <- model + ": got " + out["check"].(string) + ", want " + check
				}
				// Interleave a verify request with a different model.
				vbody := `{"model":"CRC-16/CCITT-FALSE","data":"313233343536373839","check":"29B1"}`
				vreq := httptest.NewRequest("POST", "/v1/verify", strings.NewReader(vbody))
				vrec := httptest.NewRecorder()
				s.ServeHTTP(vrec, vreq)
				var vout map[string]any
				if err := json.Unmarshal(vrec.Body.Bytes(), &vout); err != nil {
					errs <- err.Error()
					return
				}
				if vout["valid"] != true {
					errs <- "interleaved verify failed"
				}
				i++
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
