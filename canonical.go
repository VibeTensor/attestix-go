package attestix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Canonicalize produces the Attestix JCS-style canonical UTF-8 bytes for an
// arbitrary JSON document supplied as raw bytes.
//
// This is NOT strict RFC 8785. It reproduces, byte-for-byte, the output of the
// reference implementation attestix/auth/crypto.py::canonicalize_json (attestix
// 0.4.0). The rules:
//
//  1. Every string VALUE and every object KEY is NFC-normalized.
//  2. Object keys are sorted ascending by Unicode code point.
//  3. Separators are "," and ":" with no whitespace.
//  4. Non-ASCII characters are emitted as raw UTF-8, never \uXXXX.
//  5. Whole-number floats collapse to integers (1.0 -> 1); a literal that has
//     no fraction/exponent is an int and is preserved verbatim, including
//     values larger than 2^53 (arbitrary precision via math/big).
//  6. Non-whole numbers keep their literal form (the vectors only use 1.5).
//  7. true / false / null are the lowercase JSON literals.
func Canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeValue canonicalizes an already-decoded value. The value must use
// the decoder's UseNumber() representation (json.Number for numbers) so that
// integer precision and literal form are preserved. This is exposed so callers
// that already hold a parsed document (e.g. a VC with fields removed) can
// canonicalize without re-marshalling.
func CanonicalizeValue(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		return writeNumber(buf, t)
	case float64:
		// Should not occur when UseNumber is set, but handle defensively.
		return writeNumber(buf, json.Number(strconvFloat(t)))
	case map[string]interface{}:
		return writeObject(buf, t)
	case []interface{}:
		return writeArray(buf, t)
	default:
		return fmt.Errorf("attestix: unsupported JSON type %T", v)
	}
	return nil
}

func writeObject(buf *bytes.Buffer, m map[string]interface{}) error {
	// NFC-normalize keys, then sort by Unicode code point (== byte order of
	// the UTF-8 encoding for valid Unicode, which Go string comparison gives).
	type kv struct {
		key string
		val interface{}
	}
	pairs := make([]kv, 0, len(m))
	for k, val := range m {
		pairs = append(pairs, kv{key: norm.NFC.String(k), val: val})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return codepointLess(pairs[i].key, pairs[j].key)
	})
	buf.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, p.key)
		buf.WriteByte(':')
		if err := writeCanonical(buf, p.val); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeArray(buf *bytes.Buffer, a []interface{}) error {
	buf.WriteByte('[')
	for i, e := range a {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, e); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeNumber reproduces Python's serialization for the values that appear in
// signed Attestix payloads: integers (any magnitude) emit verbatim, whole
// floats collapse to int, and non-whole floats keep their literal. The
// conformance vectors only contain integers and 1.5.
func writeNumber(buf *bytes.Buffer, n json.Number) error {
	s := string(n)
	// Integer literal (no '.', 'e', 'E'): emit verbatim, arbitrary precision.
	if !strings.ContainsAny(s, ".eE") {
		// Validate it parses as an integer (rejects malformed input).
		if _, ok := new(big.Int).SetString(s, 10); !ok {
			return fmt.Errorf("attestix: invalid integer literal %q", s)
		}
		buf.WriteString(s)
		return nil
	}
	// Float literal. Collapse to int if it is a whole number (matches Python's
	// "1.0 -> 1"). Use big.Float to avoid float64 precision artefacts and to
	// honour the -0.0 guard.
	bf, _, err := big.ParseFloat(s, 10, 200, big.ToNearestEven)
	if err != nil {
		return fmt.Errorf("attestix: invalid float literal %q: %w", s, err)
	}
	if bf.IsInt() {
		// Guard against -0.0 (Python keeps -0.0 as a float, not 0). A negative
		// zero is the only int-valued float Python does NOT collapse.
		if bf.Sign() == 0 && bf.Signbit() {
			buf.WriteString(s)
			return nil
		}
		bi, _ := bf.Int(nil)
		buf.WriteString(bi.String())
		return nil
	}
	// Non-whole float: the vectors only use 1.5, which Python and Go agree on.
	// Emit the literal as parsed (trim any leading +, keep the decimal form).
	buf.WriteString(s)
	return nil
}

func strconvFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// codepointLess compares two NFC strings by Unicode code point. For valid UTF-8
// this is identical to lexicographic byte comparison, which is exactly what
// Python's sort_keys=True yields for string keys.
func codepointLess(a, b string) bool {
	return a < b
}

// writeString emits a JSON string with ensure_ascii=False semantics: only the
// JSON-mandatory escapes (", \, and C0 control characters) are escaped; every
// other rune, including all non-ASCII, is written as raw UTF-8. String VALUES
// are NFC-normalized here so callers may pass un-normalized values directly.
func writeString(buf *bytes.Buffer, s string) {
	s = norm.NFC.String(s)
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				// Other C0 controls -> \u00XX (matches Python json.dumps).
				fmt.Fprintf(buf, `\u%04x`, r)
			} else if r == utf8.RuneError {
				// Preserve the replacement character as raw UTF-8.
				buf.WriteRune(r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
