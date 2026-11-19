package attestation

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Canonicalize returns the RFC 8785 (JCS) canonical form of a single JSON
// value. It fails closed on input JCS cannot represent faithfully: duplicate
// object member names, and integer literals outside the range an IEEE 754
// double represents exactly (|n| > 2^53).
func Canonicalize(data []byte) ([]byte, error) {
	if err := checkCanonicalizable(data); err != nil {
		return nil, err
	}

	value := jsontext.Value(bytes.Clone(data))
	if err := value.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonCanonicalizableJSON, err)
	}
	return []byte(value), nil
}

// IsCanonical reports whether data is already byte-identical to its RFC 8785
// canonical form.
func IsCanonical(data []byte) bool {
	canonical, err := Canonicalize(data)
	if err != nil {
		return false
	}
	return bytes.Equal(canonical, data)
}

// checkCanonicalizable walks every token. The jsontext decoder rejects
// duplicate member names by default; number literals are checked here.
func checkCanonicalizable(data []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		if dec.PeekKind() == '0' {
			number, err := dec.ReadValue()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrNonCanonicalizableJSON, err)
			}
			if err := checkNumberLiteral(string(number)); err != nil {
				return err
			}
			continue
		}

		if _, err := dec.ReadToken(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%w: %v", ErrNonCanonicalizableJSON, err)
		}
	}
}

func checkNumberLiteral(literal string) error {
	if strings.ContainsAny(literal, ".eE") {
		return nil
	}
	digits := strings.TrimPrefix(literal, "-")
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || n > maxSafeInteger {
		return fmt.Errorf("%w: integer %s exceeds 2^53", ErrNonCanonicalizableJSON, literal)
	}
	return nil
}
