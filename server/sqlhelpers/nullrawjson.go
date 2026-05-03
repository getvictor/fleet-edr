package sqlhelpers

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// NullRawJSON is a json.RawMessage that correctly scans NULL from
// MySQL JSON columns. json.RawMessage alone fails because the MySQL
// driver returns nil for NULL JSON, and database/sql doesn't know
// how to assign nil to the named type json.RawMessage.
//
// The Marshal/Unmarshal pair lets the same type appear in api wire
// structs without an extra encode step: a nil NullRawJSON serialises
// to JSON null; a non-nil one serialises to its raw payload.
type NullRawJSON json.RawMessage

// Scan implements sql.Scanner. NULL becomes a nil slice; []byte values
// are copied so the caller doesn't share storage with the driver.
func (n *NullRawJSON) Scan(value any) error {
	if value == nil {
		*n = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("NullRawJSON.Scan: unsupported type %T", value)
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	*n = NullRawJSON(cp)
	return nil
}

// Value implements driver.Valuer. Empty + the literal "null" both map
// to SQL NULL so the column round-trips cleanly.
func (n NullRawJSON) Value() (driver.Value, error) {
	if len(n) == 0 || string(n) == "null" {
		return nil, nil
	}
	return []byte(n), nil
}

// MarshalJSON emits "null" for a nil slice; otherwise the raw payload.
func (n NullRawJSON) MarshalJSON() ([]byte, error) {
	if n == nil {
		return []byte("null"), nil
	}
	return json.RawMessage(n).MarshalJSON()
}

// UnmarshalJSON treats the literal "null" as a nil slice; everything
// else is captured byte-for-byte.
func (n *NullRawJSON) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = nil
		return nil
	}
	*n = NullRawJSON(data)
	return nil
}
