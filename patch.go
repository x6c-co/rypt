package rypt

import (
	"encoding/json"
	"reflect"
)

// Patch is one field of an update request, which can leave the field as it
// is, replace its value, or clear it. The zero Patch leaves the field as it
// is; [Set] makes one that replaces it, and [Clear] one that clears it,
// which the API receives as JSON null.
//
// A Patch of a slice type set to a nil slice is sent as an empty list, not
// as null, so that a nil slice can never clear a restriction by accident.
type Patch[T any] struct {
	value T
	op    patchOp
}

type patchOp uint8

const (
	patchKeep patchOp = iota
	patchSet
	patchClear
)

// Set returns a Patch that replaces a field's value with v.
func Set[T any](v T) Patch[T] {
	return Patch[T]{value: v, op: patchSet}
}

// Clear returns a Patch that clears a field, sending JSON null.
func Clear[T any]() Patch[T] {
	return Patch[T]{op: patchClear}
}

// IsZero reports whether p leaves its field as it is. encoding/json uses it
// to leave the field out of a request.
func (p Patch[T]) IsZero() bool { return p.op == patchKeep }

// Value returns the value p sets and true, or the zero value and false when
// p does not set one.
func (p Patch[T]) Value() (T, bool) { return p.value, p.op == patchSet }

// IsClear reports whether p clears its field.
func (p Patch[T]) IsClear() bool { return p.op == patchClear }

// MarshalJSON encodes the value p sets, or null when p clears its field or
// leaves it as it is. A field left as it is should be omitted with the
// omitzero option rather than encoded.
func (p Patch[T]) MarshalJSON() ([]byte, error) {
	if p.op != patchSet {
		return []byte("null"), nil
	}
	if v := reflect.ValueOf(p.value); v.Kind() == reflect.Slice && v.IsNil() {
		return []byte("[]"), nil
	}
	return json.Marshal(p.value)
}
