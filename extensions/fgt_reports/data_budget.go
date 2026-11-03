package fgt_reports

import (
	"context"
	"errors"
	"reflect"
	"time"
)

var errReportDataLimit = errors.New("report data exceeds the bounded serialization limit")

// json.Marshal builds its complete output before returning, so checking the
// resulting []byte is too late for amplified shared strings or large arrays.
// This allocation-free walk conservatively accounts for JSON escaping, keys,
// scalar values and structure before the encoder can allocate its buffer.
func checkReportDataBudget(ctx context.Context, data reportData) error {
	budget := maxReportSetBytes
	visits := 0
	timeType := reflect.TypeFor[time.Time]()
	var walk func(reflect.Value) error
	walk = func(value reflect.Value) error {
		visits++
		if visits%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if budget < 128 {
			return errReportDataLimit
		}
		budget -= 128
		if !value.IsValid() {
			return nil
		}
		if value.Type() == timeType {
			return nil // RFC3339 output is covered by the scalar allowance.
		}
		switch value.Kind() {
		case reflect.String:
			if value.Len() > budget/6 {
				return errReportDataLimit
			}
			budget -= value.Len() * 6
		case reflect.Pointer, reflect.Interface:
			if !value.IsNil() {
				return walk(value.Elem())
			}
		case reflect.Struct:
			for i := 0; i < value.NumField(); i++ {
				field := value.Type().Field(i)
				if !field.IsExported() || field.Tag.Get("json") == "-" {
					continue
				}
				if err := walk(value.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Slice, reflect.Array:
			if value.Len() > budget/128 {
				return errReportDataLimit
			}
			for i := 0; i < value.Len(); i++ {
				if err := walk(value.Index(i)); err != nil {
					return err
				}
			}
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			return nil
		default:
			return errReportDataLimit
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return walk(reflect.ValueOf(data))
}
