package fgtconftail

import "strings"

type configAttributeDiff struct {
	Name   string
	Before string
	After  string
}

func parseConfigAttributeDiff(value string) (configAttributeDiff, bool) {
	value = strings.TrimSpace(value)
	open := strings.IndexByte(value, '[')
	close := strings.LastIndexByte(value, ']')
	if open <= 0 || close != len(value)-1 || close <= open+1 {
		return configAttributeDiff{}, false
	}
	values := strings.SplitN(value[open+1:close], "->", 2)
	if len(values) != 2 {
		return configAttributeDiff{}, false
	}
	name := strings.TrimSpace(value[:open])
	if name == "" {
		return configAttributeDiff{}, false
	}
	return configAttributeDiff{
		Name:   name,
		Before: strings.TrimSpace(values[0]),
		After:  strings.TrimSpace(values[1]),
	}, true
}
