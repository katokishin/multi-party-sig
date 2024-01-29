package jsontools

import (
	"bytes"
)

func JoinJSON(j1 []byte, j2 []byte) ([]byte, error) {
	// Allocate new slice (-1 since we remove '}' '{' and add ',')
	data := make([]byte, len(j1)+len(j2)-1)

	j1ClosingBraceIndex := bytes.LastIndexByte(j1, '}')
	data = append(j1[:j1ClosingBraceIndex], ',')
	data = append(data, j2[1:]...)

	return data, nil
}
