package utils

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// Contains returns true if the element is in the array
func Contains(arr []string, elem string) bool {
	for _, value := range arr {
		if value == elem {
			return true
		}
	}
	return false
}

// Contains returns true if the element is in the array
func MapContains(m map[string]struct{}, elem string) bool {
	for key := range m {
		if key == elem {
			return true
		}
	}
	return false
}

func MapKeys(m map[string]interface{}) []string {
	a := make([]string, 0)
	for k := range m {
		a = append(a, k)
	}
	return a
}

// Unique returns only unique values
// Complexity : 2*n
func Unique(arr []string) []string {
	m := make(map[string]struct{})
	for _, value := range arr {
		m[value] = struct{}{}
	}

	u := make([]string, 0)
	for value := range m {
		u = append(u, value)
	}

	return u
}

// Sha256Encode encode a byte array
func Sha256Encode(buffer []byte) (sha256String string, sha256Bytes []byte) {
	h := crypto.SHA256.New()
	h.Write(buffer)
	hashSlice := h.Sum(nil)
	return hex.EncodeToString(hashSlice), hashSlice
}

func Float(n uint) float64 {
	var s string = strconv.FormatUint(uint64(n), 10)
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func Uint(f float64) uint {
	var s string = fmt.Sprintf("%.0f", f)
	n, _ := strconv.ParseUint(s, 10, 64)
	return uint(n)
}
