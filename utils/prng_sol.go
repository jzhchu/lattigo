package utils

import (
	solsha3 "github.com/miguelmota/go-solidity-sha3"
)

const sha3Size = 32

type SolPRNG struct {
	seed [32]byte
	salt uint32
	hash func(data ...interface{}) []byte
}

func NewSolPRNG(seed [32]byte, salt uint32) *SolPRNG {
	prng := new(SolPRNG)
	prng.seed = seed
	prng.salt = salt
	prng.hash = solsha3.SoliditySHA3
	return prng
}

func (prng *SolPRNG) Read(sum []byte) (n int, err error) {
	n = len(sum)
	types := []string{"bytes32", "uint32"}
	values := []interface{}{prng.seed, prng.salt}
	iv := prng.hash(types, values)
	i := 0
	for ; i < n-sha3Size; i = i + sha3Size {
		hash := prng.hash([]string{"bytes32"}, []interface{}{iv[:32]})
		iv = hash
		copy(sum[i:i+sha3Size], hash)

	}
	remain := n - i
	if remain > 0 {
		hash := prng.hash([]string{"bytes32"}, []interface{}{iv[:32]})
		iv = hash
		copy(sum[i:i+remain], hash[:remain])
	}
	
	copy(prng.seed[:32], iv[:32])

	return
}
