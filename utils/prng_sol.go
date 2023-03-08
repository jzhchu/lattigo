package utils

import (
	"github.com/ethereum/go-ethereum/crypto"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
)

const sha3Size = 32

type SolPRNG struct {
	seed []byte
	salt uint32
	hash func(data ...[]byte) []byte
}

func NewSolPRNG(seed []byte, salt uint32) *SolPRNG {
	prng := new(SolPRNG)
	prng.seed = seed
	prng.salt = salt
	prng.hash = crypto.Keccak256
	return prng
}

func (prng *SolPRNG) Read(sum []byte) (n int, err error) {
	n = len(sum)
	iv := prng.hash(prng.seed, ConvertU32toBytes32(prng.salt))
	i := 0
	for ; i <= n-sha3Size; i = i + sha3Size {
		hash := prng.hash(iv)
		iv = hash
		copy(sum[i:i+sha3Size], hash)

	}
	remain := n - i
	if remain > 0 {
		hash := prng.hash(iv)
		iv = hash
		copy(sum[i:i+remain], hash[:remain])
	}

	copy(prng.seed, iv)

	return
}

func ConvertU32toBytes32(num uint32) []byte {
	byte4 := solsha3.Uint32(num)
	prefixBytes := make([]byte, 28)
	return append(prefixBytes, byte4...)
}

func ConvertBytesToBytes32(byteArray []byte) [32]byte {
	offset := 32 - len(byteArray)
	if offset <= 0 {
		return bytesTobytes32(byteArray[:32])
	}
	prefixArray := make([]byte, offset)
	resBytes := append(byteArray, prefixArray...)
	return bytesTobytes32(resBytes)
}

func bytesTobytes32(byte32Array []byte) [32]byte {
	res := [32]byte{}
	for i := 0; i < 32; i++ {
		res[i] = byte32Array[i]
	}
	return res
}
