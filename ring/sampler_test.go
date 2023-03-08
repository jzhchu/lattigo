package ring

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jzhchu/lattigo/utils"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"testing"
)

func TestHash(t *testing.T) {
	bytes32 := "0xca1129d3a806fb4806f458f504ba1081e2d75cefbe715eff78bae7a27f11c79f"
	types := []string{"bytes32", "uint32"}
	values := []interface{}{bytes32, 2333}
	res := solsha3.SoliditySHA3(types, values)
	fmt.Println(hex.EncodeToString(res))

	typesBytes := []string{"bytes32"}
	valuesBytes := []interface{}{solsha3.Bytes32(bytes32)}
	resBytes := solsha3.SoliditySHA3(typesBytes, valuesBytes)
	hashEth := crypto.Keccak256(solsha3.Bytes32(bytes32))

	fmt.Println(hex.EncodeToString(resBytes))
	fmt.Println(hex.EncodeToString(hashEth))

	typesUint32 := []string{"uint32"}
	valuesUint32 := []interface{}{2333}
	resUint32 := solsha3.SoliditySHA3(typesUint32, valuesUint32)
	fmt.Println(hex.EncodeToString(resUint32))
}

func TestKeccak256(t *testing.T) {
	str := "maskcontract"
	numUint32 := uint32(0)

	byte1 := solsha3.Bytes32(str)
	//byte2 := solsha3.Uint32(numUint32)
	byte2 := utils.ConvertU32toBytes32(numUint32)
	bytes32 := utils.ConvertBytesToBytes32([]byte(str))
	seed := solsha3.Bytes32(bytes32)

	hash := crypto.Keccak256(seed, byte2)
	hash1 := crypto.Keccak256([]byte(str), byte2)
	fmt.Println(byte1)
	fmt.Println(byte2)
	fmt.Println(seed)
	fmt.Println([]byte(str))
	fmt.Println(hex.EncodeToString(hash))
	fmt.Println(hex.EncodeToString(hash1))
}

func TestTernarySolSampler(t *testing.T) {

	Q := []uint64{0x40002001, 0x7ffffec001, 0x8000016001}
	N := 1 << 12

	ringQ, _ := NewRing(N, Q)

	testSeed := []byte{'m', 'a', 's', 'k', 'c', 'o', 'n', 't', 'r', 'a', 'c', 't'}
	testSalt := uint32(0)
	//prng := utils.NewSolPRNG(testSeed, testSalt)
	ternarySolSampler := NewTernarySolSampler(ringQ, testSeed, true)
	ternarySolSampler.SetSalt(testSalt)
	pol := ternarySolSampler.ReadNew()

	fmt.Println(PrimitiveRoot(Q[0]))
	fmt.Println(PrimitiveRoot(Q[1]))
	fmt.Println(PrimitiveRoot(Q[2]))

	fmt.Println(testSeed)

	fmt.Println(pol.Coeffs[0])
	fmt.Println(pol.Coeffs[1])
	fmt.Println(pol.Coeffs[2])
}
