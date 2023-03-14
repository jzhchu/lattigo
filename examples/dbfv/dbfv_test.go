package main

import (
	"fmt"
	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/dbfv"
	"github.com/jzhchu/lattigo/ring"
	"github.com/jzhchu/lattigo/rlwe"
	"github.com/jzhchu/lattigo/utils"
	"testing"
)

func TestNizkPCKS(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN11QP54)
	crs, _ := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o', 't', 'e', 's', 't'})
	N := 8

	encoder := bfv.NewEncoder(params)
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	skArray := make([]*rlwe.SecretKey, N)
	cpk := rlwe.NewPublicKey(params.Parameters)
	for i := range skArray {
		skArray[i] = bfv.NewKeyGenerator(params).GenSecretKey()
	}

	ckg := dbfv.NewCKGProtocol(params)
	ckgCombined := ckg.AllocateShare()
	crp := ckg.SampleCRP(crs)
	for i := range skArray {
		ckgShare := ckg.AllocateShare()
		ckg.GenShare(skArray[i], crp, ckgShare)
		ckg.AggregateShares(ckgShare, ckgCombined, ckgCombined)
	}
	ckg.GenPublicKey(ckgCombined, crp, cpk)

	xArray := make([]uint64, params.N())
	for i := range xArray {
		xArray[i] = 9527 + uint64(i)
	}
	xPlaintext := encoder.EncodeNew(xArray, params.MaxLevel())

	encryptor := bfv.NewEncryptor(params, cpk)
	xCipherText := encryptor.EncryptNew(xPlaintext)

	uArray := make([]*ring.Poly, N)
	e0Array := make([]*ring.Poly, N)
	e1Array := make([]*ring.Poly, N)

	nizkPCKS := dbfv.NewNizkPCKSProtocol(params, 3.19)
	nizkPCKSCombined := nizkPCKS.AllocateShare(params.MaxLevel())
	encOut := bfv.NewCiphertext(params, 1, params.MaxLevel())
	for i := range skArray {
		nizkPCKSShare := nizkPCKS.AllocateShare(params.MaxLevel())
		nizkPCKS.GenShare(skArray[i], tpk, xCipherText, nizkPCKSShare)
		nizkPCKS.AggregateShares(nizkPCKSShare, nizkPCKSCombined, nizkPCKSCombined)
		uBytes, e0Bytes, e1Bytes := nizkPCKS.MarshalNizkParams()

		uArray[i] = ring.NewPoly(params.N(), params.MaxLevel())
		e0Array[i] = ring.NewPoly(params.N(), params.MaxLevel())
		e1Array[i] = ring.NewPoly(params.N(), params.MaxLevel())
		_ = uArray[i].UnmarshalBinary(uBytes)
		_ = e0Array[i].UnmarshalBinary(e0Bytes)
		_ = e1Array[i].UnmarshalBinary(e1Bytes)
	}
	nizkPCKS.KeySwitch(xCipherText, nizkPCKSCombined, encOut)

	decryptor := bfv.NewDecryptor(params, tsk)
	ptOut := decryptor.DecryptNew(encOut)
	resOut := encoder.DecodeUintNew(ptOut)

	fmt.Println("decrypt result:", resOut)
	for i := range skArray {
		fmt.Printf("%dth u is: ", i)
		fmt.Println(uArray[i].Coeffs)
		fmt.Printf("%dth e0 is:", i)
		fmt.Println(e0Array[i].Coeffs)
		fmt.Printf("%dth e1 is:", i)
		fmt.Println(e1Array[i].Coeffs)
	}

}
