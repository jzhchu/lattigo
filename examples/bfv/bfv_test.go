package main

import (
	"fmt"
	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/ring"
	"github.com/jzhchu/lattigo/rlwe"
	"github.com/jzhchu/lattigo/utils"
	"testing"
	"time"
)

func TestRing(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN12Q109)

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	ternarySampler := ring.NewTernarySampler(prng, params.RingQ(), params.Sigma(), false)
	gaussianSampler := ring.NewGaussianSampler(prng, params.RingQ(), params.Sigma(), int(6*params.Sigma()))

	ringp, err := ring.NewRing(params.N(), params.Q())
	if err != nil {
		fmt.Println(err)
		return
	}

	poly1 := ringp.NewPoly()
	ternarySampler.Read(poly1)
	ringp.NTT(poly1, poly1)
	ringp.MForm(poly1, poly1)

	poly2 := ringp.NewPoly()
	gaussianSampler.Read(poly2)
	ringp.NTT(poly2, poly2)
	ringp.MForm(poly2, poly2)

	poly3 := ringp.NewPoly()
	ringp.Add(poly1, poly2, poly3)

	ringp.InvMForm(poly1, poly1)
	ringp.InvNTT(poly1, poly1)
	ringp.InvMForm(poly2, poly2)
	ringp.InvNTT(poly2, poly2)
	ringp.InvMForm(poly3, poly3)
	ringp.InvNTT(poly3, poly3)

	poly3.Copy(poly1)

	fmt.Println(poly1)
}

func TestBFVParameters(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(bfv.DefaultParamsJ[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	encoder := bfv.NewEncoder(params)
	encryptor := bfv.NewEncryptor(params, pk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	decryptor := bfv.NewDecryptor(params, sk)

	xPlainText := bfv.NewPlaintext(params, params.MaxLevel())
	yPlainText := bfv.NewPlaintext(params, params.MaxLevel())

	xArray := make([]uint64, params.N())
	yArray := make([]uint64, params.N())
	for i := 0; i < params.N(); i++ {
		xArray[i] = 9527 + uint64(i)
		yArray[i] = 2333 + uint64(i)
	}

	encoder.Encode(xArray, xPlainText)
	encoder.Encode(yArray, yPlainText)

	startTime := time.Now()
	xCipherText := encryptor.EncryptNew(xPlainText)
	endTime := time.Now()
	encryptTime := endTime.Sub(startTime)

	yCipherText := encryptor.EncryptNew(yPlainText)

	startTime = time.Now()
	addCipherText := evaluator.AddNew(xCipherText, yCipherText)
	endTime = time.Now()
	addCipherTime := endTime.Sub(startTime)

	startTime = time.Now()
	mulCipherText := evaluator.MulNew(xCipherText, yCipherText)
	evaluator.Relinearize(mulCipherText, mulCipherText)
	endTime = time.Now()
	mulCipherTime := endTime.Sub(startTime)

	startTime = time.Now()
	addPlainText := decryptor.DecryptNew(addCipherText)
	endTime = time.Now()
	decryptTime := endTime.Sub(startTime)
	mulPlainText := decryptor.DecryptNew(mulCipherText)
	addRes := encoder.DecodeUintNew(addPlainText)
	mulRes := encoder.DecodeUintNew(mulPlainText)

	fmt.Println(addRes)
	fmt.Println(mulRes)

	fmt.Println("encryption time is:", encryptTime)
	fmt.Println("ciphertext add time is:", addCipherTime)
	fmt.Println("ciphertext mul time is:", mulCipherTime)
	fmt.Println("decryption time is:", decryptTime)

	skBytes, _ := sk.MarshalBinary()
	skSize := float64(len(skBytes)) / 1024.0
	pkBytes, _ := pk.MarshalBinary()
	pkSize := float64(len(pkBytes)) / 1024.0
	ptBytes, _ := xPlainText.MarshalBinary()
	ptSize := float64(len(ptBytes)) / 1024.0
	ctBytes, _ := addCipherText.MarshalBinary()
	ctSize := float64(len(ctBytes)) / 1024.0

	fmt.Println("secret key size (kB) is:", skSize)
	fmt.Println("public key size (kB) is:", pkSize)
	fmt.Println("plaintext size (kB) is:", ptSize)
	fmt.Println("ciphertext size (kB) is:", ctSize)
}

func TestLogProofEnc(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(bfv.PN11QP54)
	if err != nil {
		fmt.Println(err)
		return
	}

	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	encoder := bfv.NewEncoder(params)
	encryptor := bfv.NewLPEncryptor(params, pk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	decryptor := bfv.NewDecryptor(params, sk)

	x := make([]uint64, params.N())
	y := make([]uint64, params.N())
	addReal := make([]uint64, params.N())
	mulReal := make([]uint64, params.N())
	for i := range x {
		x[i] = 2333 + uint64(i)
		y[i] = 9527 + uint64(i)
		addReal[i] = (x[i] + y[i]) % params.T()
		mulReal[i] = (x[i] * y[i]) % params.T()
	}
	xPlainText := bfv.NewPlaintext(params, params.MaxLevel())
	yPlainText := bfv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(x, xPlainText)
	encoder.Encode(y, yPlainText)

	xCipherText := encryptor.EncryptNew(xPlainText)
	yCipherText := encryptor.EncryptNew(yPlainText)
	addCipherText := evaluator.AddNew(xCipherText, yCipherText)
	mulCipherText := evaluator.MulNew(xCipherText, yCipherText)
	evaluator.Relinearize(mulCipherText, mulCipherText)

	addPlainText := decryptor.DecryptNew(addCipherText)
	mulPlainText := decryptor.DecryptNew(mulCipherText)
	addRes := encoder.DecodeUintNew(addPlainText)
	mulRes := encoder.DecodeUintNew(mulPlainText)

	fmt.Print("test add Result: ")
	fmt.Println(addRes)
	fmt.Print("real add Result: ")
	fmt.Println(addReal)
	fmt.Println()
	fmt.Print("test mul Result: ")
	fmt.Println(mulRes)
	fmt.Print("real mul Result: ")
	fmt.Println(mulReal)
	fmt.Println(params.QBigInt().String())
}
