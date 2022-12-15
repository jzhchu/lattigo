package main

import (
	"fmt"
	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/rlwe"
	"testing"
)

func TestBFV(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(bfv.PN11QP54)
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
	encoder.Encode([]uint64{2333}, xPlainText)
	encoder.Encode([]uint64{9527}, yPlainText)

	xCipherText := encryptor.EncryptNew(xPlainText)
	yCipherText := encryptor.EncryptNew(yPlainText)
	addCipherText := evaluator.AddNew(xCipherText, yCipherText)
	mulCipherText := evaluator.MulNew(xCipherText, yCipherText)
	evaluator.Relinearize(mulCipherText, mulCipherText)

	addPlainText := decryptor.DecryptNew(addCipherText)
	mulPlainText := decryptor.DecryptNew(mulCipherText)
	addRes := encoder.DecodeUintNew(addPlainText)
	mulRes := encoder.DecodeUintNew(mulPlainText)

	fmt.Println(addRes)
	fmt.Println(mulRes)
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

	xPlainText := bfv.NewPlaintext(params, params.MaxLevel())
	yPlainText := bfv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode([]uint64{2333}, xPlainText)
	encoder.Encode([]uint64{9527}, yPlainText)

	xCipherText := encryptor.EncryptNew(xPlainText)
	yCipherText := encryptor.EncryptNew(yPlainText)
	addCipherText := evaluator.AddNew(xCipherText, yCipherText)
	mulCipherText := evaluator.MulNew(xCipherText, yCipherText)
	evaluator.Relinearize(mulCipherText, mulCipherText)

	addPlainText := decryptor.DecryptNew(addCipherText)
	mulPlainText := decryptor.DecryptNew(mulCipherText)
	addRes := encoder.DecodeUintNew(addPlainText)
	mulRes := encoder.DecodeUintNew(mulPlainText)

	fmt.Println(addRes)
	fmt.Println(mulRes)

}
