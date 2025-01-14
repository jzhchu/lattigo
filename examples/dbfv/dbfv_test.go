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

func TestColBootstrap(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN12Q109)
	crs, _ := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'e'})
	N := 4

	encoder := bfv.NewEncoder(params)
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	skArray := make([]*rlwe.SecretKey, N)
	cpk := rlwe.NewPublicKey(params.Parameters)
	crlk := rlwe.NewRelinearizationKey(params.Parameters, 1)
	for i := range skArray {
		skArray[i] = bfv.NewKeyGenerator(params).GenSecretKey()
	}

	ckg := dbfv.NewCKGProtocol(params)
	ckgCombined := ckg.AllocateShare()
	ckgCRP := ckg.SampleCRP(crs)
	for i := range skArray {
		ckgShare := ckg.AllocateShare()
		ckg.GenShare(skArray[i], ckgCRP, ckgShare)
		ckg.AggregateShares(ckgShare, ckgCombined, ckgCombined)
	}
	ckg.GenPublicKey(ckgCombined, ckgCRP, cpk)

	rkg := dbfv.NewRKGProtocol(params)
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()
	rkgCRP := rkg.SampleCRP(crs)
	rlkEphemSkArray := make([]*rlwe.SecretKey, N)
	for i := range skArray {
		rlkEphemSk, rkgShareOne, _ := rkg.AllocateShare()
		rkg.GenShareRoundOne(skArray[i], rkgCRP, rlkEphemSk, rkgShareOne)
		rlkEphemSkArray[i] = rlkEphemSk.CopyNew()
		rkg.AggregateShares(rkgShareOne, rkgCombined1, rkgCombined1)
	}
	for i := range skArray {
		_, _, rkgShareTwo := rkg.AllocateShare()
		rkg.GenShareRoundTwo(rlkEphemSkArray[i], skArray[i], rkgCombined1, rkgShareTwo)
		rkg.AggregateShares(rkgShareTwo, rkgCombined2, rkgCombined2)
	}
	rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, crlk)

	xArray := make([]uint64, params.N())
	yArray := make([]uint64, params.N())
	resArray := make([]uint64, params.N())
	for i := range resArray {
		xArray[i] = 95 + uint64(i)
		yArray[i] = 27 + uint64(i)
	}
	xPlaintext := encoder.EncodeNew(xArray, params.MaxLevel())
	yPlaintext := encoder.EncodeNew(yArray, params.MaxLevel())

	encryptor := bfv.NewEncryptor(params, cpk)
	xCipherText := encryptor.EncryptNew(xPlaintext)
	yCipherText := encryptor.EncryptNew(yPlaintext)
	resCipherText := bfv.NewCiphertext(params, 1, params.MaxLevel())

	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: crlk})
	evaluator.Add(xCipherText, yCipherText, resCipherText)
	for i := range resArray {
		resArray[i] = xArray[i] + yArray[i]
	}

	tmpRes := evaluator.MulNew(resCipherText, xCipherText)
	evaluator.Relinearize(tmpRes, resCipherText)
	for j := range resArray {
		resArray[j] = (resArray[j] * xArray[j]) % params.T()
	}

	//cbs := dbfv.NewRefreshProtocol(params, 3.19)
	//cbsCombined := cbs.AllocateShare(params.MaxLevel(), params.MaxLevel())
	//cbsCRP := cbs.SampleCRP(params.MaxLevel(), crs)
	//for i := range skArray {
	//	cbsShare := cbs.AllocateShare(params.MaxLevel(), params.MaxLevel())
	//	cbs.GenShare(skArray[i], resCipherText, cbsCRP, cbsShare)
	//	cbs.AggregateShares(cbsShare, cbsCombined, cbsCombined)
	//}
	//cbs.Finalize(resCipherText, cbsCRP, cbsCombined, resCipherText)

	nizkCBS := dbfv.NewNizkRefreshProtocol(params, 3.19)
	cbsCombined := nizkCBS.AllocateShare(params.MaxLevel(), params.MaxLevel())
	cbsCRP := nizkCBS.SampleCRP(params.MaxLevel(), crs)
	for i := range skArray {
		cbsShare := nizkCBS.AllocateShare(params.MaxLevel(), params.MaxLevel())
		nizkCBS.GenShare(skArray[i], resCipherText, cbsCRP, cbsShare)
		nizkCBS.AggregateShares(cbsShare, cbsCombined, cbsCombined)
		ringQ := params.RingQ()
		maskBytes, e0Bytes, e1Bytes := nizkCBS.MarshalNizkParams()
		delta := params.Delta()
		//deltaMForm := params.DeltaMForm()
		mask := new(ring.Poly)
		e0 := new(ring.Poly)
		e1 := new(ring.Poly)
		err := mask.UnmarshalBinary(maskBytes)
		if err != nil {
			panic(err)
		}
		err = e0.UnmarshalBinary(e0Bytes)
		if err != nil {
			panic(err)
		}
		err = e1.UnmarshalBinary(e1Bytes)
		if err != nil {
			panic(err)
		}

		deltaM := ringQ.NewPoly()
		c1 := ringQ.NewPoly()
		sc := ringQ.NewPoly()
		sa := ringQ.NewPoly()
		a := ringQ.NewPoly()
		s := ringQ.NewPoly()
		h0 := ringQ.NewPoly()
		h1 := ringQ.NewPoly()

		deltaPoly := ringQ.NewPoly()
		maskOverQ := ringQ.NewPoly()
		for i := 0; i < deltaPoly.Level()+1; i++ {
			deltaPoly.Coeffs[i][0] = delta
		}
		for i := 0; i < maskOverQ.N(); i++ {
			maskOverQ.Coeffs[0][i] = mask.Coeffs[0][i]
		}

		s = skArray[i].Value.Q.CopyNew()
		copy(a.Buff, cbsCRP.Buff)
		a.Resize(params.MaxLevel())
		ringQ.InvMForm(s, s)
		ringQ.InvNTT(s, s)
		ringQ.NTT(s, s)
		ringQ.NTT(a, a)
		ringQ.NTT(resCipherText.Value[1], c1)
		ringQ.NTT(maskOverQ, maskOverQ)
		ringQ.NTT(deltaPoly, deltaPoly)
		ringQ.MulCoeffs(c1, s, sc)
		ringQ.MulCoeffs(a, s, sa)
		//ringQ.MulScalar(mask, delta, deltaM)
		ringQ.MulCoeffs(maskOverQ, deltaPoly, deltaM)
		ringQ.InvNTT(deltaM, deltaM)
		ringQ.InvNTT(sc, sc)
		ringQ.InvNTT(sa, sa)
		ringQ.Add(sc, e0, h0)
		ringQ.Add(deltaM, e1, h1)
		ringQ.Sub(h0, deltaM, h0)
		ringQ.Sub(h1, sa, h1)

		hShare0, hShare1 := nizkCBS.ParseCBSShare(cbsShare.MaskedTransformShare)
		fmt.Println(ringQ.Equal(hShare0, h0), ringQ.Equal(hShare1, h1))
	}
	nizkCBS.Finalize(resCipherText, cbsCRP, cbsCombined, resCipherText)

	tmpRes = evaluator.MulNew(resCipherText, xCipherText)
	evaluator.Relinearize(tmpRes, resCipherText)
	for j := range resArray {
		resArray[j] = (resArray[j] * xArray[j]) % params.T()
	}

	pcks := dbfv.NewPCKSProtocol(params, 3.19)
	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut := bfv.NewCiphertext(params, 1, params.MaxLevel())
	for i := range skArray {
		pcksShare := pcks.AllocateShare(params.MaxLevel())
		pcks.GenShare(skArray[i], tpk, resCipherText, pcksShare)
		pcks.AggregateShares(pcksShare, pcksCombined, pcksCombined)
	}
	pcks.KeySwitch(resCipherText, pcksCombined, encOut)

	decryptor := bfv.NewDecryptor(params, tsk)
	ptOut := decryptor.DecryptNew(encOut)
	resOut := encoder.DecodeUintNew(ptOut)

	fmt.Println("decrypt result:", resOut)
	fmt.Println("reality result:", resArray)
}
