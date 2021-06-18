package rlwe

import (
	"math"
	"github.com/ldsec/lattigo/v2/ring"
)

// KeySwitcher is a struct for RLWE key-switching
type KeySwitcher struct {
	*Parameters
	*keySwitcherBuffer
	Baseconverter *ring.FastBasisExtender
	Decomposer *ring.Decomposer
}

type keySwitcherBuffer struct{
	PoolQ       [6]*ring.Poly // Memory pool in order : Decomp(c2), for NTT^-1(c2), res(c0', c1')
	PoolP       [6]*ring.Poly // Memory pool in order : Decomp(c2), res(c0', c1')
	PoolInvNTT  *ring.Poly
	C2QiQDecomp []*ring.Poly // Memory pool for the basis extension in hoisting
	C2QiPDecomp []*ring.Poly // Memory pool for the basis extension in hoisting
}

func newKeySwitcherBuffer(params Parameters) (*keySwitcherBuffer){

	buff := new(keySwitcherBuffer)
	beta := params.Beta()
	ringQ := params.RingQ()
	ringP := params.RingP()

	buff.PoolQ = [6]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
	buff.PoolP = [6]*ring.Poly{ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly()}

	buff.PoolInvNTT = ringQ.NewPoly()

	buff.C2QiQDecomp = make([]*ring.Poly, beta)
	buff.C2QiPDecomp = make([]*ring.Poly, beta)

	for i := 0; i < beta; i++ {
		buff.C2QiQDecomp[i] = ringQ.NewPoly()
		buff.C2QiPDecomp[i] = ringP.NewPoly()
	}

	return buff
}

func NewKeySwitcher(params Parameters) (*KeySwitcher){
	ks := new(KeySwitcher)
	ks.Parameters = &params
	ks.Baseconverter = ring.NewFastBasisExtender(params.RingQ(), params.RingP())
	ks.Decomposer = ring.NewDecomposer(params.RingQ().Modulus, params.RingP().Modulus)
	ks.keySwitcherBuffer = newKeySwitcherBuffer(params)
	return ks
}

func (ks *KeySwitcher) ShallowCopy() *KeySwitcher {
	return &KeySwitcher{
		Parameters:ks.Parameters,
		Decomposer:ks.Decomposer,
		keySwitcherBuffer: newKeySwitcherBuffer(*ks.Parameters),
		Baseconverter:ks.Baseconverter.ShallowCopy(),
	}
}


// SwitchKeysInPlace applies the general key-switching procedure of the form [c0 + cx*evakey[0], c1 + cx*evakey[1]]
func (ks *KeySwitcher) SwitchKeysInPlace(level int, cx *ring.Poly, evakey *SwitchingKey, p0, p1 *ring.Poly) {
	ks.SwitchKeysInPlaceNoModDown(level, cx, evakey, p0, ks.PoolP[1], p1, ks.PoolP[2])
	ks.Baseconverter.ModDownSplitNTTPQ(level, p0, ks.PoolP[1], p0)
	ks.Baseconverter.ModDownSplitNTTPQ(level, p1, ks.PoolP[2], p1)
}

func (ks *KeySwitcher) DecompInternal(levelQ int, c2NTT *ring.Poly, c2QiQDecomp, c2QiPDecomp []*ring.Poly) {

	ringQ := ks.RingQ()

	c2InvNTT := ks.PoolInvNTT
	ringQ.InvNTTLvl(levelQ, c2NTT, c2InvNTT)

	alpha := ks.Parameters.PCount()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))

	for i := 0; i < beta; i++ {
		ks.DecomposeAndSplitNTT(levelQ, i, c2NTT, c2InvNTT, c2QiQDecomp[i], c2QiPDecomp[i])
	}
}

// DecomposeAndSplitNTT decomposes the input polynomial into the target CRT basis.
func (ks *KeySwitcher) DecomposeAndSplitNTT(level, beta int, c2NTT, c2InvNTT, c2QiQ, c2QiP *ring.Poly) {

	ringQ := ks.RingQ()
	ringP := ks.RingP()

	ks.Decomposer.DecomposeAndSplit(level, beta, c2InvNTT, c2QiQ, c2QiP)

	p0idxst := beta * len(ringP.Modulus)
	p0idxed := p0idxst + ks.Decomposer.Xalpha()[beta]

	// c2_qi = cx mod qi mod qi
	for x := 0; x < level+1; x++ {
		if p0idxst <= x && x < p0idxed {
			copy(c2QiQ.Coeffs[x], c2NTT.Coeffs[x])
		} else {
			ring.NTTLazy(c2QiQ.Coeffs[x], c2QiQ.Coeffs[x], ringQ.N, ringQ.NttPsi[x], ringQ.Modulus[x], ringQ.MredParams[x], ringQ.BredParams[x])
		}
	}
	// c2QiP = c2 mod qi mod pj
	ringP.NTTLazy(c2QiP, c2QiP)
}

func (ks *KeySwitcher) SwitchKeysInPlaceNoModDown(level int, cx *ring.Poly, evakey *SwitchingKey, pool2Q, pool2P, pool3Q, pool3P *ring.Poly) {

	var reduce int

	ringQ := ks.ringQ
	ringP := ks.ringP

	// Pointers allocation
	c2QiQ := ks.PoolQ[0]
	c2QiP := ks.PoolP[0]

	c2 := ks.PoolInvNTT

	evakey0Q := new(ring.Poly)
	evakey1Q := new(ring.Poly)
	evakey0P := new(ring.Poly)
	evakey1P := new(ring.Poly)

	// We switch the element on which the switching key operation will be conducted out of the NTT domain

	ringQ.InvNTTLvl(level, cx, c2)

	reduce = 0

	alpha := len(ringP.Modulus)
	beta := int(math.Ceil(float64(level+1) / float64(alpha)))

	QiOverF := ks.Parameters.QiOverflowMargin(level) >> 1
	PiOverF := ks.Parameters.PiOverflowMargin() >> 1

	// Key switching with CRT decomposition for the Qi
	for i := 0; i < beta; i++ {

		ks.DecomposeAndSplitNTT(level, i, cx, c2, c2QiQ, c2QiP)

		evakey0Q.Coeffs = evakey.Value[i][0].Coeffs[:level+1]
		evakey1Q.Coeffs = evakey.Value[i][1].Coeffs[:level+1]
		evakey0P.Coeffs = evakey.Value[i][0].Coeffs[len(ringQ.Modulus):]
		evakey1P.Coeffs = evakey.Value[i][1].Coeffs[len(ringQ.Modulus):]

		if i == 0 {
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomeryConstant(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomeryConstant(evakey1P, c2QiP, pool3P)
		} else {
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey1P, c2QiP, pool3P)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(level, pool2Q, pool2Q)
			ringQ.ReduceLvl(level, pool3Q, pool3Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.Reduce(pool2P, pool2P)
			ringP.Reduce(pool3P, pool3P)
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		ringQ.ReduceLvl(level, pool2Q, pool2Q)
		ringQ.ReduceLvl(level, pool3Q, pool3Q)
	}

	if reduce%PiOverF != 0 {
		ringP.Reduce(pool2P, pool2P)
		ringP.Reduce(pool3P, pool3P)
	}
}

func (ks *KeySwitcher) KeyswitchHoisted(level int, c2QiQDecomp, c2QiPDecomp []*ring.Poly, evakey *SwitchingKey, pool2Q, pool3Q, pool2P, pool3P *ring.Poly) {

	ks.KeyswitchHoistedNoModDown(level, c2QiQDecomp, c2QiPDecomp, evakey, pool2Q, pool3Q, pool2P, pool3P)

	// Computes pool2Q = pool2Q/pool2P and pool3Q = pool3Q/pool3P
	ks.Baseconverter.ModDownSplitNTTPQ(level, pool2Q, pool2P, pool2Q)
	ks.Baseconverter.ModDownSplitNTTPQ(level, pool3Q, pool3P, pool3Q)
}

func (ks *KeySwitcher) KeyswitchHoistedNoModDown(level int, c2QiQDecomp, c2QiPDecomp []*ring.Poly, evakey *SwitchingKey, pool2Q, pool3Q, pool2P, pool3P *ring.Poly) {

	ringQ := ks.ringQ
	ringP := ks.ringP

	alpha := len(ringP.Modulus)
	beta := int(math.Ceil(float64(level+1) / float64(alpha)))

	evakey0Q := new(ring.Poly)
	evakey1Q := new(ring.Poly)
	evakey0P := new(ring.Poly)
	evakey1P := new(ring.Poly)

	QiOverF := ks.Parameters.QiOverflowMargin(level) >> 1
	PiOverF := ks.Parameters.PiOverflowMargin() >> 1

	// Key switching with CRT decomposition for the Qi
	var reduce int
	for i := 0; i < beta; i++ {

		evakey0Q.Coeffs = evakey.Value[i][0].Coeffs[:level+1]
		evakey1Q.Coeffs = evakey.Value[i][1].Coeffs[:level+1]
		evakey0P.Coeffs = evakey.Value[i][0].Coeffs[len(ringQ.Modulus):]
		evakey1P.Coeffs = evakey.Value[i][1].Coeffs[len(ringQ.Modulus):]

		if i == 0 {
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey0Q, c2QiQDecomp[i], pool2Q)
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey1Q, c2QiQDecomp[i], pool3Q)
			ringP.MulCoeffsMontgomeryConstant(evakey0P, c2QiPDecomp[i], pool2P)
			ringP.MulCoeffsMontgomeryConstant(evakey1P, c2QiPDecomp[i], pool3P)
		} else {
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey0Q, c2QiQDecomp[i], pool2Q)
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey1Q, c2QiQDecomp[i], pool3Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey0P, c2QiPDecomp[i], pool2P)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey1P, c2QiPDecomp[i], pool3P)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(level, pool2Q, pool2Q)
			ringQ.ReduceLvl(level, pool3Q, pool3Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.Reduce(pool2P, pool2P)
			ringP.Reduce(pool3P, pool3P)
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		ringQ.ReduceLvl(level, pool2Q, pool2Q)
		ringQ.ReduceLvl(level, pool3Q, pool3Q)
	}

	if reduce%PiOverF != 0 {
		ringP.Reduce(pool2P, pool2P)
		ringP.Reduce(pool3P, pool3P)
	}
}