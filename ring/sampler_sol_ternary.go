package ring

import (
	"github.com/jzhchu/lattigo/utils"
)

type TernarySolSampler struct {
	baseSampler
	matrixProbability [2][precision - 1]uint8
	matrixValues      [][3]uint64
	sample            func(lvl int, poly *Poly)
	seed              [32]byte
}

func NewTernarySolSampler(baseRing *Ring, seed [32]byte, montgomery bool) *TernarySolSampler {
	ternarySolSampler := new(TernarySolSampler)
	ternarySolSampler.baseRing = baseRing
	ternarySolSampler.sample = ternarySolSampler.sampleProbability
	ternarySolSampler.seed = seed
	ternarySolSampler.prng = utils.NewSolPRNG(seed, 0)
	ternarySolSampler.initializeMatrix(montgomery)

	return ternarySolSampler
}

func (ts *TernarySolSampler) SetSalt(salt uint32) {
	ts.prng = utils.NewSolPRNG(ts.seed, salt)
}

func (ts *TernarySolSampler) Read(pol *Poly) {
	ts.sample(len(ts.baseRing.Modulus)-1, pol)
}

func (ts *TernarySolSampler) ReadLvl(lvl int, pol *Poly) {
	ts.sample(lvl, pol)
}

func (ts *TernarySolSampler) ReadNew() (pol *Poly) {
	pol = ts.baseRing.NewPoly()
	ts.sample(len(ts.baseRing.Modulus)-1, pol)
	return pol
}

func (ts *TernarySolSampler) ReadLvlNew(lvl int) (pol *Poly) {
	pol = ts.baseRing.NewPolyLvl(lvl)
	ts.sample(lvl, pol)
	return pol
}

func (ts *TernarySolSampler) initializeMatrix(montgomery bool) {
	ts.matrixValues = make([][3]uint64, len(ts.baseRing.Modulus))

	for i, Qi := range ts.baseRing.Modulus {
		ts.matrixValues[i][0] = 0

		if montgomery {
			ts.matrixValues[i][1] = MForm(1, Qi, ts.baseRing.BredParams[i])
			ts.matrixValues[i][2] = MForm(Qi-1, Qi, ts.baseRing.BredParams[i])
		} else {
			ts.matrixValues[i][1] = 1
			ts.matrixValues[i][1] = Qi - 1
		}
	}
}

func (ts *TernarySolSampler) sampleProbability(lvl int, pol *Poly) {
	var coeff uint64
	var sign uint64
	var index uint64

	randomBytesCoeffs := make([]byte, ts.baseRing.N>>3)
	randomBytesSign := make([]byte, ts.baseRing.N>>3)

	ts.prng.Read(randomBytesCoeffs)
	ts.prng.Read(randomBytesSign)

	for i := 0; i < ts.baseRing.N; i++ {
		coeff = uint64(uint8(randomBytesCoeffs[i>>3])>>(i&7)) & 1
		sign = uint64(uint8(randomBytesSign[i>>3])>>(i&7)) & 1

		index = (coeff & (sign ^ 1)) | ((sign & coeff) << 1)

		for j := 0; j < lvl+1; j++ {
			pol.Coeffs[j][i] = ts.matrixValues[j][index]
		}
	}
}
