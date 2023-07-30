package dbfv

import (
	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/drlwe"
	"github.com/jzhchu/lattigo/ring"
	"github.com/jzhchu/lattigo/rlwe"
	"github.com/jzhchu/lattigo/utils"
)

// E2SProtocol is the structure storing the parameters and temporary buffers
// required by the encryption-to-shares protocol.
type E2SProtocol struct {
	*drlwe.CKSProtocol
	params bfv.Parameters

	maskSampler *ring.UniformSampler
	encoder     bfv.Encoder

	zero              *rlwe.SecretKey
	tmpPlaintextRingT *bfv.PlaintextRingT
	tmpPlaintext      *rlwe.Plaintext
}

type NizkE2SProtocol struct {
	*drlwe.NizkCKSProtocol
	params bfv.Parameters

	maskSampler *ring.UniformSampler
	encoder     bfv.Encoder

	zero              *rlwe.SecretKey
	tmpPlaintextRingT *bfv.PlaintextRingT
	tmpPlaintext      *rlwe.Plaintext
}

// ShallowCopy creates a shallow copy of E2SProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// E2SProtocol can be used concurrently.
func (e2s *E2SProtocol) ShallowCopy() *E2SProtocol {

	params := e2s.params

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	return &E2SProtocol{
		CKSProtocol:       e2s.CKSProtocol.ShallowCopy(),
		params:            e2s.params,
		maskSampler:       ring.NewUniformSampler(prng, params.RingT()),
		encoder:           e2s.encoder.ShallowCopy(),
		zero:              e2s.zero,
		tmpPlaintextRingT: bfv.NewPlaintextRingT(params),
		tmpPlaintext:      bfv.NewPlaintext(params, params.MaxLevel()),
	}
}

func (nizkE2S *NizkE2SProtocol) ShallowCopy() *NizkE2SProtocol {
	params := nizkE2S.params

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	return &NizkE2SProtocol{
		NizkCKSProtocol:   nizkE2S.NizkCKSProtocol.ShallowCopy(),
		params:            nizkE2S.params,
		maskSampler:       ring.NewUniformSampler(prng, params.RingT()),
		encoder:           nizkE2S.encoder.ShallowCopy(),
		zero:              nizkE2S.zero,
		tmpPlaintextRingT: bfv.NewPlaintextRingT(params),
		tmpPlaintext:      bfv.NewPlaintext(params, params.MaxLevel()),
	}
}

// NewE2SProtocol creates a new E2SProtocol struct from the passed BFV parameters.
func NewE2SProtocol(params bfv.Parameters, sigmaSmudging float64) *E2SProtocol {
	e2s := new(E2SProtocol)
	e2s.CKSProtocol = drlwe.NewCKSProtocol(params.Parameters, sigmaSmudging)
	e2s.params = params
	e2s.encoder = bfv.NewEncoder(params)
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	e2s.maskSampler = ring.NewUniformSampler(prng, params.RingT())
	e2s.zero = rlwe.NewSecretKey(params.Parameters)
	e2s.tmpPlaintext = bfv.NewPlaintext(params, params.MaxLevel())
	e2s.tmpPlaintextRingT = bfv.NewPlaintextRingT(params)
	return e2s
}

func NewNizkE2SProtocol(params bfv.Parameters, sigmaSmudging float64) *NizkE2SProtocol {
	nizkE2S := new(NizkE2SProtocol)
	nizkE2S.NizkCKSProtocol = drlwe.NewNizkCKSProtocol(params.Parameters, sigmaSmudging)
	nizkE2S.params = params
	nizkE2S.encoder = bfv.NewEncoder(params)
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	nizkE2S.maskSampler = ring.NewUniformSampler(prng, params.RingT())
	nizkE2S.zero = rlwe.NewSecretKey(params.Parameters)
	nizkE2S.tmpPlaintext = bfv.NewPlaintext(params, params.MaxLevel())
	nizkE2S.tmpPlaintextRingT = bfv.NewPlaintextRingT(params)

	return nizkE2S
}

// GenShare generates a party's share in the encryption-to-shares protocol. This share consist in the additive secret-share of the party
// which is written in secretShareOut and in the public masked-decryption share written in publicShareOut.
// ct1 is degree 1 element of a bfv.Ciphertext, i.e. bfv.Ciphertext.Value[1].
func (e2s *E2SProtocol) GenShare(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, secretShareOut *rlwe.AdditiveShare, publicShareOut *drlwe.CKSShare) {
	e2s.CKSProtocol.GenShare(sk, e2s.zero, ct, publicShareOut)
	e2s.maskSampler.Read(&secretShareOut.Value)
	e2s.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: &secretShareOut.Value}}, e2s.tmpPlaintext)
	e2s.params.RingQ().Sub(publicShareOut.Value, e2s.tmpPlaintext.Value, publicShareOut.Value)
}

func (nizkE2S *NizkE2SProtocol) GenShare(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, secretShareOut *rlwe.AdditiveShare, publicShareOut *drlwe.CKSShare) {
	nizkE2S.NizkCKSProtocol.GenShare(sk, nizkE2S.zero, ct, publicShareOut)
	nizkE2S.maskSampler.Read(&secretShareOut.Value)
	nizkE2S.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: &secretShareOut.Value}}, nizkE2S.tmpPlaintext)
	nizkE2S.params.RingQ().Sub(publicShareOut.Value, nizkE2S.tmpPlaintext.Value, publicShareOut.Value)
}

// GetShare is the final step of the encryption-to-share protocol. It performs the masked decryption of the target ciphertext followed by a
// the removal of the caller's secretShare as generated in the GenShare method.
// If the caller is not secret-key-share holder (i.e., didn't generate a decryption share), `secretShare` can be set to nil.
// Therefore, in order to obtain an additive sharing of the message, only one party should call this method, and the other parties should use
// the secretShareOut output of the GenShare method.
func (e2s *E2SProtocol) GetShare(secretShare *rlwe.AdditiveShare, aggregatePublicShare *drlwe.CKSShare, ct *rlwe.Ciphertext, secretShareOut *rlwe.AdditiveShare) {
	e2s.params.RingQ().Add(aggregatePublicShare.Value, ct.Value[0], e2s.tmpPlaintext.Value)
	e2s.encoder.ScaleDown(e2s.tmpPlaintext, e2s.tmpPlaintextRingT)
	if secretShare != nil {
		e2s.params.RingT().Add(&secretShare.Value, e2s.tmpPlaintextRingT.Value, &secretShareOut.Value)
	} else {
		secretShareOut.Value.Copy(e2s.tmpPlaintextRingT.Value)
	}
}

func (nizkE2S *NizkE2SProtocol) GetShare(secretShare *rlwe.AdditiveShare, aggregatePublicShare *drlwe.CKSShare, ct *rlwe.Ciphertext, secretShareOut *rlwe.AdditiveShare) {
	nizkE2S.params.RingQ().Add(aggregatePublicShare.Value, ct.Value[0], nizkE2S.tmpPlaintext.Value)
	nizkE2S.encoder.ScaleDown(nizkE2S.tmpPlaintext, nizkE2S.tmpPlaintextRingT)
	if secretShare != nil {
		nizkE2S.params.RingT().Add(&secretShare.Value, nizkE2S.tmpPlaintextRingT.Value, &secretShareOut.Value)
	} else {
		secretShareOut.Value.Copy(nizkE2S.tmpPlaintextRingT.Value)
	}
}

// S2EProtocol is the structure storing the parameters and temporary buffers
// required by the shares-to-encryption protocol.
type S2EProtocol struct {
	*drlwe.CKSProtocol
	params bfv.Parameters

	encoder bfv.Encoder

	zero         *rlwe.SecretKey
	tmpPlaintext *rlwe.Plaintext
}

type NizkS2EProtocol struct {
	*drlwe.NizkCKSProtocol
	params bfv.Parameters

	encoder bfv.Encoder

	zero         *rlwe.SecretKey
	tmpPlaintext *rlwe.Plaintext
}

// NewS2EProtocol creates a new S2EProtocol struct from the passed BFV parameters.
func NewS2EProtocol(params bfv.Parameters, sigmaSmudging float64) *S2EProtocol {
	s2e := new(S2EProtocol)
	s2e.CKSProtocol = drlwe.NewCKSProtocol(params.Parameters, sigmaSmudging)
	s2e.params = params
	s2e.encoder = bfv.NewEncoder(params)
	s2e.zero = rlwe.NewSecretKey(params.Parameters)
	s2e.tmpPlaintext = bfv.NewPlaintext(params, params.MaxLevel())
	return s2e
}

func NewNizkS2EProtocol(params bfv.Parameters, sigmaSmudging float64) *NizkS2EProtocol {
	nizkS2E := new(NizkS2EProtocol)
	nizkS2E.NizkCKSProtocol = drlwe.NewNizkCKSProtocol(params.Parameters, sigmaSmudging)
	nizkS2E.params = params
	nizkS2E.encoder = bfv.NewEncoder(params)
	nizkS2E.zero = rlwe.NewSecretKey(params.Parameters)
	nizkS2E.tmpPlaintext = bfv.NewPlaintext(params, params.MaxLevel())

	return nizkS2E
}

// ShallowCopy creates a shallow copy of S2EProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// S2EProtocol can be used concurrently.
func (s2e *S2EProtocol) ShallowCopy() *S2EProtocol {
	params := s2e.params
	return &S2EProtocol{
		CKSProtocol:  s2e.CKSProtocol.ShallowCopy(),
		encoder:      s2e.encoder.ShallowCopy(),
		params:       params,
		zero:         s2e.zero,
		tmpPlaintext: bfv.NewPlaintext(params, params.MaxLevel()),
	}
}

func (nizkS2E *NizkS2EProtocol) ShallowCopy() *NizkS2EProtocol {
	params := nizkS2E.params
	return &NizkS2EProtocol{
		NizkCKSProtocol: nizkS2E.NizkCKSProtocol.ShallowCopy(),
		encoder:         nizkS2E.encoder.ShallowCopy(),
		params:          params,
		zero:            nizkS2E.zero,
		tmpPlaintext:    bfv.NewPlaintext(params, params.MaxLevel()),
	}
}

// GenShare generates a party's in the shares-to-encryption protocol given the party's secret-key share `sk`, a common
// polynomial sampled from the CRS `crp` and the party's secret share of the message.
func (s2e *S2EProtocol) GenShare(sk *rlwe.SecretKey, crp drlwe.CKSCRP, secretShare *rlwe.AdditiveShare, c0ShareOut *drlwe.CKSShare) {
	s2e.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: &secretShare.Value}}, s2e.tmpPlaintext)
	s2e.CKSProtocol.GenShare(s2e.zero, sk, &rlwe.Ciphertext{Value: []*ring.Poly{nil, (*ring.Poly)(&crp)}, MetaData: rlwe.MetaData{IsNTT: false}}, c0ShareOut)
	s2e.params.RingQ().Add(c0ShareOut.Value, s2e.tmpPlaintext.Value, c0ShareOut.Value)
}

func (nizkS2E *NizkS2EProtocol) GenShare(sk *rlwe.SecretKey, crp drlwe.CKSCRP, secretShare *rlwe.AdditiveShare, c0shareOut *drlwe.CKSShare) {
	nizkS2E.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: &secretShare.Value}}, nizkS2E.tmpPlaintext)
	nizkS2E.NizkCKSProtocol.GenShare(nizkS2E.zero, sk, &rlwe.Ciphertext{Value: []*ring.Poly{nil, (*ring.Poly)(&crp)}, MetaData: rlwe.MetaData{IsNTT: false}}, c0shareOut)
	nizkS2E.params.RingQ().Add(c0shareOut.Value, nizkS2E.tmpPlaintext.Value, c0shareOut.Value)
}

// GetEncryption computes the final encryption of the secret-shared message when provided with the aggregation `c0Agg` of the parties'
// shares in the protocol and with the common, CRS-sampled polynomial `crp`.
func (s2e *S2EProtocol) GetEncryption(c0Agg *drlwe.CKSShare, crp drlwe.CKSCRP, ctOut *rlwe.Ciphertext) {
	if ctOut.Degree() != 1 {
		panic("cannot GetEncryption: ctOut must have degree 1.")
	}
	ctOut.Value[0].Copy(c0Agg.Value)
	ctOut.Value[1].Copy((*ring.Poly)(&crp))
}

func (nizkS2E *NizkS2EProtocol) GetEncryption(c0Agg *drlwe.CKSShare, crp drlwe.CKSCRP, ctOut *rlwe.Ciphertext) {
	if ctOut.Degree() != 1 {
		panic("cannot GetEncryption: ctOut must have degree 1.")
	}
	ctOut.Value[0].Copy(c0Agg.Value)
	ctOut.Value[1].Copy((*ring.Poly)(&crp))
}
