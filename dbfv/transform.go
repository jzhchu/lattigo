package dbfv

import (
	"fmt"

	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/drlwe"
	"github.com/jzhchu/lattigo/ring"
	"github.com/jzhchu/lattigo/rlwe"
	"github.com/jzhchu/lattigo/utils"
)

// MaskedTransformProtocol is a struct storing the parameters for the MaskedTransformProtocol protocol.
type MaskedTransformProtocol struct {
	e2s E2SProtocol
	s2e S2EProtocol

	tmpPt       *rlwe.Plaintext
	tmpMask     *ring.Poly
	tmpMaskPerm *ring.Poly
}

type NizkMaskedTransformProtocol struct {
	nizkE2S NizkE2SProtocol
	nizkS2E NizkS2EProtocol

	tmpPt       *rlwe.Plaintext
	tmpMask     *ring.Poly
	tmpMaskPerm *ring.Poly

	e0   *ring.Poly
	e1   *ring.Poly
	mask *ring.Poly
}

// ShallowCopy creates a shallow copy of MaskedTransformProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// MaskedTransformProtocol can be used concurrently.
func (rfp *MaskedTransformProtocol) ShallowCopy() *MaskedTransformProtocol {
	params := rfp.e2s.params

	return &MaskedTransformProtocol{
		e2s:         *rfp.e2s.ShallowCopy(),
		s2e:         *rfp.s2e.ShallowCopy(),
		tmpPt:       bfv.NewPlaintext(params, params.MaxLevel()),
		tmpMask:     params.RingT().NewPoly(),
		tmpMaskPerm: params.RingT().NewPoly(),
	}
}

func (nizkRFP *NizkMaskedTransformProtocol) ShallowCopy() *NizkMaskedTransformProtocol {
	params := nizkRFP.nizkE2S.params

	return &NizkMaskedTransformProtocol{
		nizkE2S:     *nizkRFP.nizkE2S.ShallowCopy(),
		nizkS2E:     *nizkRFP.nizkS2E.ShallowCopy(),
		tmpPt:       bfv.NewPlaintext(params, params.MaxLevel()),
		tmpMask:     params.RingT().NewPoly(),
		tmpMaskPerm: params.RingT().NewPoly(),
		e0:          nizkRFP.e0.CopyNew(),
		e1:          nizkRFP.e1.CopyNew(),
	}
}

// MaskedTransformFunc is struct containing user defined in-place function that can be applied to masked BFV plaintexts, as a part of the
// Masked Transform Protocol.
// Transform is a function called with a vector of integers modulo bfv.Parameters.T() of size bfv.Parameters.N() as input, and must write
// its output on the same buffer.
// Transform can be the identity.
// Decode: if true, then the masked BFV plaintext will be decoded before applying Transform.
// Recode: if true, then the masked BFV plaintext will be recoded after applying Transform.
// i.e. : Decode (true/false) -> Transform -> Recode (true/false).
type MaskedTransformFunc struct {
	Decode bool
	Func   func(coeffs []uint64)
	Encode bool
}

// MaskedTransformShare is a struct storing the decryption and recryption shares.
type MaskedTransformShare struct {
	e2sShare drlwe.CKSShare
	s2eShare drlwe.CKSShare
}

// MarshalBinary encodes a RefreshShare on a slice of bytes.
func (share *MaskedTransformShare) MarshalBinary() ([]byte, error) {
	e2sData, err := share.e2sShare.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s2eData, err := share.s2eShare.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(e2sData, s2eData...), nil
}

// UnmarshalBinary decodes a marshaled RefreshShare on the target RefreshShare.
func (share *MaskedTransformShare) UnmarshalBinary(data []byte) (err error) {
	shareLen := len(data) >> 1
	if err = share.e2sShare.UnmarshalBinary(data[:shareLen]); err != nil {
		return
	}
	if err = share.s2eShare.UnmarshalBinary(data[shareLen:]); err != nil {
		return
	}
	return
}

// NewMaskedTransformProtocol creates a new instance of the PermuteProtocol.
func NewMaskedTransformProtocol(paramsIn, paramsOut bfv.Parameters, sigmaSmudging float64) (rfp *MaskedTransformProtocol, err error) {

	if paramsIn.N() > paramsOut.N() {
		return nil, fmt.Errorf("newMaskedTransformProtocol: paramsIn.N() != paramsOut.N()")
	}

	rfp = new(MaskedTransformProtocol)

	rfp.e2s = *NewE2SProtocol(paramsIn, sigmaSmudging)
	rfp.s2e = *NewS2EProtocol(paramsOut, sigmaSmudging)

	rfp.tmpPt = bfv.NewPlaintext(paramsOut, paramsOut.MaxLevel())
	rfp.tmpMask = paramsIn.RingT().NewPoly()
	rfp.tmpMaskPerm = paramsIn.RingT().NewPoly()
	return
}

func NewNizkMaskedTransformProtocol(paramsIn, paramsOut bfv.Parameters, sigmaSmudging float64) (nizkRFP *NizkMaskedTransformProtocol, err error) {
	if paramsIn.N() > paramsOut.N() {
		return nil, fmt.Errorf("newNizkMaskedTransformProtocol: paramsIn.N() != paramsOut.N()")
	}

	nizkRFP = new(NizkMaskedTransformProtocol)

	nizkRFP.nizkE2S = *NewNizkE2SProtocol(paramsIn, sigmaSmudging)
	nizkRFP.nizkS2E = *NewNizkS2EProtocol(paramsOut, sigmaSmudging)
	//nizkRFP.nizkE2S.NizkCKSProtocol

	nizkRFP.tmpPt = bfv.NewPlaintext(paramsOut, paramsOut.MaxLevel())
	nizkRFP.tmpMask = paramsIn.RingT().NewPoly()
	nizkRFP.tmpMaskPerm = paramsIn.RingT().NewPoly()

	return
}

// SampleCRP samples a common random polynomial to be used in the Masked-Transform protocol from the provided
// common reference string.
func (rfp *MaskedTransformProtocol) SampleCRP(level int, crs utils.PRNG) drlwe.CKSCRP {
	return rfp.s2e.SampleCRP(level, crs)
}

func (nizkRFP *NizkMaskedTransformProtocol) SampleCRP(level int, crs utils.PRNG) drlwe.CKSCRP {
	return nizkRFP.nizkS2E.SampleCRP(level, crs)
}

// AllocateShare allocates the shares of the PermuteProtocol.
func (rfp *MaskedTransformProtocol) AllocateShare(levelIn, levelOut int) *MaskedTransformShare {
	return &MaskedTransformShare{*rfp.e2s.AllocateShare(levelIn), *rfp.s2e.AllocateShare(levelOut)}
}

func (nizkRFP *NizkMaskedTransformProtocol) AllocateShare(levelIn, levelOut int) *MaskedTransformShare {
	return &MaskedTransformShare{*nizkRFP.nizkE2S.AllocateShare(levelIn), *nizkRFP.nizkS2E.AllocateShare(levelOut)}
}

// GenShare generates the shares of the PermuteProtocol.
// ct1 is the degree 1 element of a bfv.Ciphertext, i.e. bfv.Ciphertext.Value[1].
func (rfp *MaskedTransformProtocol) GenShare(skIn, skOut *rlwe.SecretKey, ct *rlwe.Ciphertext, crs drlwe.CKSCRP, transform *MaskedTransformFunc, shareOut *MaskedTransformShare) {

	rfp.e2s.GenShare(skIn, ct, &rlwe.AdditiveShare{Value: *rfp.tmpMask}, &shareOut.e2sShare)

	mask := rfp.tmpMask
	if transform != nil {
		coeffs := make([]uint64, rfp.e2s.params.N())
		ecd := rfp.e2s.encoder
		ptT := &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}

		if transform.Decode {
			ecd.Decode(ptT, coeffs)
		} else {
			copy(coeffs, ptT.Value.Coeffs[0])
		}

		transform.Func(coeffs)

		if transform.Encode {
			ecd.EncodeRingT(coeffs, &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: rfp.tmpMaskPerm}})
		} else {
			copy(rfp.tmpMaskPerm.Coeffs[0], coeffs)
		}

		mask = rfp.tmpMaskPerm
	}

	rfp.s2e.GenShare(skOut, crs, &rlwe.AdditiveShare{Value: *mask}, &shareOut.s2eShare)
}

func (nizkRFP *NizkMaskedTransformProtocol) GenShare(skIn, skOut *rlwe.SecretKey, ct *rlwe.Ciphertext, crs drlwe.CKSCRP, transform *MaskedTransformFunc, shareOut *MaskedTransformShare) {
	nizkRFP.nizkE2S.GenShare(skIn, ct, &rlwe.AdditiveShare{Value: *nizkRFP.tmpMask}, &shareOut.e2sShare)

	mask := nizkRFP.tmpMask
	if transform != nil {
		coeffs := make([]uint64, nizkRFP.nizkE2S.params.N())
		ecd := nizkRFP.nizkE2S.encoder
		ptT := &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}

		if transform.Decode {
			ecd.Decode(ptT, coeffs)
		} else {
			copy(coeffs, ptT.Value.Coeffs[0])
		}

		transform.Func(coeffs)

		if transform.Encode {
			ecd.EncodeRingT(coeffs, &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: nizkRFP.tmpMaskPerm}})
		} else {
			copy(nizkRFP.tmpMaskPerm.Coeffs[0], coeffs)
		}

		mask = nizkRFP.tmpMaskPerm
	}

	nizkRFP.nizkS2E.GenShare(skOut, crs, &rlwe.AdditiveShare{Value: *mask}, &shareOut.s2eShare)

	nizkRFP.e0 = nizkRFP.nizkE2S.GetNizkParams()
	nizkRFP.e1 = nizkRFP.nizkS2E.GetNizkParams()
	nizkRFP.mask = mask.CopyNew()
}

// AggregateShares sums share1 and share2 on shareOut.
func (rfp *MaskedTransformProtocol) AggregateShares(share1, share2, shareOut *MaskedTransformShare) {
	rfp.e2s.params.RingQ().Add(share1.e2sShare.Value, share2.e2sShare.Value, shareOut.e2sShare.Value)
	rfp.s2e.params.RingQ().Add(share1.s2eShare.Value, share2.s2eShare.Value, shareOut.s2eShare.Value)
}

func (nizkRFP *NizkMaskedTransformProtocol) AggregateShares(share1, share2, shareOut *MaskedTransformShare) {
	nizkRFP.nizkE2S.params.RingQ().Add(share1.e2sShare.Value, share2.e2sShare.Value, shareOut.e2sShare.Value)
	nizkRFP.nizkS2E.params.RingQ().Add(share1.s2eShare.Value, share2.s2eShare.Value, shareOut.s2eShare.Value)
}

func (nizkRFP *NizkMaskedTransformProtocol) ParseCBSShare(cbsShare MaskedTransformShare) (*ring.Poly, *ring.Poly) {
	h0 := cbsShare.e2sShare.Value.CopyNew()
	h1 := cbsShare.s2eShare.Value.CopyNew()

	return h0, h1
}

// Transform applies Decrypt, Recode and Recrypt on the input ciphertext.
func (rfp *MaskedTransformProtocol) Transform(ciphertext *rlwe.Ciphertext, transform *MaskedTransformFunc, crs drlwe.CKSCRP, share *MaskedTransformShare, ciphertextOut *rlwe.Ciphertext) {

	rfp.e2s.GetShare(nil, &share.e2sShare, ciphertext, &rlwe.AdditiveShare{Value: *rfp.tmpMask}) // tmpMask RingT(m - sum M_i)

	mask := rfp.tmpMask

	if transform != nil {
		coeffs := make([]uint64, rfp.e2s.params.N())
		ecd := rfp.e2s.encoder
		ptT := &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}

		if transform.Decode {
			ecd.Decode(ptT, coeffs)
		} else {
			copy(coeffs, ptT.Value.Coeffs[0])
		}

		transform.Func(coeffs)

		if transform.Encode {
			ecd.EncodeRingT(coeffs, &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: rfp.tmpMaskPerm}})
		} else {
			copy(rfp.tmpMaskPerm.Coeffs[0], coeffs)
		}

		mask = rfp.tmpMaskPerm
	}

	ciphertextOut.Resize(1, rfp.s2e.params.MaxLevel())
	rfp.s2e.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}, rfp.tmpPt)
	rfp.s2e.params.RingQ().Add(rfp.tmpPt.Value, share.s2eShare.Value, ciphertextOut.Value[0])
	rfp.s2e.GetEncryption(&drlwe.CKSShare{Value: ciphertextOut.Value[0]}, crs, ciphertextOut)
}

func (nizkRFP *NizkMaskedTransformProtocol) Transform(ciphertext *rlwe.Ciphertext, transform *MaskedTransformFunc, crs drlwe.CKSCRP, share *MaskedTransformShare, ciphertextOut *rlwe.Ciphertext) {
	nizkRFP.nizkE2S.GetShare(nil, &share.e2sShare, ciphertext, &rlwe.AdditiveShare{Value: *nizkRFP.tmpMask})
	mask := nizkRFP.tmpMask
	if transform != nil {
		coeffs := make([]uint64, nizkRFP.nizkE2S.params.N())
		ecd := nizkRFP.nizkE2S.encoder
		ptT := &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}

		if transform.Decode {
			ecd.Decode(ptT, coeffs)
		} else {
			copy(coeffs, ptT.Value.Coeffs[0])
		}

		transform.Func(coeffs)

		if transform.Encode {
			ecd.EncodeRingT(coeffs, &bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: nizkRFP.tmpMaskPerm}})
		} else {
			copy(nizkRFP.tmpMaskPerm.Coeffs[0], coeffs)
		}

		mask = nizkRFP.tmpMaskPerm
	}

	ciphertextOut.Resize(1, nizkRFP.nizkS2E.params.MaxLevel())
	nizkRFP.nizkS2E.encoder.ScaleUp(&bfv.PlaintextRingT{Plaintext: &rlwe.Plaintext{Value: mask}}, nizkRFP.tmpPt)
	nizkRFP.nizkS2E.params.RingQ().Add(nizkRFP.tmpPt.Value, share.s2eShare.Value, ciphertextOut.Value[0])
	nizkRFP.nizkS2E.GetEncryption(&drlwe.CKSShare{Value: ciphertextOut.Value[0]}, crs, ciphertextOut)
}

func (nizkRFP *NizkMaskedTransformProtocol) MarshalNizkParams() ([]byte, []byte, []byte) {
	e0Bytes, _ := nizkRFP.e0.MarshalBinary()
	e1Bytes, _ := nizkRFP.e1.MarshalBinary()
	maskBytes, _ := nizkRFP.mask.MarshalBinary()

	return maskBytes, e0Bytes, e1Bytes
}
