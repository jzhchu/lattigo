package dbfv

import (
	"github.com/jzhchu/lattigo/bfv"
	"github.com/jzhchu/lattigo/drlwe"
	"github.com/jzhchu/lattigo/rlwe"
)

// RefreshProtocol is a struct storing the relevant parameters for the Refresh protocol.
type RefreshProtocol struct {
	MaskedTransformProtocol
}

type NizkRefreshProtocol struct {
	NizkMaskedTransformProtocol
}

// ShallowCopy creates a shallow copy of RefreshProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// RefreshProtocol can be used concurrently.
func (rfp *RefreshProtocol) ShallowCopy() *RefreshProtocol {
	return &RefreshProtocol{*rfp.MaskedTransformProtocol.ShallowCopy()}
}

func (nizkRFP *NizkRefreshProtocol) ShallowCopy() *NizkRefreshProtocol {
	return &NizkRefreshProtocol{*nizkRFP.NizkMaskedTransformProtocol.ShallowCopy()}
}

// RefreshShare is a struct storing a party's share in the Refresh protocol.
type RefreshShare struct {
	MaskedTransformShare
}

// NewRefreshProtocol creates a new Refresh protocol instance.
func NewRefreshProtocol(params bfv.Parameters, sigmaSmudging float64) (rfp *RefreshProtocol) {
	rfp = new(RefreshProtocol)
	mt, _ := NewMaskedTransformProtocol(params, params, sigmaSmudging)
	rfp.MaskedTransformProtocol = *mt
	return
}

func NewNizkRefreshProtocol(params bfv.Parameters, sigmaSmudging float64) (nizkRFP *NizkRefreshProtocol) {
	nizkRFP = new(NizkRefreshProtocol)
	nizkMT, _ := NewNizkMaskedTransformProtocol(params, params, sigmaSmudging)
	nizkRFP.NizkMaskedTransformProtocol = *nizkMT
	return
}

// AllocateShare allocates the shares of the PermuteProtocol
func (rfp *RefreshProtocol) AllocateShare(levelIn, levelOut int) *RefreshShare {
	share := rfp.MaskedTransformProtocol.AllocateShare(levelIn, levelOut)
	return &RefreshShare{*share}
}

func (nizkRFP *NizkRefreshProtocol) AllocateShare(levelIn, levelOut int) *RefreshShare {
	share := nizkRFP.NizkMaskedTransformProtocol.AllocateShare(levelIn, levelOut)
	return &RefreshShare{*share}
}

// GenShare generates a share for the Refresh protocol.
// ct1 is degree 1 element of a bfv.Ciphertext, i.e. bfv.Ciphertext.Value[1].
func (rfp *RefreshProtocol) GenShare(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, crp drlwe.CKSCRP, shareOut *RefreshShare) {
	rfp.MaskedTransformProtocol.GenShare(sk, sk, ct, crp, nil, &shareOut.MaskedTransformShare)
}

func (nizkRFP *NizkRefreshProtocol) GenShare(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, crp drlwe.CKSCRP, shareOut *RefreshShare) {
	nizkRFP.NizkMaskedTransformProtocol.GenShare(sk, sk, ct, crp, nil, &shareOut.MaskedTransformShare)
}

//func (nizkRFP *NizkRefreshProtocol) MarshalNizkParams() []byte {
//	eBytes := nizkRFP.MarshalNizkParams()
//	return eBytes
//}

// AggregateShares aggregates two parties' shares in the Refresh protocol.
func (rfp *RefreshProtocol) AggregateShares(share1, share2, shareOut *RefreshShare) {
	rfp.MaskedTransformProtocol.AggregateShares(&share1.MaskedTransformShare, &share2.MaskedTransformShare, &shareOut.MaskedTransformShare)
}

func (nizkRFP *NizkRefreshProtocol) AggregateShares(share1, share2, shareOut *RefreshShare) {
	nizkRFP.NizkMaskedTransformProtocol.AggregateShares(&share1.MaskedTransformShare, &share2.MaskedTransformShare, &shareOut.MaskedTransformShare)
}

// Finalize applies Decrypt, Recode and Recrypt on the input ciphertext.
func (rfp *RefreshProtocol) Finalize(ctIn *rlwe.Ciphertext, crp drlwe.CKSCRP, share *RefreshShare, ctOut *rlwe.Ciphertext) {
	rfp.MaskedTransformProtocol.Transform(ctIn, nil, crp, &share.MaskedTransformShare, ctOut)
}

func (nizkRFP *NizkRefreshProtocol) Finalize(ctIn *rlwe.Ciphertext, crp drlwe.CKSCRP, share *RefreshShare, ctOut *rlwe.Ciphertext) {
	nizkRFP.NizkMaskedTransformProtocol.Transform(ctIn, nil, crp, &share.MaskedTransformShare, ctOut)
}
