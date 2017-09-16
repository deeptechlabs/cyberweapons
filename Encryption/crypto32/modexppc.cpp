// modexppc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "modexppc.h"
#include "asn.h"

#include "algebra.cpp"
#include "eprecomp.cpp"

NAMESPACE_BEGIN(CryptoPP)

ModExpPrecomputation::~ModExpPrecomputation() {}

ModExpPrecomputation::ModExpPrecomputation(const Integer &mod, const Integer &base, unsigned int maxExpBits, unsigned int storage)
{
	Precompute(mod, base, maxExpBits, storage);
}

ModExpPrecomputation::ModExpPrecomputation(const ModExpPrecomputation &mep)
	: mr(mep.mr.get() ? new MontgomeryRepresentation(*mep.mr) : NULL)
	, ep(mep.ep.get() ? new ExponentiationPrecomputation<Integer>(mr->MultiplicativeGroup(), *mep.ep) : NULL)
{
}

ModExpPrecomputation& ModExpPrecomputation::operator=(const ModExpPrecomputation &mep)
{
	mr.reset(mep.mr.get() ? new MontgomeryRepresentation(*mep.mr) : NULL);
	ep.reset(mep.ep.get() ? new ExponentiationPrecomputation<Integer>(mr->MultiplicativeGroup(), *mep.ep) : NULL);
	return *this;
}

void ModExpPrecomputation::Precompute(const Integer &mod, const Integer &base, unsigned int maxExpBits, unsigned int storage)
{
	if (!mr.get() || mr->GetModulus()!=mod)
	{
		mr.reset(new MontgomeryRepresentation(mod));
		ep.reset(NULL);
	}

	if (!ep.get() || ep->storage < storage)
		ep.reset(new ExponentiationPrecomputation<Integer>(mr->MultiplicativeGroup(), mr->ConvertIn(base), maxExpBits, storage));
}

void ModExpPrecomputation::Load(const Integer &mod, BufferedTransformation &bt)
{
	if (!mr.get() || mr->GetModulus()!=mod)
		mr.reset(new MontgomeryRepresentation(mod));

	ep.reset(new ExponentiationPrecomputation<Integer>(mr->MultiplicativeGroup()));
	BERSequenceDecoder seq(bt);
	ep->storage = (unsigned int)(Integer(seq).ConvertToLong());
	ep->exponentBase.BERDecode(seq);
	ep->g.resize(ep->storage);
	for (unsigned i=0; i<ep->storage; i++)
		ep->g[i].BERDecode(seq);
	seq.OutputFinished();
}

void ModExpPrecomputation::Save(BufferedTransformation &bt) const
{
	assert(ep.get());
	DERSequenceEncoder seq(bt);
	Integer(ep->storage).DEREncode(seq);
	ep->exponentBase.DEREncode(seq);
	for (unsigned i=0; i<ep->storage; i++)
		ep->g[i].DEREncode(seq);
	seq.InputFinished();
}

Integer ModExpPrecomputation::Exponentiate(const Integer &exponent) const
{
	assert(mr.get() && ep.get());
	return mr->ConvertOut(ep->Exponentiate(exponent));
}

Integer ModExpPrecomputation::CascadeExponentiate(const Integer &exponent, const ModExpPrecomputation &pc2, const Integer &exponent2) const
{
	assert(mr.get() && ep.get());
	return mr->ConvertOut(ep->CascadeExponentiate(exponent, *pc2.ep, exponent2));
}

NAMESPACE_END
