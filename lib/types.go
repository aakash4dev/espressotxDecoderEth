package lib

import (
	"math/big"
)

// G1Point represents a point on the G1 curve
type G1Point struct {
	X, Y BaseField
}
type BaseField = *big.Int
type ScalarField = *big.Int

// G2Point represents a point on the G2 curve
type G2Point struct {
	X0, X1, Y0, Y1 BaseField
}
type Genesis struct {
	ViewNum        uint64 // Adjust this as per your needs.
	BlockHeight    uint64 // Adjust this as per your needs.
	BlockCommRoot  *big.Int
	FeeLedgerComm  *big.Int
	BlsKeyComm     *big.Int
	SchnorrKeyComm *big.Int
	AmountComm     *big.Int
	Threshold      *big.Int
}

type PcsInfo struct {
	u                   big.Int
	evalPoint           big.Int
	nextEvalPoint       big.Int
	eval                big.Int
	commScalars         []big.Int
	commBases           []G1Point
	openingProof        G1Point
	shiftedOpeningProof G1Point
}

type Challenges struct {
	alpha  *big.Int
	alpha2 *big.Int
	alpha3 *big.Int
	beta   *big.Int
	gamma  *big.Int
	zeta   *big.Int
	v      *big.Int
	u      *big.Int
}

// IplonkVerifier.sol
type PlonkProof struct {
	Wire0                 G1Point  `json:"wire0"`
	Wire1                 G1Point  `json:"wire1"`
	Wire2                 G1Point  `json:"wire2"`
	Wire3                 G1Point  `json:"wire3"`
	Wire4                 G1Point  `json:"wire4"`
	ProdPerm              G1Point  `json:"prodPerm"`
	Split0                G1Point  `json:"split0"`
	Split1                G1Point  `json:"split1"`
	Split2                G1Point  `json:"split2"`
	Split3                G1Point  `json:"split3"`
	Split4                G1Point  `json:"split4"`
	Zeta                  G1Point  `json:"zeta"`
	ZetaOmega             G1Point  `json:"zetaOmega"`
	WireEval0             *big.Int `json:"wireEval0"`
	WireEval1             *big.Int `json:"wireEval1"`
	WireEval2             *big.Int `json:"wireEval2"`
	WireEval3             *big.Int `json:"wireEval3"`
	WireEval4             *big.Int `json:"wireEval4"`
	SigmaEval0            *big.Int `json:"sigmaEval0"`
	SigmaEval1            *big.Int `json:"sigmaEval1"`
	SigmaEval2            *big.Int `json:"sigmaEval2"`
	SigmaEval3            *big.Int `json:"sigmaEval3"`
	ProdPermZetaOmegaEval *big.Int `json:"prodPermZetaOmegaEval"`
}
type VerifyingKey struct {
	DomainSize *big.Int
	NumInputs  *big.Int
	Sigma0     G1Point
	Sigma1     G1Point
	Sigma2     G1Point
	Sigma3     G1Point
	Sigma4     G1Point
	Q1         G1Point
	Q2         G1Point
	Q3         G1Point
	Q4         G1Point
	QM12       G1Point
	QM34       G1Point
	QO         G1Point
	QC         G1Point
	QH1        G1Point
	QH2        G1Point
	QH3        G1Point
	QH4        G1Point
	QEcc       G1Point
}

type EvalDomain struct {
	LogSize     *big.Int
	Size        *big.Int
	SizeInv     *big.Int
	GroupGen    *big.Int
	GroupGenInv *big.Int
}

// EvalData represents the evaluation data.
type EvalData struct {
	VanishEval  ScalarField
	LagrangeOne ScalarField
	PiEval      ScalarField
}
