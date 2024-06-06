package lib

//package lib
//
//import (
//	"bytes"
//	"encoding/binary"
//	"errors"
//	"fmt"
//	"math/big"
//)
//
//// Utils.sol
//func reverseEndianness(input *big.Int) *big.Int {
//	// Create masks and a copy of the input
//	mask8, _ := new(big.Int).SetString("FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00", 16)
//	mask16, _ := new(big.Int).SetString("FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000", 16)
//	mask32, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000", 16)
//	mask64, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000", 16)
//
//	v := new(big.Int).Set(input)
//
//	// Perform the bitwise operations as described in the Solidity function
//	v = new(big.Int).Or(
//		new(big.Int).Rsh(new(big.Int).And(v, mask8), 8),
//		new(big.Int).Lsh(new(big.Int).And(v, new(big.Int).Not(mask8)), 8),
//	)
//
//	v = new(big.Int).Or(
//		new(big.Int).Rsh(new(big.Int).And(v, mask16), 16),
//		new(big.Int).Lsh(new(big.Int).And(v, new(big.Int).Not(mask16)), 16),
//	)
//
//	v = new(big.Int).Or(
//		new(big.Int).Rsh(new(big.Int).And(v, mask32), 32),
//		new(big.Int).Lsh(new(big.Int).And(v, new(big.Int).Not(mask32)), 32),
//	)
//
//	v = new(big.Int).Or(
//		new(big.Int).Rsh(new(big.Int).And(v, mask64), 64),
//		new(big.Int).Lsh(new(big.Int).And(v, new(big.Int).Not(mask64)), 64),
//	)
//
//	v = new(big.Int).Or(
//		new(big.Int).Rsh(v, 128),
//		new(big.Int).Lsh(v, 128),
//	)
//
//	return v
//}
//
//// Byteslib.sol
//// Concat concatenates two byte slices.
//func Concat(preBytes, postBytes []byte) []byte {
//	return append(preBytes, postBytes...)
//}
//
//// Slice slices a byte slice from the start index with the specified length.
//func Slice(bytes []byte, start, length uint64) []byte {
//	if uint64(len(bytes)) < start+length {
//		panic("slice_outOfBounds")
//	}
//	return bytes[start : start+length]
//}
//
//// ToAddress converts a byte slice to an address starting from the given index.
//func ToAddress(bytes []byte, start uint64) string {
//	if uint64(len(bytes)) < start+20 {
//		panic("toAddress_outOfBounds")
//	}
//	return fmt.Sprintf("%x", bytes[start:start+20])
//}
//
//// ToUint8 converts a byte slice to a uint8 starting from the given index.
//func ToUint8(bytes []byte, start uint64) uint8 {
//	if uint64(len(bytes)) < start+1 {
//		panic("toUint8_outOfBounds")
//	}
//	return uint8(bytes[start])
//}
//
//// ToUint16 converts a byte slice to a uint16 starting from the given index.
//func ToUint16(bytes []byte, start uint64) uint16 {
//	if uint64(len(bytes)) < start+2 {
//		panic("toUint16_outOfBounds")
//	}
//	return binary.BigEndian.Uint16(bytes[start : start+2])
//}
//
//// ToUint32 converts a byte slice to a uint32 starting from the given index.
//func ToUint32(bytes []byte, start uint64) uint32 {
//	if uint64(len(bytes)) < start+4 {
//		panic("toUint32_outOfBounds")
//	}
//	return binary.BigEndian.Uint32(bytes[start : start+4])
//}
//
//// ToUint64 converts a byte slice to a uint64 starting from the given index.
//func ToUint64(bytes []byte, start uint64) uint64 {
//	if uint64(len(bytes)) < start+8 {
//		panic("toUint64_outOfBounds")
//	}
//	return binary.BigEndian.Uint64(bytes[start : start+8])
//}
//
//// ToUint96 converts a byte slice to a uint96 starting from the given index.
//func ToUint96(bytes []byte, start uint64) *big.Int {
//	if uint64(len(bytes)) < start+12 {
//		panic("toUint96_outOfBounds")
//	}
//	return new(big.Int).SetBytes(bytes[start : start+12])
//}
//
//// ToUint128 converts a byte slice to a uint128 starting from the given index.
//func ToUint128(bytes []byte, start uint64) *big.Int {
//	if uint64(len(bytes)) < start+16 {
//		panic("toUint128_outOfBounds")
//	}
//	return new(big.Int).SetBytes(bytes[start : start+16])
//}
//
//// ToUint256 converts a byte slice to a uint256 starting from the given index.
//func ToUint256(bytes []byte, start uint64) *big.Int {
//	if uint64(len(bytes)) < start+32 {
//		panic("toUint256_outOfBounds")
//	}
//	return new(big.Int).SetBytes(bytes[start : start+32])
//}
//
//// ToBytes32 converts a byte slice to a bytes32 starting from the given index.
//func ToBytes32(bytes []byte, start uint64) [32]byte {
//	if uint64(len(bytes)) < start+32 {
//		panic("toBytes32_outOfBounds")
//	}
//	var result [32]byte
//	copy(result[:], bytes[start:start+32])
//	return result
//}
//
//// Equal compares two byte slices for equality.
//func Equal(preBytes, postBytes []byte) bool {
//	return bytes.Equal(preBytes, postBytes)
//}
//
//// BN254.sol
//// Constants for the BN254 curve
//var (
//	P_MOD, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
//	R_MOD, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
//)
//
//// ScalarField and BaseField are types representing the scalar and base fields in BN254
//type ScalarField = *big.Int
//type BaseField = *big.Int
//
//// P1 returns the generator point of G1
//func P1() G1Point {
//	return G1Point{big.NewInt(1), big.NewInt(2)}
//}
//
//// P2 returns the generator point of G2
//func P2() G2Point {
//	x0, _ := new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
//	x1, _ := new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
//	y0, _ := new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)
//	y1, _ := new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
//	return G2Point{
//		X0: x0,
//		X1: x1,
//		Y0: y0,
//		Y1: y1,
//	}
//}
//
//// Infinity returns the point at infinity on G1
//func Infinity() G1Point {
//	return G1Point{big.NewInt(0), big.NewInt(0)}
//}
//
//// IsInfinity checks if a G1Point is the point at infinity
//func IsInfinity(point G1Point) bool {
//	return point.X.Cmp(big.NewInt(0)) == 0 && point.Y.Cmp(big.NewInt(0)) == 0
//}
//
//// Negate negates a G1Point
//func Negate(p G1Point) G1Point {
//	if IsInfinity(p) {
//		return p
//	}
//	PMod := P_MOD
//	y := new(big.Int).Mod(new(big.Int).Neg(p.Y), PMod)
//	return G1Point{p.X, y}
//}
//
//// NegateScalar negates a scalar field element
//func NegateScalar(fr ScalarField) ScalarField {
//	RMod := R_MOD
//	return new(big.Int).Mod(new(big.Int).Neg(fr), RMod)
//}
//
//// Add adds two G1Points
//func Add(p1, p2 G1Point) (G1Point, error) {
//	if IsInfinity(p1) {
//		return p2, nil
//	}
//	if IsInfinity(p2) {
//		return p1, nil
//	}
//
//	// Point doubling case
//	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 {
//		return Double(p1)
//	}
//
//	// Point addition
//	lambda := new(big.Int).Sub(p2.Y, p1.Y)
//	lambda.Mod(lambda, P_MOD)
//	lambda.Mul(lambda, new(big.Int).ModInverse(new(big.Int).Sub(p2.X, p1.X), P_MOD))
//	lambda.Mod(lambda, P_MOD)
//
//	x3 := new(big.Int).Mul(lambda, lambda)
//	x3.Sub(x3, p1.X)
//	x3.Sub(x3, p2.X)
//	x3.Mod(x3, P_MOD)
//
//	y3 := new(big.Int).Sub(p1.X, x3)
//	y3.Mul(lambda, y3)
//	y3.Sub(y3, p1.Y)
//	y3.Mod(y3, P_MOD)
//
//	return G1Point{x3, y3}, nil
//}
//
//func Mul(x, y *big.Int) *big.Int {
//	return new(big.Int).Mul(x, y)
//}
//
//// Double doubles a G1Point
//func Double(p G1Point) (G1Point, error) {
//	if IsInfinity(p) {
//		return p, nil
//	}
//
//	lambda := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.X, p.X))
//	lambda.Add(lambda, big.NewInt(3))
//	lambda.Mod(lambda, P_MOD)
//	lambda.Mul(lambda, new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), p.Y), P_MOD))
//	lambda.Mod(lambda, P_MOD)
//
//	x3 := new(big.Int).Mul(lambda, lambda)
//	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), p.X))
//	x3.Mod(x3, P_MOD)
//
//	y3 := new(big.Int).Sub(p.X, x3)
//	y3.Mul(lambda, y3)
//	y3.Sub(y3, p.Y)
//	y3.Mod(y3, P_MOD)
//
//	return G1Point{x3, y3}, nil
//}
//
//// ScalarMul multiplies a G1Point by a scalar using double-and-add method
//func ScalarMul(p G1Point, s ScalarField) G1Point {
//	res := Infinity()
//	addend := p
//
//	scalar := s
//	for i := scalar.BitLen(); i >= 0; i-- {
//		res, _ = Double(res)
//		if scalar.Bit(i) == 1 {
//			res, _ = Add(res, addend)
//		}
//	}
//
//	return res
//}
//
//func MultiScalerMul(p []G1Point, s []ScalarField) G1Point {
//	if len(p) != len(s) {
//		panic("MultiScalerMul: p and s must have the same length")
//	}
//
//	res := Infinity()
//	for i := 0; i < len(p); i++ {
//		res, _ = Add(res, ScalarMul(p[i], s[i]))
//	}
//
//	return res
//}
//
//func invert(a *big.Int) *big.Int {
//	return new(big.Int).ModInverse(a, P_MOD)
//}
//
//func validG1Point(p G1Point) bool {
//	if p.X.Cmp(big.NewInt(0)) == 0 && p.Y.Cmp(big.NewInt(0)) == 0 {
//		return true
//	}
//
//	left := new(big.Int).Mul(p.Y, p.Y)
//	left.Mod(left, P_MOD)
//
//	right := new(big.Int).Mul(p.X, p.X)
//	right.Mod(right, P_MOD)
//	right.Mul(right, p.X)
//	right.Add(right, big.NewInt(3))
//	right.Add(right, big.NewInt(4))
//	right.Mod(right, P_MOD)
//
//	return left.Cmp(right) == 0
//}
//func validG2Point(p G2Point) bool {
//	if p.X0.Cmp(big.NewInt(0)) == 0 && p.X1.Cmp(big.NewInt(0)) == 0 && p.Y0.Cmp(big.NewInt(0)) == 0 && p.Y1.Cmp(big.NewInt(0)) == 0 {
//		return true
//	}
//
//	left := new(big.Int).Mul(p.Y0, p.Y0)
//	left.Mod(left, P_MOD)
//
//	right := new(big.Int).Mul(p.X0, p.X0)
//	right.Mod(right, P_MOD)
//	right.Mul(right, p.X0)
//	right.Add(right, big.NewInt(3))
//	right.Add(right, big.NewInt(4))
//	right.Mod(right, P_MOD)
//
//	return left.Cmp(right) == 0
//
//}
//func validScalerField(a *big.Int) bool {
//	return a.Cmp(big.NewInt(0)) >= 0 && a.Cmp(R_MOD) < 0
//}
//
//func NegateG2(p G2Point) G2Point {
//	if p.X0.Cmp(big.NewInt(0)) == 0 && p.X1.Cmp(big.NewInt(0)) == 0 && p.Y0.Cmp(big.NewInt(0)) == 0 && p.Y1.Cmp(big.NewInt(0)) == 0 {
//		return p
//	}
//	PMod := P_MOD
//	y0 := new(big.Int).Mod(new(big.Int).Neg(p.Y0), PMod)
//	y1 := new(big.Int).Mod(new(big.Int).Neg(p.Y1), PMod)
//	return G2Point{p.X0, p.X1, y0, y1}
//}
//func DoubleG2(p G2Point) G2Point {
//	if p.X0.Cmp(big.NewInt(0)) == 0 && p.X1.Cmp(big.NewInt(0)) == 0 && p.Y0.Cmp(big.NewInt(0)) == 0 && p.Y1.Cmp(big.NewInt(0)) == 0 {
//		return p
//	}
//
//	lambda := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.X0, p.X0))
//	lambda.Add(lambda, big.NewInt(3))
//	lambda.Mod(lambda, P_MOD)
//	lambda.Mul(lambda, new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), p.Y0), P_MOD))
//	lambda.Mod(lambda, P_MOD)
//
//	x3 := new(big.Int).Mul(lambda, lambda)
//	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), p.X0))
//	x3.Mod(x3, P_MOD)
//
//	y3 := new(big.Int).Sub(p.X0, x3)
//	y3.Mul(lambda, y3)
//	y3.Sub(y3, p.Y0)
//	y3.Mod(y3, P_MOD)
//
//	return G2Point{x3, p.X1, y3, p.Y1}
//
//}
//
//func AddG2(p1, p2 G2Point) G2Point {
//	if p1.X0.Cmp(p2.X0) == 0 && p1.X1.Cmp(p2.X1) == 0 && p1.Y0.Cmp(p2.Y0) == 0 && p1.Y1.Cmp(p2.Y1) == 0 {
//		return DoubleG2(p1)
//	}
//
//	lambda := new(big.Int).Sub(p2.Y0, p1.Y0)
//	lambda.Mod(lambda, P_MOD)
//	lambda.Mul(lambda, new(big.Int).ModInverse(new(big.Int).Sub(p2.X0, p1.X0), P_MOD))
//	lambda.Mod(lambda, P_MOD)
//
//	x3 := new(big.Int).Mul(lambda, lambda)
//	x3.Sub(x3, p1.X0)
//	x3.Sub(x3, p2.X0)
//	x3.Mod(x3, P_MOD)
//
//	y3 := new(big.Int).Sub(p1.X0, x3)
//	y3.Mul(lambda, y3)
//	y3.Sub(y3, p1.Y0)
//	y3.Mod(y3, P_MOD)
//
//	return G2Point{x3, p2.X1, y3, p2.Y1}
//
//}
//func ScalarMulG2(p G2Point, s ScalarField) G2Point {
//	res := G2Point{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
//	addend := p
//
//	scalar := s
//	for i := scalar.BitLen(); i >= 0; i-- {
//		res = DoubleG2(res)
//		if scalar.Bit(i) == 1 {
//			res = AddG2(res, addend)
//		}
//	}
//
//	return res
//}
//func pairingProd(p1 G1Point, p2 G2Point) *big.Int {
//	if !validG1Point(p1) {
//		panic("pairingProd: invalid G1 point")
//	}
//
//	if !validG2Point(p2) {
//		panic("pairingProd: invalid G2 point")
//	}
//
//	if !validG1Point(Negate(p1)) {
//		panic("pairingProd: invalid G1 point")
//	}
//
//	if !validG2Point(NegateG2(p2)) {
//		panic("pairingProd: invalid G2 point")
//	}
//
//	if !validG1Point(ScalarMul(p1, R_MOD)) {
//		panic("pairingProd: invalid G1 point")
//	}
//
//	if !validG2Point(ScalarMulG2(p2, R_MOD)) {
//		panic("pairingProd: invalid G2 point")
//	}
//
//	return new(big.Int).Exp(
//		new(big.Int).Mul(p2.X0, p2.X1),
//		new(big.Int).Sub(P_MOD, big.NewInt(1)),
//		P_MOD,
//	)
//}
//
//func pairingProd2(p1 G1Point, p2 G2Point) *big.Int {
//	if !validG1Point(p1) {
//		panic("pairingProd2: invalid G1 point")
//	}
//
//	if !validG2Point(p2) {
//		panic("pairingProd2: invalid G2 point")
//	}
//
//	if !validG1Point(Negate(p1)) {
//		panic("pairingProd2: invalid G1 point")
//	}
//
//	if !validG2Point(NegateG2(p2)) {
//		panic("pairingProd2: invalid G2 point")
//	}
//
//	if !validG1Point(ScalarMul(p1, R_MOD)) {
//		panic("pairingProd2: invalid G1 point")
//	}
//
//	if !validG2Point(ScalarMulG2(p2, R_MOD)) {
//		panic("pairingProd2: invalid G2 point")
//	}
//
//	return pairingProd(p1, p2)
//}
//
//func fromLeBytesModOrder(bytes []byte) *big.Int {
//	return new(big.Int).SetBytes(bytes)
//}
//
//func isYNegative(y *big.Int) bool {
//	return y.Bit(0) == 1
//}
//
//func powSmallBase(base, exp, modulus *big.Int) *big.Int {
//	return new(big.Int).Exp(base, exp, modulus)
//}
//
//func g1Serialize(p G1Point) []byte {
//	return Concat(p.X.Bytes(), p.Y.Bytes())
//}
//
//func g1Deserialize(bytes []byte) G1Point {
//	if len(bytes) != 64 {
//		panic("g1Deserialize: invalid input length")
//	}
//
//	return G1Point{
//		X: new(big.Int).SetBytes(bytes[:32]),
//		Y: new(big.Int).SetBytes(bytes[32:]),
//	}
//}
//
//func quadraticResidue(a *big.Int) bool {
//	return new(big.Int).Exp(a, new(big.Int).Div(P_MOD, big.NewInt(2)), P_MOD).Cmp(big.NewInt(1)) == 0
//}
//
//type IPlonkVerifier interface {
//	Verify(verifyingKey VerifyingKey, publicInput []*big.Int, proof PlonkProof, extraTranscriptInitMsg []byte) bool
//}
//
//// PolynomialEval.sol
//
//// newEvalDomain initializes and returns an EvalDomain based on the given domainSize.
//func newEvalDomain(domainSize int) (*EvalDomain, error) {
//	switch domainSize {
//	case 65536:
//		logsize, _ := new(big.Int).SetString("16", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x30, 0x64, 0x1e, 0x0e, 0x92, 0xbe, 0xbe, 0xf8, 0x18, 0x26, 0x8d, 0x66, 0x3b, 0xca, 0xd6, 0xdb, 0xcf, 0xd6, 0xc0, 0x14, 0x91, 0x70, 0xf6, 0xd7, 0xd3, 0x50, 0xb1, 0xb1, 0xfa, 0x6c, 0x10, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x00, 0xee, 0xb2, 0xcb, 0x59, 0x81, 0xed, 0x45, 0x64, 0x9a, 0xbe, 0xbd, 0xe0, 0x81, 0xdc, 0xff, 0x16, 0xc8, 0x60, 0x1d, 0xe4, 0x34, 0x7e, 0x7d, 0xd1, 0x62, 0x8b, 0xa2, 0xda, 0xac, 0x43, 0xb7}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x0b, 0x5d, 0x56, 0xb7, 0x7f, 0xe7, 0x04, 0xe8, 0xe9, 0x23, 0x38, 0xc0, 0x08, 0x2f, 0x37, 0xe0, 0x91, 0x12, 0x64, 0x14, 0xc8, 0x30, 0xe4, 0xc6, 0x92, 0x2d, 0x5a, 0xc8, 0x02, 0xd8, 0x42, 0xd4}),
//		}, nil
//	case 131072:
//		logsize, _ := new(big.Int).SetString("17", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x30, 0x64, 0x36, 0x40, 0xb9, 0xf8, 0x2f, 0x90, 0xe8, 0x3b, 0x69, 0x8e, 0x5e, 0xa6, 0x17, 0x9c, 0x7c, 0x05, 0x54, 0x2e, 0x85, 0x95, 0x33, 0xb4, 0x8b, 0x99, 0x53, 0xa2, 0xf5, 0x36, 0x08, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x1b, 0xf8, 0x2d, 0xeb, 0xa7, 0xd7, 0x49, 0x02, 0xc3, 0x70, 0x8c, 0xc6, 0xe7, 0x0e, 0x61, 0xf3, 0x05, 0x12, 0xec, 0xa9, 0x56, 0x55, 0x21, 0x0e, 0x27, 0x6e, 0x58, 0x58, 0xce, 0x8f, 0x58, 0xe5}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x24, 0x4c, 0xf0, 0x10, 0xc4, 0x3c, 0xa8, 0x72, 0x37, 0xd8, 0xb0, 0x0b, 0xf9, 0xdd, 0x50, 0xc4, 0xc0, 0x1c, 0x7f, 0x08, 0x6b, 0xd4, 0xe8, 0xc9, 0x20, 0xe7, 0x52, 0x51, 0xd9, 0x6f, 0x0d, 0x22}),
//		}, nil
//	case 262144:
//		logsize, _ := new(big.Int).SetString("18", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x30, 0x64, 0x42, 0x59, 0xcd, 0x94, 0xe7, 0xdd, 0x50, 0x45, 0xd7, 0xa2, 0x70, 0x13, 0xb7, 0xfc, 0xd2, 0x1c, 0x9e, 0x3b, 0x7f, 0xa7, 0x52, 0x22, 0xe7, 0xbd, 0xa4, 0x9b, 0x72, 0x9b, 0x04, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x19, 0xdd, 0xbc, 0xaf, 0x3a, 0x8d, 0x46, 0xc1, 0x5c, 0x01, 0x76, 0xfb, 0xb5, 0xb9, 0x5e, 0x4d, 0xc5, 0x70, 0x88, 0xff, 0x13, 0xf4, 0xd1, 0xbd, 0x84, 0xc6, 0xbf, 0xa5, 0x7d, 0xcd, 0xc0, 0xe0}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x03, 0x68, 0x53, 0xf0, 0x83, 0x78, 0x0e, 0x87, 0xf8, 0xd7, 0xc7, 0x1d, 0x11, 0x11, 0x19, 0xc5, 0x7d, 0xbe, 0x11, 0x8c, 0x22, 0xd5, 0xad, 0x70, 0x7a, 0x82, 0x31, 0x74, 0x66, 0xc5, 0x17, 0x4c}),
//		}, nil
//	case 524288:
//		logsize, _ := new(big.Int).SetString("19", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x30, 0x64, 0x48, 0x66, 0x57, 0x63, 0x44, 0x03, 0x84, 0x4b, 0x0e, 0xac, 0x78, 0xca, 0x88, 0x2c, 0xfd, 0x28, 0x43, 0x41, 0xfc, 0xb0, 0x61, 0x5a, 0x15, 0xcf, 0xcd, 0x17, 0xb1, 0x4d, 0x82, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x22, 0x60, 0xe7, 0x24, 0x84, 0x4b, 0xca, 0x52, 0x51, 0x82, 0x93, 0x53, 0x96, 0x8e, 0x49, 0x15, 0x30, 0x52, 0x58, 0x41, 0x83, 0x57, 0x47, 0x3a, 0x5c, 0x1d, 0x59, 0x7f, 0x61, 0x3f, 0x6c, 0xbd}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x06, 0xe4, 0x02, 0xc0, 0xa3, 0x14, 0xfb, 0x67, 0xa1, 0x5c, 0xf8, 0x06, 0x66, 0x4a, 0xe1, 0xb7, 0x22, 0xdb, 0xc0, 0xef, 0xe6, 0x6e, 0x6c, 0x81, 0xd9, 0x8f, 0x99, 0x24, 0xca, 0x53, 0x53, 0x21}),
//		}, nil
//	case 1048576:
//		logsize, _ := new(big.Int).SetString("20", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x30, 0x64, 0x4b, 0x6c, 0x9c, 0x4a, 0x72, 0x16, 0x9e, 0x4d, 0xaa, 0x31, 0x7d, 0x25, 0xf0, 0x45, 0x12, 0xae, 0x15, 0xc5, 0x3b, 0x34, 0xe8, 0xf5, 0xac, 0xd8, 0xe1, 0x55, 0xd0, 0xa6, 0xc1, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x26, 0x12, 0x5d, 0xa1, 0x0a, 0x0e, 0xd0, 0x63, 0x27, 0x50, 0x8a, 0xba, 0x06, 0xd1, 0xe3, 0x03, 0xac, 0x61, 0x66, 0x32, 0xdb, 0xed, 0x34, 0x9f, 0x53, 0x42, 0x2d, 0xa9, 0x53, 0x33, 0x78, 0x57}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x10, 0x0c, 0x33, 0x2d, 0x21, 0x00, 0x89, 0x5f, 0xab, 0x64, 0x73, 0xbc, 0x2c, 0x51, 0xbf, 0xca, 0x52, 0x1f, 0x45, 0xcb, 0x3b, 0xac, 0xa6, 0x26, 0x08, 0x52, 0xa8, 0xfd, 0xe2, 0x6c, 0x91, 0xf3}),
//		}, nil
//	case 32:
//		logsize, _ := new(big.Int).SetString("5", 10)
//		return &EvalDomain{
//			LogSize:     logsize,
//			Size:        big.NewInt(int64(domainSize)),
//			SizeInv:     new(big.Int).SetBytes([]byte{0x2e, 0xe1, 0x2b, 0xff, 0x4a, 0x28, 0x13, 0x28, 0x6a, 0x8d, 0xc3, 0x88, 0xcd, 0x75, 0x4d, 0x9a, 0x3e, 0xf2, 0x49, 0x06, 0x35, 0xeb, 0xa5, 0x0c, 0xb9, 0xc2, 0xe5, 0xe7, 0x50, 0x80, 0x00, 0x01}),
//			GroupGen:    new(big.Int).SetBytes([]byte{0x09, 0xc5, 0x32, 0xc6, 0x30, 0x6b, 0x93, 0xd2, 0x96, 0x78, 0x20, 0x0d, 0x47, 0xc0, 0xb2, 0xa9, 0x9c, 0x18, 0xd5, 0x1b, 0x83, 0x8e, 0xeb, 0x1d, 0x3e, 0xed, 0x4c, 0x53, 0x3b, 0xb5, 0x12, 0xd0}),
//			GroupGenInv: new(big.Int).SetBytes([]byte{0x27, 0x24, 0x71, 0x36, 0x03, 0xbf, 0xbd, 0x79, 0x0a, 0xea, 0xf3, 0xe7, 0xdf, 0x25, 0xd8, 0xe7, 0xef, 0x8f, 0x31, 0x13, 0x34, 0x90, 0x5b, 0x4d, 0x8c, 0x99, 0x98, 0x0c, 0xf2, 0x10, 0x97, 0x9d}),
//		}, nil
//	default:
//		return nil, errors.New("unsupported degree")
//	}
//}
//
//// evaluateVanishingPoly evaluates the vanishing polynomial at the given zeta.
//func evaluateVanishingPoly(domain *EvalDomain, zeta *big.Int) *big.Int {
//	p := R_MOD
//	res := new(big.Int)
//
//	// Convert LogSize to an integer if it is safe to do so
//	logSize := new(big.Int).Set(domain.LogSize)
//	if !logSize.IsInt64() {
//		panic("LogSize is too large to convert to int")
//	}
//	loopCount := int(logSize.Int64())
//
//	if zeta.Cmp(big.NewInt(0)) == 0 {
//		res.Sub(p, big.NewInt(1))
//	} else {
//		res.Set(zeta)
//		for i := 0; i < loopCount; i++ {
//			res.Mul(res, res).Mod(res, p)
//		}
//		res.Sub(res, big.NewInt(1))
//	}
//
//	return res
//}
//
//// Invert calculates the modular inverse of a ScalarField element.
//func Invert(a ScalarField) ScalarField {
//	return new(big.Int).ModInverse(a, R_MOD)
//}
//
//// evaluateLagrangeOne evaluates the Lagrange polynomial at one.
//func evaluateLagrangeOne(domain *EvalDomain, zeta, vanishEval ScalarField) ScalarField {
//	p := R_MOD
//	divisor := new(big.Int)
//	vanishEvalMulSizeInv := new(big.Int).Set(domain.SizeInv)
//
//	if vanishEval.Cmp(big.NewInt(0)) == 0 {
//		return big.NewInt(0)
//	}
//
//	vanishEvalMulSizeInv.Mul(vanishEval, vanishEvalMulSizeInv).Mod(vanishEvalMulSizeInv, p)
//
//	if zeta.Cmp(big.NewInt(0)) == 0 {
//		divisor.Sub(p, big.NewInt(1))
//	} else {
//		divisor.Sub(zeta, big.NewInt(1))
//	}
//
//	divisor = Invert(divisor)
//	res := new(big.Int).Mul(vanishEvalMulSizeInv, divisor).Mod(vanishEvalMulSizeInv, p)
//	return res
//}
//
//// EvaluatePiPoly evaluates the Pi polynomial.
//func EvaluatePiPoly(domain *EvalDomain, pi []*big.Int, zeta, vanishEval ScalarField) ScalarField {
//	if vanishEval.Cmp(big.NewInt(0)) == 0 {
//		return big.NewInt(0)
//	}
//
//	p := R_MOD
//	length := len(pi)
//	var ithLagrange, ithDivisor, tmp, divisorProd ScalarField
//	vanishEvalDivN := new(big.Int).Mul(vanishEval, domain.SizeInv)
//	vanishEvalDivN.Mod(vanishEvalDivN, p)
//	divisors := make([]*big.Int, length)
//	localDomainElements, _ := DomainElements(domain, length)
//
//	divisorProd = big.NewInt(1)
//
//	for i := 0; i < length; i++ {
//		tmp = localDomainElements[i]
//		ithDivisor = new(big.Int).Add(zeta, new(big.Int).Neg(tmp))
//		ithDivisor.Mod(ithDivisor, p)
//		divisorProd.Mul(divisorProd, ithDivisor)
//		divisorProd.Mod(divisorProd, p)
//		divisors[i] = ithDivisor
//	}
//
//	divisorProd = Invert(divisorProd)
//
//	res := big.NewInt(0)
//
//	for i := 0; i < length; i++ {
//		tmp = localDomainElements[i]
//		ithLagrange = new(big.Int).Mul(vanishEvalDivN, tmp)
//		ithLagrange.Mod(ithLagrange, p)
//		ithLagrange.Mul(ithLagrange, divisorProd)
//		ithLagrange.Mod(ithLagrange, p)
//
//		for j := 0; j < length; j++ {
//			if i != j {
//				ithDivisor = divisors[j]
//				ithLagrange.Mul(ithLagrange, ithDivisor)
//				ithLagrange.Mod(ithLagrange, p)
//			}
//		}
//
//		tmp = pi[i]
//		ithLagrange.Mul(ithLagrange, tmp)
//		ithLagrange.Mod(ithLagrange, p)
//		res.Add(res, ithLagrange)
//		res.Mod(res, p)
//	}
//
//	return res
//}
//
//// DomainElements generates the domain elements for a given length.
//func DomainElements(domain *EvalDomain, length int) ([]*big.Int, error) {
//	if big.NewInt(int64(length)).Cmp(domain.Size) > 0 {
//		return nil, errors.New("InvalidPolyEvalArgs")
//	}
//
//	elements := make([]*big.Int, length)
//	groupGen := domain.GroupGen
//	tmp := big.NewInt(1)
//	p := R_MOD
//
//	elements[0] = new(big.Int).Set(tmp)
//
//	for i := 1; i < length; i++ {
//		tmp.Mul(tmp, groupGen)
//		tmp.Mod(tmp, p)
//		elements[i] = new(big.Int).Set(tmp)
//	}
//
//	return elements, nil
//}
//
//// EvalDataGen generates evaluation data for the given zeta and publicInput.
//func EvalDataGen(domain *EvalDomain, zeta ScalarField, publicInput []*big.Int) (*EvalData, error) {
//	vanishEval := evaluateVanishingPoly(domain, zeta)
//	lagrangeOne := evaluateLagrangeOne(domain, zeta, vanishEval)
//	piEval := EvaluatePiPoly(domain, publicInput, zeta, vanishEval)
//
//	evalData := &EvalData{
//		VanishEval:  vanishEval,
//		LagrangeOne: lagrangeOne,
//		PiEval:      piEval,
//	}
//	return evalData, nil
//}
//
//// LightClientStateUpdateVK.sol
//func GetVKey() VerifyingKey {
//	vk := VerifyingKey{
//		DomainSize: big.NewInt(1048576),
//		NumInputs:  big.NewInt(8),
//		Sigma0: G1Point{
//			X: big.NewInt(14829590452951582429597937921803746951066352088554415416011470961765685672755),
//			Y: big.NewInt(1640805128987262135097000798716519252415689101125171714241944191382225430588),
//		},
//		Sigma1: G1Point{
//			X: big.NewInt(18274068123557654431658802492586722727412966290987193881329212617379409092827),
//			Y: big.NewInt(15262267645961173197854134224641529185383299058832029120242801083020131756400),
//		},
//		Sigma2: G1Point{
//			X: big.NewInt(3546893388503598029379371535595161595693832489221556391602992086886519831449),
//			Y: big.NewInt(5372901058006419475432857030090030698039020632248561039251432764657711254637),
//		},
//		Sigma3: G1Point{
//			X: big.NewInt(8928358756130581276782896781228211285855331943263768176288185111880065377829),
//			Y: big.NewInt(11296094221230007321906902566798665556326310712938157478561243271436961185939),
//		},
//		Sigma4: G1Point{
//			X: big.NewInt(4270203435103829510210885065469080215759206247600073141969144340825736456361),
//			Y: big.NewInt(18435513468464898350668089458023802596061834199836906544891249686171357011496),
//		},
//		Q1: G1Point{
//			X: big.NewInt(1353825928133056546105071835787168542506364373349693671191581615121126233747),
//			Y: big.NewInt(14552181871867089243248249259028502752341497337283269364895091407532060232707),
//		},
//		Q2: G1Point{
//			X: big.NewInt(16134962525970404894447932095148604805089607916596239986859009518831961541095),
//			Y: big.NewInt(12912418721630015879588720063744969517312801940994098982636356180615148009133),
//		},
//		Q3: G1Point{
//			X: big.NewInt(10367884953135327072589416694300506531675903043698271118039737017003907416548),
//			Y: big.NewInt(18645767054976951986441477674607729822362900191642269701059692086595011309617),
//		},
//		Q4: G1Point{
//			X: big.NewInt(20290438753634591112566805159744566085943118086910415955566637541975611306568),
//			Y: big.NewInt(3616081350190366687413620745033189240584091802830669829058164649134460203062),
//		},
//		QM12: G1Point{
//			X: big.NewInt(1392866654032974419818610994350340752885270300830841653620814131913125942809),
//			Y: big.NewInt(7926323714312408409342288501031785033608020789818750772083444352168852620309),
//		},
//		QM34: G1Point{
//			X: big.NewInt(3791333556380290364066652753532128031853997955294626527563616698625259260872),
//			Y: big.NewInt(3628907676439037794810640678014156959914018154448361319066535585239352845219),
//		},
//		QO: G1Point{
//			X: big.NewInt(7288452744039439153187019986732880627393606422995836790888938928792979430332),
//			Y: big.NewInt(3898946817206780988021496513282121271248375416352393169747615149428446748796),
//		},
//		QC: G1Point{
//			X: big.NewInt(20482389538634884293964815753989066984137903177461009416710382582511144614720),
//			Y: big.NewInt(11258994014172499578597433237341729986035258019178718124058091521884134834133),
//		},
//		QH1: G1Point{
//			X: big.NewInt(6452329770023103857611525837563150030587644522618711966359232731854161969093),
//			Y: big.NewInt(6635683706001669495270751033107447145849321869191941901164391368358042033363),
//		},
//		QH2: G1Point{
//			X: big.NewInt(18852624756618899688471924454580455174040214747122588704978836212290318639012),
//			Y: big.NewInt(19668150013698798224912707568562000682376208453509380984273539880691910555900),
//		},
//		QH3: G1Point{
//			X: big.NewInt(2897648376529441855171451962918729606513806930163982507283513591881780437542),
//			Y: big.NewInt(18058066682160117591143604241687402897699656641104339334068174388078565105166),
//		},
//		QH4: G1Point{
//			X: big.NewInt(8311780877242981974134745557347343806199562160806780762496164569715285508665),
//			Y: big.NewInt(9739465744057100599476346315622632649775803938784339749244299845794851098068),
//		},
//		QEcc: G1Point{
//			X: big.NewInt(16504816536031923515595107276719833176967746018194462214393291822653673414274),
//			Y: big.NewInt(20309550876545766116130682111350015544103338784776768395329281357767924326613),
//		},
//	}
//	return vk
//}
//
//// Transcript.sol
//type TranscriptData struct {
//	Transcript []byte
//	State      [32]byte
//}
