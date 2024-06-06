package main

import (
	"encoding/hex"
	"fmt"
	"github.com/aakash4dev/espressotxDecoderEth/lib"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"log"
	"math/big"
	"reflect"
	"strings"
)

// ABI of the contract
const contractABI = `[
   {
     "type": "constructor",
     "inputs": [],
     "stateMutability": "nonpayable"
   },
   {
     "type": "function",
     "name": "newFinalizedState",
     "inputs": [
       {
         "name": "newState",
         "type": "tuple",
         "internalType": "struct LightClient.LightClientState",
         "components": [
           {
             "name": "viewNum",
             "type": "uint64",
             "internalType": "uint64"
           },
           {
             "name": "blockHeight",
             "type": "uint64",
             "internalType": "uint64"
           },
           {
             "name": "blockCommRoot",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "feeLedgerComm",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "stakeTableBlsKeyComm",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "stakeTableSchnorrKeyComm",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "stakeTableAmountComm",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "threshold",
             "type": "uint256",
             "internalType": "uint256"
           }
         ]
       },
       {
         "name": "proof",
         "type": "tuple",
         "internalType": "struct IPlonkVerifier.PlonkProof",
         "components": [
           {
             "name": "wire0",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "wire1",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "wire2",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "wire3",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "wire4",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "prodPerm",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "split0",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "split1",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "split2",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "split3",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "split4",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "zeta",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "zetaOmega",
             "type": "tuple",
             "internalType": "struct BN254.G1Point",
             "components": [
               {
                 "name": "x",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               },
               {
                 "name": "y",
                 "type": "uint256",
                 "internalType": "BN254.BaseField"
               }
             ]
           },
           {
             "name": "wireEval0",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "wireEval1",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "wireEval2",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "wireEval3",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "wireEval4",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "sigmaEval0",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "sigmaEval1",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "sigmaEval2",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "sigmaEval3",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           },
           {
             "name": "prodPermZetaOmegaEval",
             "type": "uint256",
             "internalType": "BN254.ScalarField"
           }
         ]
       }
     ],
     "outputs": [],
     "stateMutability": "nonpayable"
   }
 ]`

// ClientState Define the struct based on the JSON schema
type ClientState struct {
	ViewNum                  uint64   `json:"viewNum"`
	BlockHeight              uint64   `json:"blockHeight"`
	BlockCommRoot            *big.Int `json:"blockCommRoot"`
	FeeLedgerComm            *big.Int `json:"feeLedgerComm"`
	StakeTableBlsKeyComm     *big.Int `json:"stakeTableBlsKeyComm"`
	StakeTableSchnorrKeyComm *big.Int `json:"stakeTableSchnorrKeyComm"`
	StakeTableAmountComm     *big.Int `json:"stakeTableAmountComm"`
	Threshold                *big.Int `json:"threshold"`
}

//	type G1Point struct {
//		X *big.Int `json:"x"`
//		Y *big.Int `json:"y"`
//	}

func main() {
	// Example raw transaction input data (replace with your own)
	// this input data is taken from : https://sepolia.etherscan.io/tx/0x0e4ca8973d392997a7f1c887fbe2c200071a476278223859c1666607b2c1d95e
	inputData := "0x409939b70000000000000000000000000000000000000000000000000000000000076cec0000000000000000000000000000000000000000000000000000000000072f3d049bfa31be62bd57a185481ec7c446bb553c2ed175a34011c6557703f8492a610ae8372d30960b2c6ccf8d9dd64493f6659030963ca1449f00f44feb4ba721d60cd5efc510d52630363959fedd2aa72185a98482b46e0b65775023083994f91b1ce1483ffbd1ce894f879a128546d5c77a8758f3a61620c3536b3400ee412d6f00c5dcfcbf351b8264a4e1afbb3ee46c4801fed73713484f4077dd55d6d886c300000000000000000000000000000000000000000000000000000000000000222d81e67f227e7d2efb8c8e1bf04cb7d19d69f513298e8ececcf83fad80d4b1ea1d1cb0cedb08ff72850b83087f3d568b96a34b4d9bf7378bf3def280e0dc37e1060d18b4bfd86f8fcfd4a56b78f2a2498d5f64b2f2b70a0783f702748ebadebc1a62384b3ac9b3126e29765cf300ab686387bfa805a34a8341e4c0261b7802970b91a93852b163fa4484c47f8f2462556654c1d2b4c5381aacef7d22307e683608b4ca996e66dc77c55fc28c0e5d26fd5dc6df50fe36243e27b44e820766d77e20b4c34417bf05655b5584a5b250b6993b4193f1b9e9365750204c7ebd2247cf1faabef5752af83de74c60cacb7b868d2c2859ee2eb374bf05abede4d72e1f782d5261454a2bda265e52cd5f90aeb72fc31f90a945fcec1739461466f691df1328b16ebfb3f742b0edbd4557d3f12e914fa314c154c0f851541789cb2ed434b30c7ea953abac62c2cff11226843de82597e8b0a0f393fd92fc11516cdd688a45200410a0167b7ca4af0b35b3d46ed77d4995d9a607b0d839111a854c44d95d5c2d8a19d3f37682137667fb1766ae39d4a9b39bcbda6e9ddde3c28d52cf0f8c022e71d7f18a203347c0e432c17f71a0fb2ddebeba23d5f48599ddebfc7c27dfbe2be03ee546f3965767fc0d9698a34e967f2838c47cfcd6a6ab218745c368a745257087389ac78883d27355cdcccda6fd030267e6f6e110222552e3caca7e7dfd2307799915d9887401a9bb967d52a1a8f2862d1938c372e2ad486f84153c67ce2db3c181927b15bba955b1cfe7cf52d1af9ccd5b0e27c93fc10ed576cebcbfca1bfb7bbeb17abfdcd2ec2be6dfa4b1cd2252b07d2c5276218df24b1ed0c751ba2f79bf97148a43c4dd0dd56a655f8237043da0653a94747e6736923a89ccf5e027f8b7d9c8c8ef4ffc4d7c8d1489ab0492f5c2bcfb79a9d7dd7d776b0ae073a30ab51c1fc2792355c07396ab6ea3cf8c049bae7a6530e3605b28a51cbfab78302a5ba918464abd08c0f6de432ce891c231dc974054a42b37a4ecdd5b8f7d169818420c15aa05fcb1a6958b156aa1eba804436a597f6805d9787652eabf46e3df0972f1b9e8460ab9c9fdb7e03a61d89295e11b5ac999d50b50701c582d306f0a2afdbe58e2fdd793c351896a0e12aa5c6f9524fdd2dd06c6c1e1fc007e2c70712f081a3caff7e40b7077397789db92bf3356d188b500489ee4ab407013a54b0d2c61806c9e8eb8c62473afe8728ad8a2760dd4a7750147ecf4526d11da9841de1f816697d773928ee8a33224438007a8980cc31afdaf4afbfb17055c1262938b084a0ef42add32dcbc9e5d6566cc841ff27397804f7cf4f6a1c1e44c3492c1d41900656bb55f180a0d10c0b16c557b8be46c39c97c5d4409d2ac619779edabd7130e10e40974f34e33ab34b45bcdc34e7a61245253409bd25e221bcf857a9ae0003f799273b494d5648f723179a7f9b1289934272b5cb5080c29ffc0e49014df00c8f19a202e36e96d317e2e699d211395800c2d63f286fda1eb9e213cd6d1160553ae5a81f3d0eece39f943bf94d725ab31a7b594bff0d798f04e7b07ce82c72ee0160a3bfa494b0d6502a39e49bd0dbb934de102b4557d6668c38a3abd25bc"

	// Decode the hex string to bytes
	inputBytes, err := hex.DecodeString(strings.TrimPrefix(inputData, "0x"))
	if err != nil {
		log.Fatalf("Failed to decode input hex: %v", err)
	}

	// Parse the contract ABI
	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}

	// Method ID is the first 4 bytes of the input data
	methodID := inputBytes[:4]
	// Remaining bytes are the method arguments
	methodArgs := inputBytes[4:]

	// Find the method from the ABI using the method ID
	method, err := parsedABI.MethodById(methodID)
	if err != nil {
		log.Fatalf("Failed to find method by ID: %v", err)
	}

	// Decode the arguments
	args := make(map[string]interface{})
	err = method.Inputs.UnpackIntoMap(args, methodArgs)
	if err != nil {
		log.Fatalf("Failed to unpack arguments: %v", err)
	}

	// Assuming the first argument is the one we are interested in
	stateData := args[method.Inputs[0].Name]
	clientState := DecodeClientState(stateData)
	fmt.Println("State:")
	printFieldsAndValues(clientState)

	// Assuming the second argument is the proof
	proofData := args[method.Inputs[1].Name]
	proof := DecodeProof(proofData)
	fmt.Println("PlonkProof:")
	printFieldsAndValues(proof)

	//vk := GetVKey()

	//valid := VerifyPlonkProof(vk, proof, clientState)
	//if valid {
	//	fmt.Println("Proof is valid!")
	//} else {
	//	fmt.Println("Proof is invalid!")
	//}
}

func DecodeClientState(stateData interface{}) ClientState {

	rv := reflect.ValueOf(stateData)

	viewNum := rv.FieldByName("ViewNum").Interface().(uint64)
	blockHeight := rv.FieldByName("BlockHeight").Interface().(uint64)
	blockCommRoot := rv.FieldByName("BlockCommRoot").Interface().(*big.Int)
	feeLedgerComm := rv.FieldByName("FeeLedgerComm").Interface().(*big.Int)
	stakeTableBlsKeyComm := rv.FieldByName("StakeTableBlsKeyComm").Interface().(*big.Int)
	stakeTableSchnorrKeyComm := rv.FieldByName("StakeTableSchnorrKeyComm").Interface().(*big.Int)
	stakeTableAmountComm := rv.FieldByName("StakeTableAmountComm").Interface().(*big.Int)
	threshold := rv.FieldByName("Threshold").Interface().(*big.Int)

	clientState := ClientState{
		ViewNum:                  viewNum,
		BlockHeight:              blockHeight,
		BlockCommRoot:            blockCommRoot,
		FeeLedgerComm:            feeLedgerComm,
		StakeTableBlsKeyComm:     stakeTableBlsKeyComm,
		StakeTableSchnorrKeyComm: stakeTableSchnorrKeyComm,
		StakeTableAmountComm:     stakeTableAmountComm,
		Threshold:                threshold,
	}

	fmt.Println("ViewNum:", clientState.ViewNum)
	fmt.Println("BlockHeight:", clientState.BlockHeight)

	return clientState
}

func DecodeProof(proofData interface{}) lib.PlonkProof {
	rv := reflect.ValueOf(proofData)

	wire0 := decodeG1Point(rv.FieldByName("Wire0").Interface())
	wire1 := decodeG1Point(rv.FieldByName("Wire1").Interface())
	wire2 := decodeG1Point(rv.FieldByName("Wire2").Interface())
	wire3 := decodeG1Point(rv.FieldByName("Wire3").Interface())
	wire4 := decodeG1Point(rv.FieldByName("Wire4").Interface())
	prodPerm := decodeG1Point(rv.FieldByName("ProdPerm").Interface())
	split0 := decodeG1Point(rv.FieldByName("Split0").Interface())
	split1 := decodeG1Point(rv.FieldByName("Split1").Interface())
	split2 := decodeG1Point(rv.FieldByName("Split2").Interface())
	split3 := decodeG1Point(rv.FieldByName("Split3").Interface())
	split4 := decodeG1Point(rv.FieldByName("Split4").Interface())
	zeta := decodeG1Point(rv.FieldByName("Zeta").Interface())
	zetaOmega := decodeG1Point(rv.FieldByName("ZetaOmega").Interface())
	wireEval0 := rv.FieldByName("WireEval0").Interface().(*big.Int)
	wireEval1 := rv.FieldByName("WireEval1").Interface().(*big.Int)
	wireEval2 := rv.FieldByName("WireEval2").Interface().(*big.Int)
	wireEval3 := rv.FieldByName("WireEval3").Interface().(*big.Int)
	wireEval4 := rv.FieldByName("WireEval4").Interface().(*big.Int)
	sigmaEval0 := rv.FieldByName("SigmaEval0").Interface().(*big.Int)
	sigmaEval1 := rv.FieldByName("SigmaEval1").Interface().(*big.Int)
	sigmaEval2 := rv.FieldByName("SigmaEval2").Interface().(*big.Int)
	sigmaEval3 := rv.FieldByName("SigmaEval3").Interface().(*big.Int)
	prodPermZetaOmegaEval := rv.FieldByName("ProdPermZetaOmegaEval").Interface().(*big.Int)

	proof := lib.PlonkProof{
		Wire0:                 wire0,
		Wire1:                 wire1,
		Wire2:                 wire2,
		Wire3:                 wire3,
		Wire4:                 wire4,
		ProdPerm:              prodPerm,
		Split0:                split0,
		Split1:                split1,
		Split2:                split2,
		Split3:                split3,
		Split4:                split4,
		Zeta:                  zeta,
		ZetaOmega:             zetaOmega,
		WireEval0:             wireEval0,
		WireEval1:             wireEval1,
		WireEval2:             wireEval2,
		WireEval3:             wireEval3,
		WireEval4:             wireEval4,
		SigmaEval0:            sigmaEval0,
		SigmaEval1:            sigmaEval1,
		SigmaEval2:            sigmaEval2,
		SigmaEval3:            sigmaEval3,
		ProdPermZetaOmegaEval: prodPermZetaOmegaEval,
	}
	return proof
}

func decodeG1Point(g1PointData interface{}) lib.G1Point {
	rv := reflect.ValueOf(g1PointData)
	x := rv.FieldByName("X").Interface().(*big.Int)
	y := rv.FieldByName("Y").Interface().(*big.Int)
	return lib.G1Point{
		X: x,
		Y: y,
	}
}

func printFieldsAndValues(i interface{}) {
	val := reflect.ValueOf(i)

	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		typeField := val.Type().Field(i)

		fmt.Printf(" %s : %v\n", typeField.Name, valueField.Interface())
	}
}
