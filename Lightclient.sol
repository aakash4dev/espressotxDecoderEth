// SPDX-License-Identifier: MIT
pragma solidity <0.9.0 >=0.8.0 ^0.8.0 ^0.8.20;
pragma experimental ABIEncoderV2;

library Utils {
    function reverseEndianness(uint256 input) internal pure returns (uint256 v) {
        v = input;

        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        v = (v >> 128) | (v << 128);
    }
}

interface IERC1822Proxiable {
    function proxiableUUID() external view returns (bytes32);
}

interface IBeacon {
    function implementation() external view returns (address);
}

library Address {

    error AddressInsufficientBalance(address account);

    error AddressEmptyCode(address target);

    error FailedInnerCall();

    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert AddressInsufficientBalance(address(this));
        }

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert FailedInnerCall();
        }
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {

            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    function _revert(bytes memory returndata) private pure {

        if (returndata.length > 0) {

            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedInnerCall();
        }
    }
}

library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {

        assembly {
            r.slot := store.slot
        }
    }

    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {

        assembly {
            r.slot := slot
        }
    }

    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {

        assembly {
            r.slot := store.slot
        }
    }
}

abstract contract Initializable {

    struct InitializableStorage {

        uint64 _initialized;

        bool _initializing;
    }

    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    error InvalidInitialization();

    error NotInitializing();

    event Initialized(uint64 version);

    modifier initializer() {

        InitializableStorage storage $ = _getInitializableStorage();

        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    modifier reinitializer(uint64 version) {

        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    function _disableInitializers() internal virtual {

        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}

library BytesLib {
    function concat(
        bytes memory _preBytes,
        bytes memory _postBytes
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory tempBytes;

        assembly {

            tempBytes := mload(0x40)

            let length := mload(_preBytes)
            mstore(tempBytes, length)

            let mc := add(tempBytes, 0x20)

            let end := add(mc, length)

            for {

                let cc := add(_preBytes, 0x20)
            } lt(mc, end) {

                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {

                mstore(mc, mload(cc))
            }

            length := mload(_postBytes)
            mstore(tempBytes, add(length, mload(tempBytes)))

            mc := end

            end := add(mc, length)

            for {
                let cc := add(_postBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            mstore(0x40, and(
              add(add(end, iszero(add(length, mload(_preBytes)))), 31),
              not(31)
            ))
        }

        return tempBytes;
    }

    function concatStorage(bytes storage _preBytes, bytes memory _postBytes) internal {
        assembly {

            let fslot := sload(_preBytes.slot)

            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)
            let newlength := add(slength, mlength)

            switch add(lt(slength, 32), lt(newlength, 32))
            case 2 {

                sstore(
                    _preBytes.slot,

                    add(

                        fslot,
                        add(
                            mul(
                                div(

                                    mload(add(_postBytes, 0x20)),

                                    exp(0x100, sub(32, mlength))
                                ),

                                exp(0x100, sub(32, newlength))
                            ),

                            mul(mlength, 2)
                        )
                    )
                )
            }
            case 1 {

                mstore(0x0, _preBytes.slot)
                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                let submod := sub(32, slength)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(
                    sc,
                    add(
                        and(
                            fslot,
                            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
                        ),
                        and(mload(mc), mask)
                    )
                )

                for {
                    mc := add(mc, 0x20)
                    sc := add(sc, 1)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
            default {

                mstore(0x0, _preBytes.slot)

                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                let slengthmod := mod(slength, 32)
                let mlengthmod := mod(mlength, 32)
                let submod := sub(32, slengthmod)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(sc, add(sload(sc), and(mload(mc), mask)))

                for {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
        }
    }

    function slice(
        bytes memory _bytes,
        uint256 _start,
        uint256 _length
    )
        internal
        pure
        returns (bytes memory)
    {
        require(_length + 31 >= _length, "slice_overflow");
        require(_bytes.length >= _start + _length, "slice_outOfBounds");

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {

                tempBytes := mload(0x40)

                let lengthmod := and(_length, 31)

                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {

                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                mstore(0x40, and(add(mc, 31), not(31)))
            }

            default {
                tempBytes := mload(0x40)

                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    function toAddress(bytes memory _bytes, uint256 _start) internal pure returns (address) {
        require(_bytes.length >= _start + 20, "toAddress_outOfBounds");
        address tempAddress;

        assembly {
            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)
        }

        return tempAddress;
    }

    function toUint8(bytes memory _bytes, uint256 _start) internal pure returns (uint8) {
        require(_bytes.length >= _start + 1 , "toUint8_outOfBounds");
        uint8 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

        return tempUint;
    }

    function toUint16(bytes memory _bytes, uint256 _start) internal pure returns (uint16) {
        require(_bytes.length >= _start + 2, "toUint16_outOfBounds");
        uint16 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x2), _start))
        }

        return tempUint;
    }

    function toUint32(bytes memory _bytes, uint256 _start) internal pure returns (uint32) {
        require(_bytes.length >= _start + 4, "toUint32_outOfBounds");
        uint32 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x4), _start))
        }

        return tempUint;
    }

    function toUint64(bytes memory _bytes, uint256 _start) internal pure returns (uint64) {
        require(_bytes.length >= _start + 8, "toUint64_outOfBounds");
        uint64 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x8), _start))
        }

        return tempUint;
    }

    function toUint96(bytes memory _bytes, uint256 _start) internal pure returns (uint96) {
        require(_bytes.length >= _start + 12, "toUint96_outOfBounds");
        uint96 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0xc), _start))
        }

        return tempUint;
    }

    function toUint128(bytes memory _bytes, uint256 _start) internal pure returns (uint128) {
        require(_bytes.length >= _start + 16, "toUint128_outOfBounds");
        uint128 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x10), _start))
        }

        return tempUint;
    }

    function toUint256(bytes memory _bytes, uint256 _start) internal pure returns (uint256) {
        require(_bytes.length >= _start + 32, "toUint256_outOfBounds");
        uint256 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x20), _start))
        }

        return tempUint;
    }

    function toBytes32(bytes memory _bytes, uint256 _start) internal pure returns (bytes32) {
        require(_bytes.length >= _start + 32, "toBytes32_outOfBounds");
        bytes32 tempBytes32;

        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes32;
    }

    function equal(bytes memory _preBytes, bytes memory _postBytes) internal pure returns (bool) {
        bool success = true;

        assembly {
            let length := mload(_preBytes)

            switch eq(length, mload(_postBytes))
            case 1 {

                let cb := 1

                let mc := add(_preBytes, 0x20)
                let end := add(mc, length)

                for {
                    let cc := add(_postBytes, 0x20)

                } eq(add(lt(mc, end), cb), 2) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {

                    if iszero(eq(mload(mc), mload(cc))) {

                        success := 0
                        cb := 0
                    }
                }
            }
            default {

                success := 0
            }
        }

        return success;
    }

    function equalStorage(
        bytes storage _preBytes,
        bytes memory _postBytes
    )
        internal
        view
        returns (bool)
    {
        bool success = true;

        assembly {

            let fslot := sload(_preBytes.slot)

            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)

            switch eq(slength, mlength)
            case 1 {

                if iszero(iszero(slength)) {
                    switch lt(slength, 32)
                    case 1 {

                        fslot := mul(div(fslot, 0x100), 0x100)

                        if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {

                            success := 0
                        }
                    }
                    default {

                        let cb := 1

                        mstore(0x0, _preBytes.slot)
                        let sc := keccak256(0x0, 0x20)

                        let mc := add(_postBytes, 0x20)
                        let end := add(mc, mlength)

                        for {} eq(add(lt(mc, end), cb), 2) {
                            sc := add(sc, 1)
                            mc := add(mc, 0x20)
                        } {
                            if iszero(eq(sload(sc), mload(mc))) {

                                success := 0
                                cb := 0
                            }
                        }
                    }
                }
            }
            default {

                success := 0
            }
        }

        return success;
    }
}

library BN254 {

    type ScalarField is uint256;

    type BaseField is uint256;

    uint256 public constant P_MOD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant R_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct G1Point {
        BaseField x;
        BaseField y;
    }

    struct G2Point {
        BaseField x0;
        BaseField x1;
        BaseField y0;
        BaseField y1;
    }

    function P1() internal pure returns (G1Point memory) {
        return G1Point(BaseField.wrap(1), BaseField.wrap(2));
    }

    function P2() internal pure returns (G2Point memory) {
        return G2Point({
            x0: BaseField.wrap(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
            x1: BaseField.wrap(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2),
            y0: BaseField.wrap(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
            y1: BaseField.wrap(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
        });
    }

    function infinity() internal pure returns (G1Point memory) {
        return G1Point(BaseField.wrap(0), BaseField.wrap(0));
    }

    function isInfinity(G1Point memory point) internal pure returns (bool result) {
        assembly {
            let x := mload(point)
            let y := mload(add(point, 0x20))
            result := and(iszero(x), iszero(y))
        }
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (isInfinity(p)) {
            return p;
        }
        return G1Point(p.x, BaseField.wrap(P_MOD - (BaseField.unwrap(p.y) % P_MOD)));
    }

    function negate(ScalarField fr) internal pure returns (ScalarField res) {
        return ScalarField.wrap(R_MOD - (ScalarField.unwrap(fr) % R_MOD));
    }

    function negate(BaseField fq) internal pure returns (BaseField) {
        return BaseField.wrap(P_MOD - (BaseField.unwrap(fq) % P_MOD));
    }

    function add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = BaseField.unwrap(p1.x);
        input[1] = BaseField.unwrap(p1.y);
        input[2] = BaseField.unwrap(p2.x);
        input[3] = BaseField.unwrap(p2.y);
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)

            switch success
            case 0 { revert(0, 0) }
        }
        require(success, "Bn254: group addition failed!");
    }

    function add(BaseField a, BaseField b) internal pure returns (BaseField) {
        return BaseField.wrap(addmod(BaseField.unwrap(a), BaseField.unwrap(b), P_MOD));
    }

    function add(ScalarField a, ScalarField b) internal pure returns (ScalarField) {
        return ScalarField.wrap(addmod(ScalarField.unwrap(a), ScalarField.unwrap(b), R_MOD));
    }

    function mul(BaseField a, BaseField b) internal pure returns (BaseField) {
        return BaseField.wrap(mulmod(BaseField.unwrap(a), BaseField.unwrap(b), P_MOD));
    }

    function mul(ScalarField a, ScalarField b) internal pure returns (ScalarField) {
        return ScalarField.wrap(mulmod(ScalarField.unwrap(a), ScalarField.unwrap(b), R_MOD));
    }

    function scalarMul(G1Point memory p, ScalarField s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = BaseField.unwrap(p.x);
        input[1] = BaseField.unwrap(p.y);
        input[2] = ScalarField.unwrap(s);
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)

            switch success
            case 0 { revert(0, 0) }
        }
        require(success, "Bn254: scalar mul failed!");
    }

    function multiScalarMul(G1Point[] memory bases, ScalarField[] memory scalars)
        internal
        view
        returns (G1Point memory r)
    {
        require(scalars.length == bases.length, "MSM error: length does not match");

        r = scalarMul(bases[0], scalars[0]);
        for (uint256 i = 1; i < scalars.length; i++) {
            r = add(r, scalarMul(bases[i], scalars[i]));
        }
    }

    function invert(ScalarField fr) internal view returns (ScalarField output) {
        bool success;
        uint256 p = R_MOD;
        assembly {
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), fr)
            mstore(add(mPtr, 0x80), sub(p, 2))
            mstore(add(mPtr, 0xa0), p)
            success := staticcall(gas(), 0x05, mPtr, 0xc0, 0x00, 0x20)
            output := mload(0x00)
        }
        require(success, "Bn254: pow precompile failed!");
    }

    function validateG1Point(G1Point memory point) internal pure {
        bool isWellFormed;
        uint256 p = P_MOD;
        if (isInfinity(point)) {
            return;
        }
        assembly {
            let x := mload(point)
            let y := mload(add(point, 0x20))

            isWellFormed :=
                and(
                    and(lt(x, p), lt(y, p)),
                    eq(mulmod(y, y, p), addmod(mulmod(x, mulmod(x, x, p), p), 3, p))
                )
        }
        require(isWellFormed, "Bn254: invalid G1 point");
    }

    function validateScalarField(ScalarField fr) internal pure {
        bool isValid;
        assembly {
            isValid := lt(fr, R_MOD)
        }
        require(isValid, "Bn254: invalid scalar field");
    }

    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        uint256 out;
        bool success;
        assembly {
            let mPtr := mload(0x40)
            mstore(mPtr, mload(a1))
            mstore(add(mPtr, 0x20), mload(add(a1, 0x20)))
            mstore(add(mPtr, 0x40), mload(add(a2, 0x20)))
            mstore(add(mPtr, 0x60), mload(a2))
            mstore(add(mPtr, 0x80), mload(add(a2, 0x60)))
            mstore(add(mPtr, 0xa0), mload(add(a2, 0x40)))

            mstore(add(mPtr, 0xc0), mload(b1))
            mstore(add(mPtr, 0xe0), mload(add(b1, 0x20)))
            mstore(add(mPtr, 0x100), mload(add(b2, 0x20)))
            mstore(add(mPtr, 0x120), mload(b2))
            mstore(add(mPtr, 0x140), mload(add(b2, 0x60)))
            mstore(add(mPtr, 0x160), mload(add(b2, 0x40)))
            success := staticcall(gas(), 8, mPtr, 0x180, 0x00, 0x20)
            out := mload(0x00)
        }
        require(success,    "Bn254: Pairing check failed!");
        return (out != 0);
    }

    function fromLeBytesModOrder(bytes memory leBytes) internal pure returns (uint256 ret) {
        for (uint256 i = 0; i < leBytes.length; i++) {
            ret = mulmod(ret, 256, R_MOD);
            ret = addmod(ret, uint256(uint8(leBytes[leBytes.length - 1 - i])), R_MOD);
        }
    }

    function isYNegative(G1Point memory point) internal pure returns (bool) {
        return (BaseField.unwrap(point.y) << 1) < P_MOD;
    }

    function powSmall(uint256 base, uint256 exponent, uint256 modulus)
        internal
        pure
        returns (uint256)
    {
        uint256 result = 1;
        uint256 input = base;
        uint256 count = 1;

        assembly {
            let endpoint := add(exponent, 0x01)
            for { } lt(count, endpoint) { count := add(count, count) } {
                if and(exponent, count) { result := mulmod(result, input, modulus) }
                input := mulmod(input, input, modulus)
            }
        }

        return result;
    }

    function g1Serialize(G1Point memory point) internal pure returns (bytes memory) {
        uint256 mask = 0;

        if (isInfinity(point)) {
            mask |= 0x4000000000000000000000000000000000000000000000000000000000000000;
        }

        if (!isYNegative(point)) {
            mask = 0x8000000000000000000000000000000000000000000000000000000000000000;
        }

        return abi.encodePacked(Utils.reverseEndianness(BaseField.unwrap(point.x) | mask));
    }

    function g1Deserialize(bytes32 input) internal view returns (G1Point memory point) {
        uint256 mask = 0x4000000000000000000000000000000000000000000000000000000000000000;
        uint256 xVal = Utils.reverseEndianness(uint256(input));
        bool isQuadraticResidue;
        bool isYPositive;
        if (xVal & mask != 0) {

            point = infinity();
        } else {

            mask = 0x8000000000000000000000000000000000000000000000000000000000000000;
            isYPositive = (xVal & mask != 0);

            mask = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
            xVal &= mask;

            BaseField x = BaseField.wrap(xVal);
            BaseField y = add(mul(mul(x, x), x), BaseField.wrap(3));
            (isQuadraticResidue, y) = quadraticResidue(y);

            require(isQuadraticResidue, "deser fail: not on curve");

            if (isYPositive) {
                y = negate(y);
            }
            point = G1Point(x, y);
        }
    }

    function quadraticResidue(BaseField x)
        internal
        view
        returns (bool isQuadraticResidue, BaseField)
    {
        bool success;
        uint256 a;

        uint256 e = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;
        uint256 p = P_MOD;

        assembly {

            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), x)
            mstore(add(mPtr, 0x80), e)
            mstore(add(mPtr, 0xa0), p)
            success := staticcall(gas(), 0x05, mPtr, 0xc0, 0x00, 0x20)
            a := mload(0x00)
        }
        require(success, "pow precompile call failed!");

        if (a << 1 > p) {
            a = p - a;
        }

        e = mulmod(a, a, p);

        isQuadraticResidue = (e == BaseField.unwrap(x));
        return (isQuadraticResidue, BaseField.wrap(a));
    }
}

abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {

    struct OwnableStorage {
        address _owner;
    }

    bytes32 private constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    error OwnableUnauthorizedAccount(address account);

    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function __Ownable_init(address initialOwner) internal onlyInitializing {
        __Ownable_init_unchained(initialOwner);
    }

    function __Ownable_init_unchained(address initialOwner) internal onlyInitializing {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        address oldOwner = $._owner;
        $._owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}



//todo: continue from here ///////////////////////////////////////////////////////////////////
interface IPlonkVerifier {

    struct PlonkProof {
            BN254.G1Point wire0;
            BN254.G1Point wire1;
            BN254.G1Point wire2;
            BN254.G1Point wire3;
            BN254.G1Point wire4;

            BN254.G1Point prodPerm;

            BN254.G1Point split0;
            BN254.G1Point split1;
            BN254.G1Point split2;
            BN254.G1Point split3;
            BN254.G1Point split4;

            BN254.G1Point zeta;

            BN254.G1Point zetaOmega;

            BN254.ScalarField wireEval0;
            BN254.ScalarField wireEval1;
            BN254.ScalarField wireEval2;
            BN254.ScalarField wireEval3;
            BN254.ScalarField wireEval4;

            BN254.ScalarField sigmaEval0;
            BN254.ScalarField sigmaEval1;
            BN254.ScalarField sigmaEval2;
            BN254.ScalarField sigmaEval3;

            BN254.ScalarField prodPermZetaOmegaEval;
        }

    struct VerifyingKey {
        uint256 domainSize;
        uint256 numInputs;

        BN254.G1Point sigma0;
        BN254.G1Point sigma1;
        BN254.G1Point sigma2;
        BN254.G1Point sigma3;
        BN254.G1Point sigma4;

        BN254.G1Point q1;
        BN254.G1Point q2;
        BN254.G1Point q3;
        BN254.G1Point q4;

        BN254.G1Point qM12;

        BN254.G1Point qM34;

        BN254.G1Point qO;

        BN254.G1Point qC;

        BN254.G1Point qH1;

        BN254.G1Point qH2;

        BN254.G1Point qH3;

        BN254.G1Point qH4;

        BN254.G1Point qEcc;
    }

    function verify(
        VerifyingKey memory verifyingKey,
        uint256[] memory publicInput,
        PlonkProof memory proof,
        bytes memory extraTranscriptInitMsg
    ) external view returns (bool);
}

library PolynomialEval {

    error UnsupportedDegree();

    error InvalidPolyEvalArgs();

    struct EvalDomain {
        uint256 logSize;
        uint256 size;
        uint256 sizeInv;
        uint256 groupGen;
        uint256 groupGenInv;
    }

    struct EvalData {
        BN254.ScalarField vanishEval;
        BN254.ScalarField lagrangeOne;
        BN254.ScalarField piEval;
    }

    function newEvalDomain(uint256 domainSize) internal pure returns (EvalDomain memory) {
        if (domainSize == 65536) {
            return EvalDomain(
                16,
                domainSize,
                0x30641e0e92bebef818268d663bcad6dbcfd6c0149170f6d7d350b1b1fa6c1001,
                0x00eeb2cb5981ed45649abebde081dcff16c8601de4347e7dd1628ba2daac43b7,
                0x0b5d56b77fe704e8e92338c0082f37e091126414c830e4c6922d5ac802d842d4
            );
        } else if (domainSize == 131072) {
            return EvalDomain(
                17,
                domainSize,
                0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801,
                0x1bf82deba7d74902c3708cc6e70e61f30512eca95655210e276e5858ce8f58e5,
                0x244cf010c43ca87237d8b00bf9dd50c4c01c7f086bd4e8c920e75251d96f0d22
            );
        } else if (domainSize == 262144) {
            return EvalDomain(
                18,
                domainSize,
                0x30644259cd94e7dd5045d7a27013b7fcd21c9e3b7fa75222e7bda49b729b0401,
                0x19ddbcaf3a8d46c15c0176fbb5b95e4dc57088ff13f4d1bd84c6bfa57dcdc0e0,
                0x36853f083780e87f8d7c71d111119c57dbe118c22d5ad707a82317466c5174c
            );
        } else if (domainSize == 524288) {
            return EvalDomain(
                19,
                domainSize,
                0x3064486657634403844b0eac78ca882cfd284341fcb0615a15cfcd17b14d8201,
                0x2260e724844bca5251829353968e4915305258418357473a5c1d597f613f6cbd,
                0x6e402c0a314fb67a15cf806664ae1b722dbc0efe66e6c81d98f9924ca535321
            );
        } else if (domainSize == 1048576) {
            return EvalDomain(
                20,
                domainSize,
                0x30644b6c9c4a72169e4daa317d25f04512ae15c53b34e8f5acd8e155d0a6c101,
                0x26125da10a0ed06327508aba06d1e303ac616632dbed349f53422da953337857,
                0x100c332d2100895fab6473bc2c51bfca521f45cb3baca6260852a8fde26c91f3
            );
        }
        if (domainSize == 32) {

            return EvalDomain(
                5,
                domainSize,
                0x2ee12bff4a2813286a8dc388cd754d9a3ef2490635eba50cb9c2e5e750800001,
                0x9c532c6306b93d29678200d47c0b2a99c18d51b838eeb1d3eed4c533bb512d0,
                0x2724713603bfbd790aeaf3e7df25d8e7ef8f311334905b4d8c99980cf210979d
            );
        } else {
            revert UnsupportedDegree();
        }
    }

    // reached here
    function evaluateVanishingPoly(EvalDomain memory self, uint256 zeta)
        internal
        pure
        returns (uint256 res)
    {
        uint256 p = BN254.R_MOD;
        uint256 logSize = self.logSize;

        assembly {
            switch zeta
            case 0 { res := sub(p, 1) }
            default {
                res := zeta
                for { let i := 0 } lt(i, logSize) { i := add(i, 1) } { res := mulmod(res, res, p) }

                res := sub(res, 1)
            }
        }
    }

    function evaluateLagrangeOne(
        EvalDomain memory self,
        BN254.ScalarField zeta,
        BN254.ScalarField vanishEval
    ) internal view returns (BN254.ScalarField res) {
        if (BN254.ScalarField.unwrap(vanishEval) == 0) {
            return BN254.ScalarField.wrap(0);
        }

        uint256 p = BN254.R_MOD;
        uint256 divisor;
        uint256 vanishEvalMulSizeInv = self.sizeInv;

        assembly {
            vanishEvalMulSizeInv := mulmod(vanishEval, vanishEvalMulSizeInv, p)

            switch zeta
            case 0 { divisor := sub(p, 1) }
            default { divisor := sub(zeta, 1) }
        }
        divisor = BN254.ScalarField.unwrap((BN254.invert(BN254.ScalarField.wrap(divisor))));
        assembly {
            res := mulmod(vanishEvalMulSizeInv, divisor, p)
        }
    }

    function evaluatePiPoly(
        EvalDomain memory self,
        uint256[] memory pi,
        uint256 zeta,
        uint256 vanishEval
    ) internal view returns (uint256 res) {
        if (vanishEval == 0) {
            return 0;
        }

        uint256 p = BN254.R_MOD;
        uint256 length = pi.length;
        uint256 ithLagrange;
        uint256 ithDivisor;
        uint256 tmp;
        uint256 vanishEvalDivN = self.sizeInv;
        uint256 divisorProd;
        uint256[] memory localDomainElements = domainElements(self, length);
        uint256[] memory divisors = new uint256[](length);

        assembly {

            vanishEvalDivN := mulmod(vanishEvalDivN, vanishEval, p)

            divisorProd := 1

            for { let i := 0 } lt(i, length) { i := add(i, 1) } {

                tmp := mload(add(add(localDomainElements, 0x20), mul(i, 0x20)))

                ithDivisor := addmod(sub(p, tmp), zeta, p)

                divisorProd := mulmod(divisorProd, ithDivisor, p)

                mstore(add(add(divisors, 0x20), mul(i, 0x20)), ithDivisor)
            }
        }

        divisorProd = BN254.ScalarField.unwrap(BN254.invert(BN254.ScalarField.wrap(divisorProd)));

        assembly {
            for { let i := 0 } lt(i, length) { i := add(i, 1) } {

                tmp := mload(add(add(localDomainElements, 0x20), mul(i, 0x20)))

                ithLagrange := mulmod(vanishEvalDivN, tmp, p)

                ithLagrange := mulmod(ithLagrange, divisorProd, p)
                for { let j := 0 } lt(j, length) { j := add(j, 1) } {
                    if iszero(eq(i, j)) {
                        ithDivisor := mload(add(add(divisors, 0x20), mul(j, 0x20)))
                        ithLagrange := mulmod(ithLagrange, ithDivisor, p)
                    }
                }

                tmp := mload(add(add(pi, 0x20), mul(i, 0x20)))
                ithLagrange := mulmod(ithLagrange, tmp, p)
                res := addmod(res, ithLagrange, p)
            }
        }
    }

    function domainElements(EvalDomain memory self, uint256 length)
        internal
        pure
        returns (uint256[] memory elements)
    {
        if (length > self.size) revert InvalidPolyEvalArgs();
        uint256 groupGen = self.groupGen;
        uint256 tmp = 1;
        uint256 p = BN254.R_MOD;
        elements = new uint256[](length);
        assembly {
            if not(iszero(length)) {
                let ptr := add(elements, 0x20)
                let end := add(ptr, mul(0x20, length))
                mstore(ptr, 1)
                ptr := add(ptr, 0x20)

                for { } lt(ptr, end) { ptr := add(ptr, 0x20) } {
                    tmp := mulmod(tmp, groupGen, p)
                    mstore(ptr, tmp)
                }
            }
        }
    }

    function evalDataGen(EvalDomain memory self, uint256 zeta, uint256[] memory publicInput)
        internal
        view
        returns (EvalData memory evalData)
    {
        evalData.vanishEval = BN254.ScalarField.wrap(evaluateVanishingPoly(self, zeta));
        evalData.lagrangeOne =
            evaluateLagrangeOne(self, BN254.ScalarField.wrap(zeta), evalData.vanishEval);
        evalData.piEval = BN254.ScalarField.wrap(
            evaluatePiPoly(self, publicInput, zeta, BN254.ScalarField.unwrap(evalData.vanishEval))
        );
    }
}

library ERC1967Utils {

    event Upgraded(address indexed implementation);

    event AdminChanged(address previousAdmin, address newAdmin);

    event BeaconUpgraded(address indexed beacon);

    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    error ERC1967InvalidImplementation(address implementation);

    error ERC1967InvalidAdmin(address admin);

    error ERC1967InvalidBeacon(address beacon);

    error ERC1967NonPayable();

    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    function getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    function _setAdmin(address newAdmin) private {
        if (newAdmin == address(0)) {
            revert ERC1967InvalidAdmin(address(0));
        }
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    function changeAdmin(address newAdmin) internal {
        emit AdminChanged(getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    bytes32 internal constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    function getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(BEACON_SLOT).value;
    }

    function _setBeacon(address newBeacon) private {
        if (newBeacon.code.length == 0) {
            revert ERC1967InvalidBeacon(newBeacon);
        }

        StorageSlot.getAddressSlot(BEACON_SLOT).value = newBeacon;

        address beaconImplementation = IBeacon(newBeacon).implementation();
        if (beaconImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(beaconImplementation);
        }
    }

    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);

        if (data.length > 0) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        } else {
            _checkNonPayable();
        }
    }

    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}

library LightClientStateUpdateVK {
    function getVk() internal pure returns (IPlonkVerifier.VerifyingKey memory vk) {
        assembly {

            mstore(vk, 1048576)

            mstore(add(vk, 0x20), 8)

            mstore(
                mload(add(vk, 0x40)),
                14829590452951582429597937921803746951066352088554415416011470961765685672755
            )
            mstore(
                add(mload(add(vk, 0x40)), 0x20),
                1640805128987262135097000798716519252415689101125171714241944191382225430588
            )

            mstore(
                mload(add(vk, 0x60)),
                18274068123557654431658802492586722727412966290987193881329212617379409092827
            )
            mstore(
                add(mload(add(vk, 0x60)), 0x20),
                15262267645961173197854134224641529185383299058832029120242801083020131756400
            )

            mstore(
                mload(add(vk, 0x80)),
                3546893388503598029379371535595161595693832489221556391602992086886519831449
            )
            mstore(
                add(mload(add(vk, 0x80)), 0x20),
                5372901058006419475432857030090030698039020632248561039251432764657711254637
            )

            mstore(
                mload(add(vk, 0xa0)),
                8928358756130581276782896781228211285855331943263768176288185111880065377829
            )
            mstore(
                add(mload(add(vk, 0xa0)), 0x20),
                11296094221230007321906902566798665556326310712938157478561243271436961185939
            )

            mstore(
                mload(add(vk, 0xc0)),
                4270203435103829510210885065469080215759206247600073141969144340825736456361
            )
            mstore(
                add(mload(add(vk, 0xc0)), 0x20),
                18435513468464898350668089458023802596061834199836906544891249686171357011496
            )

            mstore(
                mload(add(vk, 0xe0)),
                1353825928133056546105071835787168542506364373349693671191581615121126233747
            )
            mstore(
                add(mload(add(vk, 0xe0)), 0x20),
                14552181871867089243248249259028502752341497337283269364895091407532060232707
            )

            mstore(
                mload(add(vk, 0x100)),
                16134962525970404894447932095148604805089607916596239986859009518831961541095
            )
            mstore(
                add(mload(add(vk, 0x100)), 0x20),
                12912418721630015879588720063744969517312801940994098982636356180615148009133
            )

            mstore(
                mload(add(vk, 0x120)),
                10367884953135327072589416694300506531675903043698271118039737017003907416548
            )
            mstore(
                add(mload(add(vk, 0x120)), 0x20),
                18645767054976951986441477674607729822362900191642269701059692086595011309617
            )

            mstore(
                mload(add(vk, 0x140)),
                20290438753634591112566805159744566085943118086910415955566637541975611306568
            )
            mstore(
                add(mload(add(vk, 0x140)), 0x20),
                3616081350190366687413620745033189240584091802830669829058164649134460203062
            )

            mstore(
                mload(add(vk, 0x160)),
                1392866654032974419818610994350340752885270300830841653620814131913125942809
            )
            mstore(
                add(mload(add(vk, 0x160)), 0x20),
                7926323714312408409342288501031785033608020789818750772083444352168852620309
            )

            mstore(
                mload(add(vk, 0x180)),
                3791333556380290364066652753532128031853997955294626527563616698625259260872
            )
            mstore(
                add(mload(add(vk, 0x180)), 0x20),
                3628907676439037794810640678014156959914018154448361319066535585239352845219
            )

            mstore(
                mload(add(vk, 0x1a0)),
                7288452744039439153187019986732880627393606422995836790888938928792979430332
            )
            mstore(
                add(mload(add(vk, 0x1a0)), 0x20),
                3898946817206780988021496513282121271248375416352393169747615149428446748796
            )

            mstore(
                mload(add(vk, 0x1c0)),
                20482389538634884293964815753989066984137903177461009416710382582511144614720
            )
            mstore(
                add(mload(add(vk, 0x1c0)), 0x20),
                11258994014172499578597433237341729986035258019178718124058091521884134834133
            )

            mstore(
                mload(add(vk, 0x1e0)),
                6452329770023103857611525837563150030587644522618711966359232731854161969093
            )
            mstore(
                add(mload(add(vk, 0x1e0)), 0x20),
                6635683706001669495270751033107447145849321869191941901164391368358042033363
            )

            mstore(
                mload(add(vk, 0x200)),
                18852624756618899688471924454580455174040214747122588704978836212290318639012
            )
            mstore(
                add(mload(add(vk, 0x200)), 0x20),
                19668150013698798224912707568562000682376208453509380984273539880691910555900
            )

            mstore(
                mload(add(vk, 0x220)),
                2897648376529441855171451962918729606513806930163982507283513591881780437542
            )
            mstore(
                add(mload(add(vk, 0x220)), 0x20),
                18058066682160117591143604241687402897699656641104339334068174388078565105166
            )

            mstore(
                mload(add(vk, 0x240)),
                8311780877242981974134745557347343806199562160806780762496164569715285508665
            )
            mstore(
                add(mload(add(vk, 0x240)), 0x20),
                9739465744057100599476346315622632649775803938784339749244299845794851098068
            )

            mstore(
                mload(add(vk, 0x260)),
                16504816536031923515595107276719833176967746018194462214393291822653673414274
            )
            mstore(
                add(mload(add(vk, 0x260)), 0x20),
                20309550876545766116130682111350015544103338784776768395329281357767924326613
            )
        }
    }
}

library Transcript {
    struct TranscriptData {
        bytes transcript;
        bytes32 state;
    }

    function appendMessage(TranscriptData memory self, bytes memory message) internal pure {
        self.transcript = abi.encodePacked(self.transcript, message);
    }

    function appendChallenge(TranscriptData memory self, uint256 challenge) internal pure {
        self.transcript = abi.encodePacked(self.transcript, Utils.reverseEndianness(challenge));
    }

    function appendCommitments(TranscriptData memory self, BN254.G1Point[] memory comms)
        internal
        pure
    {
        for (uint256 i = 0; i < comms.length; i++) {
            appendCommitment(self, comms[i]);
        }
    }

    function appendCommitment(TranscriptData memory self, BN254.G1Point memory comm)
        internal
        pure
    {
        self.transcript = abi.encodePacked(self.transcript, BN254.g1Serialize(comm));
    }

    function getAndAppendChallenge(TranscriptData memory self) internal pure returns (uint256) {
        bytes32 hash;

        bytes32 a = self.state;
        bytes memory b = self.transcript;

        assembly {

            let bLength := mload(b)

            let data := mload(0x40)

            mstore(data, a)

            let dataOffset := add(data, 32)
            for { let i := 0 } lt(i, bLength) { i := add(i, 0x20) } {
                mstore(add(dataOffset, i), mload(add(add(b, i), 0x20)))
            }

            hash := keccak256(data, add(32, bLength))
        }

        self.state = hash;

        uint256 ret = uint256(hash) % BN254.R_MOD;
        return ret;
    }

    function appendVkAndPubInput(
        TranscriptData memory self,
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        uint256[] memory publicInput
    ) internal pure {
        uint32 sizeInBits = 254;

        self.transcript = abi.encodePacked(
            self.transcript,
            BytesLib.slice(abi.encodePacked(Utils.reverseEndianness(sizeInBits)), 0, 4),

            BytesLib.slice(abi.encodePacked(Utils.reverseEndianness(verifyingKey.domainSize)), 0, 8),

            BytesLib.slice(abi.encodePacked(Utils.reverseEndianness(verifyingKey.numInputs)), 0, 8)

        );

        self.transcript = abi.encodePacked(
            self.transcript,
            Utils.reverseEndianness(0x1),
            Utils.reverseEndianness(
                0x2f8dd1f1a7583c42c4e12a44e110404c73ca6c94813f85835da4fb7bb1301d4a
            ),
            Utils.reverseEndianness(
                0x1ee678a0470a75a6eaa8fe837060498ba828a3703b311d0f77f010424afeb025
            ),
            Utils.reverseEndianness(
                0x2042a587a90c187b0a087c03e29c968b950b1db26d5c82d666905a6895790c0a
            ),
            Utils.reverseEndianness(
                0x2e2b91456103698adf57b799969dea1c8f739da5d8d40dd3eb9222db7c81e881
            )
        );

        self.transcript = abi.encodePacked(
            self.transcript,
            BN254.g1Serialize(verifyingKey.q1),
            BN254.g1Serialize(verifyingKey.q2),
            BN254.g1Serialize(verifyingKey.q3),
            BN254.g1Serialize(verifyingKey.q4),
            BN254.g1Serialize(verifyingKey.qM12),
            BN254.g1Serialize(verifyingKey.qM34),
            BN254.g1Serialize(verifyingKey.qH1)
        );
        self.transcript = abi.encodePacked(
            self.transcript,
            BN254.g1Serialize(verifyingKey.qH2),
            BN254.g1Serialize(verifyingKey.qH3),
            BN254.g1Serialize(verifyingKey.qH4),
            BN254.g1Serialize(verifyingKey.qO),
            BN254.g1Serialize(verifyingKey.qC),
            BN254.g1Serialize(verifyingKey.qEcc)
        );

        self.transcript = abi.encodePacked(
            self.transcript,
            BN254.g1Serialize(verifyingKey.sigma0),
            BN254.g1Serialize(verifyingKey.sigma1),
            BN254.g1Serialize(verifyingKey.sigma2),
            BN254.g1Serialize(verifyingKey.sigma3),
            BN254.g1Serialize(verifyingKey.sigma4)
        );

        self.transcript = abi.encodePacked(
            self.transcript,
            Utils.reverseEndianness(publicInput[0]),
            Utils.reverseEndianness(publicInput[1]),
            Utils.reverseEndianness(publicInput[2]),
            Utils.reverseEndianness(publicInput[3]),
            Utils.reverseEndianness(publicInput[4]),
            Utils.reverseEndianness(publicInput[5]),
            Utils.reverseEndianness(publicInput[6]),
            Utils.reverseEndianness(publicInput[7])
        );
    }

    function appendProofEvaluations(
        TranscriptData memory self,
        IPlonkVerifier.PlonkProof memory proof
    ) internal pure {
        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval0))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval1))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval2))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval3))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval4))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval0))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval1))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval2))
        );

        self.transcript = abi.encodePacked(
            self.transcript, Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval3))
        );

        self.transcript = abi.encodePacked(
            self.transcript,
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.prodPermZetaOmegaEval))
        );
    }
}

abstract contract UUPSUpgradeable is Initializable, IERC1822Proxiable {

    address private immutable __self = address(this);

    string public constant UPGRADE_INTERFACE_VERSION = "5.0.0";

    error UUPSUnauthorizedCallContext();

    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    modifier onlyProxy() {
        _checkProxy();
        _;
    }

    modifier notDelegated() {
        _checkNotDelegated();
        _;
    }

    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }

    function proxiableUUID() external view virtual notDelegated returns (bytes32) {
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    function _checkProxy() internal view virtual {
        if (
            address(this) == __self ||
            ERC1967Utils.getImplementation() != __self
        ) {
            revert UUPSUnauthorizedCallContext();
        }
    }

    function _checkNotDelegated() internal view virtual {
        if (address(this) != __self) {

            revert UUPSUnauthorizedCallContext();
        }
    }

    function _authorizeUpgrade(address newImplementation) internal virtual;

    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
            ERC1967Utils.upgradeToAndCall(newImplementation, data);
        } catch {

            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }
    }
}

library PlonkVerifier {

    error InvalidPlonkArgs();

    error WrongPlonkVK();

    using Transcript for Transcript.TranscriptData;

    uint256 internal constant COSET_K1 =
        0x2f8dd1f1a7583c42c4e12a44e110404c73ca6c94813f85835da4fb7bb1301d4a;
    uint256 internal constant COSET_K2 =
        0x1ee678a0470a75a6eaa8fe837060498ba828a3703b311d0f77f010424afeb025;
    uint256 internal constant COSET_K3 =
        0x2042a587a90c187b0a087c03e29c968b950b1db26d5c82d666905a6895790c0a;
    uint256 internal constant COSET_K4 =
        0x2e2b91456103698adf57b799969dea1c8f739da5d8d40dd3eb9222db7c81e881;

    uint256 internal constant BETA_H_X0 =
        0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1;
    uint256 internal constant BETA_H_X1 =
        0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0;
    uint256 internal constant BETA_H_Y0 =
        0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4;
    uint256 internal constant BETA_H_Y1 =
        0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55;

    uint256 internal constant NUM_WIRE_TYPES = 5;

    struct PcsInfo {

        uint256 u;

        uint256 evalPoint;

        uint256 nextEvalPoint;

        uint256 eval;

        uint256[] commScalars;

        BN254.G1Point[] commBases;

        BN254.G1Point openingProof;

        BN254.G1Point shiftedOpeningProof;
    }

    struct Challenges {
        uint256 alpha;
        uint256 alpha2;
        uint256 alpha3;
        uint256 beta;
        uint256 gamma;
        uint256 zeta;
        uint256 v;
        uint256 u;
    }

    function verify(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        uint256[] memory publicInput,
        IPlonkVerifier.PlonkProof memory proof
    ) internal view returns (bool) {
        _validateProof(proof);

        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[0]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[1]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[2]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[3]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[4]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[5]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[6]));
        BN254.validateScalarField(BN254.ScalarField.wrap(publicInput[7]));

        PcsInfo memory pcsInfo = _preparePcsInfo(verifyingKey, publicInput, proof);
        return _verifyOpeningProofs(pcsInfo);
    }

    function _validateProof(IPlonkVerifier.PlonkProof memory proof) internal pure {
        BN254.validateG1Point(proof.wire0);
        BN254.validateG1Point(proof.wire1);
        BN254.validateG1Point(proof.wire2);
        BN254.validateG1Point(proof.wire3);
        BN254.validateG1Point(proof.wire4);
        BN254.validateG1Point(proof.prodPerm);
        BN254.validateG1Point(proof.split0);
        BN254.validateG1Point(proof.split1);
        BN254.validateG1Point(proof.split2);
        BN254.validateG1Point(proof.split3);
        BN254.validateG1Point(proof.split4);
        BN254.validateG1Point(proof.zeta);
        BN254.validateG1Point(proof.zetaOmega);
        BN254.validateScalarField(proof.wireEval0);
        BN254.validateScalarField(proof.wireEval1);
        BN254.validateScalarField(proof.wireEval2);
        BN254.validateScalarField(proof.wireEval3);
        BN254.validateScalarField(proof.wireEval4);
        BN254.validateScalarField(proof.sigmaEval0);
        BN254.validateScalarField(proof.sigmaEval1);
        BN254.validateScalarField(proof.sigmaEval2);
        BN254.validateScalarField(proof.sigmaEval3);
        BN254.validateScalarField(proof.prodPermZetaOmegaEval);
    }

    function _preparePcsInfo(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        uint256[] memory publicInput,
        IPlonkVerifier.PlonkProof memory proof
    ) internal view returns (PcsInfo memory res) {
        if (publicInput.length != verifyingKey.numInputs) revert WrongPlonkVK();

        Challenges memory chal = _computeChallenges(verifyingKey, publicInput, proof);

        PolynomialEval.EvalDomain memory domain = PolynomialEval.newEvalDomain(verifyingKey.domainSize);

        PolynomialEval.EvalData memory evalData = PolynomialEval.evalDataGen(domain, chal.zeta, publicInput);

        uint256[] memory commScalars = new uint256[](30);
        BN254.G1Point[] memory commBases = new BN254.G1Point[](30);

        uint256 eval =
            _prepareOpeningProof(verifyingKey, evalData, proof, chal, commScalars, commBases);

        uint256 zeta = chal.zeta;
        uint256 omega = domain.groupGen;
        uint256 p = BN254.R_MOD;
        uint256 zetaOmega;
        assembly {
            zetaOmega := mulmod(zeta, omega, p)
        }

        res = PcsInfo(
            chal.u, zeta, zetaOmega, eval, commScalars, commBases, proof.zeta, proof.zetaOmega
        );
    }

    function _computeChallenges(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        uint256[] memory publicInput,
        IPlonkVerifier.PlonkProof memory proof
    ) internal pure returns (Challenges memory res) {
        Transcript.TranscriptData memory transcript;
        uint256 p = BN254.R_MOD;

        transcript.appendVkAndPubInput(verifyingKey, publicInput);

        transcript.transcript = abi.encodePacked(
            transcript.transcript,
            BN254.g1Serialize(proof.wire0),
            BN254.g1Serialize(proof.wire1),
            BN254.g1Serialize(proof.wire2),
            BN254.g1Serialize(proof.wire3),
            BN254.g1Serialize(proof.wire4)
        );

        transcript.getAndAppendChallenge();
        res.beta = transcript.getAndAppendChallenge();
        res.gamma = transcript.getAndAppendChallenge();

        transcript.transcript =
            abi.encodePacked(transcript.transcript, BN254.g1Serialize(proof.prodPerm));

        res.alpha = transcript.getAndAppendChallenge();

        transcript.transcript = abi.encodePacked(
            transcript.transcript,
            BN254.g1Serialize(proof.split0),
            BN254.g1Serialize(proof.split1),
            BN254.g1Serialize(proof.split2),
            BN254.g1Serialize(proof.split3),
            BN254.g1Serialize(proof.split4)
        );

        res.zeta = transcript.getAndAppendChallenge();

        transcript.transcript = abi.encodePacked(
            transcript.transcript,
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval0)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval1)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval2)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval3)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.wireEval4))
        );

        transcript.transcript = abi.encodePacked(
            transcript.transcript,
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval0)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval1)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval2)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.sigmaEval3)),
            Utils.reverseEndianness(BN254.ScalarField.unwrap(proof.prodPermZetaOmegaEval))
        );

        res.v = transcript.getAndAppendChallenge();

        transcript.transcript = abi.encodePacked(
            transcript.transcript, BN254.g1Serialize(proof.zeta), BN254.g1Serialize(proof.zetaOmega)
        );

        res.u = transcript.getAndAppendChallenge();

        assembly {
            let alpha := mload(res)
            let alpha2 := mulmod(alpha, alpha, p)
            let alpha3 := mulmod(alpha2, alpha, p)
            mstore(add(res, 0x20), alpha2)
            mstore(add(res, 0x40), alpha3)
        }
    }

    function _prepareOpeningProof(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        PolynomialEval.EvalData memory evalData,
        IPlonkVerifier.PlonkProof memory proof,
        Challenges memory chal,
        uint256[] memory commScalars,
        BN254.G1Point[] memory commBases
    ) internal pure returns (uint256 eval) {

        uint256 linPolyConstant = _computeLinPolyConstantTerm(chal, proof, evalData);

        _preparePolyCommitments(verifyingKey, chal, evalData, proof, commScalars, commBases);

        eval = _prepareEvaluations(linPolyConstant, proof, commScalars);
    }

    function _computeLinPolyConstantTerm(
        Challenges memory chal,
        IPlonkVerifier.PlonkProof memory proof,
        PolynomialEval.EvalData memory evalData
    ) internal pure returns (uint256 res) {
        uint256 p = BN254.R_MOD;
        uint256 lagrangeOneEval = BN254.ScalarField.unwrap(evalData.lagrangeOne);
        uint256 piEval = BN254.ScalarField.unwrap(evalData.piEval);
        uint256 perm = 1;

        assembly {
            let beta := mload(add(chal, 0x60))
            let gamma := mload(add(chal, 0x80))

            {
                let w0 := mload(add(proof, 0x1a0))
                let sigma0 := mload(add(proof, 0x240))
                perm := mulmod(perm, addmod(add(w0, gamma), mulmod(beta, sigma0, p), p), p)
            }
            {
                let w1 := mload(add(proof, 0x1c0))
                let sigma1 := mload(add(proof, 0x260))
                perm := mulmod(perm, addmod(add(w1, gamma), mulmod(beta, sigma1, p), p), p)
            }
            {
                let w2 := mload(add(proof, 0x1e0))
                let sigma2 := mload(add(proof, 0x280))
                perm := mulmod(perm, addmod(add(w2, gamma), mulmod(beta, sigma2, p), p), p)
            }
            {
                let w3 := mload(add(proof, 0x200))
                let sigma3 := mload(add(proof, 0x2a0))
                perm := mulmod(perm, addmod(add(w3, gamma), mulmod(beta, sigma3, p), p), p)
            }

            {
                let w4 := mload(add(proof, 0x220))
                let permNextEval := mload(add(proof, 0x2c0))
                perm := mulmod(perm, mulmod(addmod(w4, gamma, p), permNextEval, p), p)
            }

            let alpha := mload(chal)
            let alpha2 := mload(add(chal, 0x20))

            res := addmod(piEval, sub(p, mulmod(alpha2, lagrangeOneEval, p)), p)
            res := addmod(res, sub(p, mulmod(alpha, perm, p)), p)
        }
    }

    function _preparePolyCommitments(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        Challenges memory chal,
        PolynomialEval.EvalData memory evalData,
        IPlonkVerifier.PlonkProof memory proof,
        uint256[] memory commScalars,
        BN254.G1Point[] memory commBases
    ) internal pure {
        _linearizationScalarsAndBases(verifyingKey, chal, evalData, proof, commBases, commScalars);

        uint256 p = BN254.R_MOD;
        uint256 v = chal.v;
        uint256 vBase = v;

        commScalars[20] = vBase;
        commBases[20] = proof.wire0;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[21] = vBase;
        commBases[21] = proof.wire1;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[22] = vBase;
        commBases[22] = proof.wire2;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[23] = vBase;
        commBases[23] = proof.wire3;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[24] = vBase;
        commBases[24] = proof.wire4;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[25] = vBase;
        commBases[25] = verifyingKey.sigma0;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[26] = vBase;
        commBases[26] = verifyingKey.sigma1;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[27] = vBase;
        commBases[27] = verifyingKey.sigma2;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[28] = vBase;
        commBases[28] = verifyingKey.sigma3;
        assembly {
            vBase := mulmod(vBase, v, p)
        }

        commScalars[29] = chal.u;
        commBases[29] = proof.prodPerm;
    }

    function _prepareEvaluations(
        uint256 linPolyConstant,
        IPlonkVerifier.PlonkProof memory proof,
        uint256[] memory commScalars
    ) internal pure returns (uint256 eval) {
        uint256 p = BN254.R_MOD;
        assembly {
            eval := sub(p, linPolyConstant)
            for { let i := 0 } lt(i, 10) { i := add(i, 1) } {

                let combiner := mload(add(commScalars, mul(add(i, 21), 0x20)))
                let termEval := mload(add(proof, add(0x1a0, mul(i, 0x20))))
                eval := addmod(eval, mulmod(combiner, termEval, p), p)
            }
        }
    }

    function _verifyOpeningProofs(PcsInfo memory pcsInfo) internal view returns (bool) {
        uint256 p = BN254.R_MOD;

        BN254.G1Point memory a1;
        BN254.G1Point memory b1;

        {
            BN254.ScalarField[] memory scalars = new BN254.ScalarField[](2);
            BN254.G1Point[] memory bases = new BN254.G1Point[](2);
            uint256 rBase = 1;

            scalars[0] = BN254.ScalarField.wrap(rBase);
            bases[0] = pcsInfo.openingProof;

            scalars[1] = BN254.ScalarField.wrap(pcsInfo.u);

            bases[1] = pcsInfo.shiftedOpeningProof;

            a1 = BN254.multiScalarMul(bases, scalars);
        }

        {
            BN254.ScalarField[] memory scalars;
            BN254.G1Point[] memory bases;
            {

                uint256 scalarsLenPerInfo = pcsInfo.commScalars.length;
                uint256 totalScalarsLen = (2 + scalarsLenPerInfo) + 1;
                scalars = new BN254.ScalarField[](totalScalarsLen);
                bases = new BN254.G1Point[](totalScalarsLen);
            }
            uint256 sumEvals = 0;
            uint256 idx = 0;

            for (uint256 j = 0; j < pcsInfo.commScalars.length; j++) {
                scalars[idx] = BN254.ScalarField.wrap(pcsInfo.commScalars[j]);

                bases[idx] = pcsInfo.commBases[j];
                idx += 1;
            }

            scalars[idx] = BN254.ScalarField.wrap(pcsInfo.evalPoint);

            bases[idx] = pcsInfo.openingProof;
            idx += 1;

            {
                uint256 u = pcsInfo.u;
                uint256 nextEvalPoint = pcsInfo.nextEvalPoint;
                uint256 tmp;
                assembly {

                    tmp := mulmod(u, nextEvalPoint, p)
                }
                scalars[idx] = BN254.ScalarField.wrap(tmp);
            }
            bases[idx] = pcsInfo.shiftedOpeningProof;
            idx += 1;

            {
                uint256 eval = pcsInfo.eval;
                assembly {
                    sumEvals := addmod(sumEvals, eval, p)
                }
            }

            scalars[idx] = BN254.negate(BN254.ScalarField.wrap(sumEvals));
            bases[idx] = BN254.P1();
            b1 = BN254.negate(BN254.multiScalarMul(bases, scalars));
        }

        BN254.G2Point memory betaH = BN254.G2Point({
            x0: BN254.BaseField.wrap(BETA_H_X1),
            x1: BN254.BaseField.wrap(BETA_H_X0),
            y0: BN254.BaseField.wrap(BETA_H_Y1),
            y1: BN254.BaseField.wrap(BETA_H_Y0)
        });

        return BN254.pairingProd2(a1, betaH, b1, BN254.P2());
    }

    function _batchVerifyOpeningProofs(PcsInfo[] memory pcsInfos) internal view returns (bool) {
        uint256 pcsLen = pcsInfos.length;
        uint256 p = BN254.R_MOD;

        uint256 r = 1;
        if (pcsLen > 1) {
            Transcript.TranscriptData memory transcript;
            for (uint256 i = 0; i < pcsLen; i++) {
                transcript.appendChallenge(pcsInfos[i].u);
            }
            r = transcript.getAndAppendChallenge();
        }

        BN254.G1Point memory a1;
        BN254.G1Point memory b1;

        {
            BN254.ScalarField[] memory scalars = new BN254.ScalarField[](2 * pcsLen);
            BN254.G1Point[] memory bases = new BN254.G1Point[](2 * pcsLen);
            uint256 rBase = 1;
            for (uint256 i = 0; i < pcsLen; i++) {
                scalars[2 * i] = BN254.ScalarField.wrap(rBase);
                bases[2 * i] = pcsInfos[i].openingProof;

                {

                    uint256 tmp;
                    uint256 u = pcsInfos[i].u;
                    assembly {
                        tmp := mulmod(rBase, u, p)
                    }
                    scalars[2 * i + 1] = BN254.ScalarField.wrap(tmp);
                }
                bases[2 * i + 1] = pcsInfos[i].shiftedOpeningProof;

                assembly {
                    rBase := mulmod(rBase, r, p)
                }
            }
            a1 = BN254.multiScalarMul(bases, scalars);
        }

        {
            BN254.ScalarField[] memory scalars;
            BN254.G1Point[] memory bases;
            {

                uint256 scalarsLenPerInfo = pcsInfos[0].commScalars.length;
                uint256 totalScalarsLen = (2 + scalarsLenPerInfo) * pcsInfos.length + 1;
                scalars = new BN254.ScalarField[](totalScalarsLen);
                bases = new BN254.G1Point[](totalScalarsLen);
            }
            uint256 sumEvals = 0;
            uint256 idx = 0;
            uint256 rBase = 1;
            for (uint256 i = 0; i < pcsInfos.length; i++) {
                for (uint256 j = 0; j < pcsInfos[0].commScalars.length; j++) {
                    {

                        uint256 s = pcsInfos[i].commScalars[j];
                        uint256 tmp;
                        assembly {

                            tmp := mulmod(rBase, s, p)
                        }
                        scalars[idx] = BN254.ScalarField.wrap(tmp);
                    }
                    bases[idx] = pcsInfos[i].commBases[j];
                    idx += 1;
                }

                {

                    uint256 evalPoint = pcsInfos[i].evalPoint;
                    uint256 tmp;
                    assembly {

                        tmp := mulmod(rBase, evalPoint, p)
                    }
                    scalars[idx] = BN254.ScalarField.wrap(tmp);
                }
                bases[idx] = pcsInfos[i].openingProof;
                idx += 1;

                {

                    uint256 u = pcsInfos[i].u;
                    uint256 nextEvalPoint = pcsInfos[i].nextEvalPoint;
                    uint256 tmp;
                    assembly {

                        tmp := mulmod(rBase, mulmod(u, nextEvalPoint, p), p)
                    }
                    scalars[idx] = BN254.ScalarField.wrap(tmp);
                }
                bases[idx] = pcsInfos[i].shiftedOpeningProof;
                idx += 1;

                {

                    uint256 eval = pcsInfos[i].eval;
                    assembly {
                        sumEvals := addmod(sumEvals, mulmod(rBase, eval, p), p)
                        rBase := mulmod(rBase, r, p)
                    }
                }
            }
            scalars[idx] = BN254.negate(BN254.ScalarField.wrap(sumEvals));
            bases[idx] = BN254.P1();
            b1 = BN254.negate(BN254.multiScalarMul(bases, scalars));
        }

        BN254.G2Point memory betaH = BN254.G2Point({
            x0: BN254.BaseField.wrap(BETA_H_X1),
            x1: BN254.BaseField.wrap(BETA_H_X0),
            y0: BN254.BaseField.wrap(BETA_H_Y1),
            y1: BN254.BaseField.wrap(BETA_H_Y0)
        });

        return BN254.pairingProd2(a1, betaH, b1, BN254.P2());
    }

    function _linearizationScalarsAndBases(
        IPlonkVerifier.VerifyingKey memory verifyingKey,
        Challenges memory challenge,
        PolynomialEval.EvalData memory evalData,
        IPlonkVerifier.PlonkProof memory proof,
        BN254.G1Point[] memory bases,
        uint256[] memory scalars
    ) internal pure {
        uint256 firstScalar;
        uint256 secondScalar;
        uint256 rhs;
        uint256 tmp;
        uint256 tmp2;
        uint256 p = BN254.R_MOD;

        assembly {

            firstScalar := mulmod(mload(add(challenge, 0x20)), mload(add(evalData, 0x20)), p)

            rhs := mload(challenge)

            tmp := mulmod(mload(add(challenge, 0x60)), mload(add(challenge, 0xA0)), p)

            tmp2 := addmod(tmp, mload(add(proof, 0x1A0)), p)
            tmp2 := addmod(tmp2, mload(add(challenge, 0x80)), p)

            rhs := mulmod(tmp2, rhs, p)

            tmp2 := mulmod(tmp, COSET_K1, p)
            tmp2 := addmod(tmp2, mload(add(proof, 0x1C0)), p)
            tmp2 := addmod(tmp2, mload(add(challenge, 0x80)), p)

            rhs := mulmod(tmp2, rhs, p)

            tmp2 := mulmod(tmp, COSET_K2, p)
            tmp2 := addmod(tmp2, mload(add(proof, 0x1E0)), p)
            tmp2 := addmod(tmp2, mload(add(challenge, 0x80)), p)
            rhs := mulmod(tmp2, rhs, p)

            tmp2 := mulmod(tmp, COSET_K3, p)
            tmp2 := addmod(tmp2, mload(add(proof, 0x200)), p)
            tmp2 := addmod(tmp2, mload(add(challenge, 0x80)), p)
            rhs := mulmod(tmp2, rhs, p)

            tmp2 := mulmod(tmp, COSET_K4, p)
            tmp2 := addmod(tmp2, mload(add(proof, 0x220)), p)
            tmp2 := addmod(tmp2, mload(add(challenge, 0x80)), p)
            rhs := mulmod(tmp2, rhs, p)

            firstScalar := addmod(firstScalar, rhs, p)
        }
        bases[0] = proof.prodPerm;
        scalars[0] = firstScalar;

        assembly {

            secondScalar := mulmod(mload(challenge), mload(add(challenge, 0x60)), p)
            secondScalar := mulmod(secondScalar, mload(add(proof, 0x2C0)), p)

            tmp := mulmod(mload(add(challenge, 0x60)), mload(add(proof, 0x240)), p)
            tmp := addmod(tmp, mload(add(proof, 0x1A0)), p)
            tmp := addmod(tmp, mload(add(challenge, 0x80)), p)

            secondScalar := mulmod(secondScalar, tmp, p)

            tmp := mulmod(mload(add(challenge, 0x60)), mload(add(proof, 0x260)), p)
            tmp := addmod(tmp, mload(add(proof, 0x1C0)), p)
            tmp := addmod(tmp, mload(add(challenge, 0x80)), p)

            secondScalar := mulmod(secondScalar, tmp, p)

            tmp := mulmod(mload(add(challenge, 0x60)), mload(add(proof, 0x280)), p)
            tmp := addmod(tmp, mload(add(proof, 0x1E0)), p)
            tmp := addmod(tmp, mload(add(challenge, 0x80)), p)

            secondScalar := mulmod(secondScalar, tmp, p)

            tmp := mulmod(mload(add(challenge, 0x60)), mload(add(proof, 0x2A0)), p)
            tmp := addmod(tmp, mload(add(proof, 0x200)), p)
            tmp := addmod(tmp, mload(add(challenge, 0x80)), p)

            secondScalar := mulmod(secondScalar, tmp, p)
        }
        bases[1] = verifyingKey.sigma4;
        scalars[1] = p - secondScalar;

        scalars[2] = BN254.ScalarField.unwrap(proof.wireEval0);
        scalars[3] = BN254.ScalarField.unwrap(proof.wireEval1);
        scalars[4] = BN254.ScalarField.unwrap(proof.wireEval2);
        scalars[5] = BN254.ScalarField.unwrap(proof.wireEval3);
        bases[2] = verifyingKey.q1;
        bases[3] = verifyingKey.q2;
        bases[4] = verifyingKey.q3;
        bases[5] = verifyingKey.q4;

        assembly {
            tmp := mulmod(mload(add(proof, 0x1A0)), mload(add(proof, 0x1C0)), p)
        }
        scalars[6] = tmp;
        bases[6] = verifyingKey.qM12;

        assembly {
            tmp := mulmod(mload(add(proof, 0x1E0)), mload(add(proof, 0x200)), p)
        }
        scalars[7] = tmp;
        bases[7] = verifyingKey.qM34;

        assembly {
            tmp := mload(add(proof, 0x1A0))
            tmp2 := mulmod(tmp, tmp, p)
            tmp2 := mulmod(tmp2, tmp2, p)
            tmp := mulmod(tmp, tmp2, p)
        }
        scalars[8] = tmp;
        bases[8] = verifyingKey.qH1;

        assembly {
            tmp := mload(add(proof, 0x1C0))
            tmp2 := mulmod(tmp, tmp, p)
            tmp2 := mulmod(tmp2, tmp2, p)
            tmp := mulmod(tmp, tmp2, p)
        }
        scalars[9] = tmp;
        bases[9] = verifyingKey.qH2;

        assembly {
            tmp := mload(add(proof, 0x1E0))
            tmp2 := mulmod(tmp, tmp, p)
            tmp2 := mulmod(tmp2, tmp2, p)
            tmp := mulmod(tmp, tmp2, p)
        }
        scalars[10] = tmp;
        bases[10] = verifyingKey.qH3;

        assembly {
            tmp := mload(add(proof, 0x200))
            tmp2 := mulmod(tmp, tmp, p)
            tmp2 := mulmod(tmp2, tmp2, p)
            tmp := mulmod(tmp, tmp2, p)
        }
        scalars[11] = tmp;
        bases[11] = verifyingKey.qH4;

        scalars[12] = p - BN254.ScalarField.unwrap(proof.wireEval4);
        bases[12] = verifyingKey.qO;

        scalars[13] = 1;
        bases[13] = verifyingKey.qC;

        assembly {
            tmp := mulmod(mload(add(proof, 0x1A0)), mload(add(proof, 0x1C0)), p)
            tmp := mulmod(tmp, mload(add(proof, 0x1E0)), p)
            tmp := mulmod(tmp, mload(add(proof, 0x200)), p)
            tmp := mulmod(tmp, mload(add(proof, 0x220)), p)
        }
        scalars[14] = tmp;
        bases[14] = verifyingKey.qEcc;

        scalars[15] = p - BN254.ScalarField.unwrap(evalData.vanishEval);
        bases[15] = proof.split0;
        assembly {

            tmp := addmod(mload(evalData), 1, p)

            tmp2 := mulmod(mload(add(challenge, 0xA0)), mload(add(challenge, 0xA0)), p)
            tmp := mulmod(tmp, tmp2, p)
        }

        assembly {
            tmp2 := mulmod(mload(add(scalars, mul(16, 0x20))), tmp, p)
        }
        scalars[16] = tmp2;
        bases[16] = proof.split1;

        assembly {
            tmp2 := mulmod(mload(add(scalars, mul(17, 0x20))), tmp, p)
        }
        scalars[17] = tmp2;
        bases[17] = proof.split2;

        assembly {
            tmp2 := mulmod(mload(add(scalars, mul(18, 0x20))), tmp, p)
        }
        scalars[18] = tmp2;
        bases[18] = proof.split3;

        assembly {
            tmp2 := mulmod(mload(add(scalars, mul(19, 0x20))), tmp, p)
        }
        scalars[19] = tmp2;
        bases[19] = proof.split4;
    }
}

contract LightClient is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    event EpochChanged(uint64);
    event Upgrade(address implementation);
    event PermissionedProverRequired(address permissionedProver);
    event PermissionedProverNotRequired();
    uint32 public blocksPerEpoch;
    uint32 internal genesisState;
    uint32 internal finalizedState;
    uint64 public currentEpoch;
    bytes32 public votingStakeTableCommitment;
    uint256 public votingThreshold;
    bytes32 public frozenStakeTableCommitment;
    uint256 public frozenThreshold;
    mapping(uint32 => LightClientState) public states;
    address public permissionedProver;
    bool public permissionedProverEnabled;

    struct LightClientState {
        uint64 viewNum;
        uint64 blockHeight;
        BN254.ScalarField blockCommRoot;
        BN254.ScalarField feeLedgerComm;
        BN254.ScalarField stakeTableBlsKeyComm;
        BN254.ScalarField stakeTableSchnorrKeyComm;
        BN254.ScalarField stakeTableAmountComm;
        uint256 threshold;
    }

    event NewState(
        uint64 indexed viewNum, uint64 indexed blockHeight, BN254.ScalarField blockCommRoot
    );

    constructor() {
        _disableInitializers();
    }

    function initialize(LightClientState memory genesis, uint32 numBlocksPerEpoch, address owner)
    public
    initializer
    {
        __Ownable_init(owner);
        __UUPSUpgradeable_init();
        genesisState = 0;
        finalizedState = 1;
        _initializeState(genesis, numBlocksPerEpoch);
    }

    function getVersion()
    public
    pure
    returns (uint8 majorVersion, uint8 minorVersion, uint8 patchVersion)
    {
        return (1, 0, 0);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        emit Upgrade(newImplementation);
    }

    function _initializeState(LightClientState memory genesis, uint32 numBlockPerEpoch) internal {
        if (
            genesis.viewNum != 0 || genesis.blockHeight != 0
            || BN254.ScalarField.unwrap(genesis.stakeTableBlsKeyComm) == 0
            || BN254.ScalarField.unwrap(genesis.stakeTableSchnorrKeyComm) == 0
            || BN254.ScalarField.unwrap(genesis.stakeTableAmountComm) == 0 || genesis.threshold == 0
            || numBlockPerEpoch == 0
        ) {
            revert("InvalidArgs");
        }

        states[genesisState] = genesis;
        states[finalizedState] = genesis;
        currentEpoch = 0;

        blocksPerEpoch = numBlockPerEpoch;

        bytes32 initStakeTableComm = computeStakeTableComm(genesis);
        votingStakeTableCommitment = initStakeTableComm;
        votingThreshold = genesis.threshold;
        frozenStakeTableCommitment = initStakeTableComm;
        frozenThreshold = genesis.threshold;
    }

    function getGenesisState() public view returns (LightClientState memory) {
        return states[genesisState];
    }

    function getFinalizedState() public view returns (LightClientState memory) {
        return states[finalizedState];
    }

    function newFinalizedState(
        LightClientState memory newState,
        IPlonkVerifier.PlonkProof memory proof
    ) external {
        if (permissionedProverEnabled && msg.sender != permissionedProver) {
            if (permissionedProver == address(0)) {
                revert("PermissionedProverNotSet");
            }
            revert("ProverNotPermissioned");
        }

        if (
            newState.viewNum <= getFinalizedState().viewNum
            || newState.blockHeight <= getFinalizedState().blockHeight
        ) {
            revert("OutdatedState");
        }
        uint64 epochEndingBlockHeight = currentEpoch * blocksPerEpoch;

        bool isNewEpoch = states[finalizedState].blockHeight == epochEndingBlockHeight;
        if (!isNewEpoch && newState.blockHeight > epochEndingBlockHeight) {
            revert("MissingLastBlockForCurrentEpoch");
        }
        BN254.validateScalarField(newState.blockCommRoot);
        BN254.validateScalarField(newState.feeLedgerComm);
        BN254.validateScalarField(newState.stakeTableBlsKeyComm);
        BN254.validateScalarField(newState.stakeTableSchnorrKeyComm);
        BN254.validateScalarField(newState.stakeTableAmountComm);

        if (isNewEpoch) {
            _advanceEpoch();
        }

        verifyProof(newState, proof);

        states[finalizedState] = newState;
        emit NewState(newState.viewNum, newState.blockHeight, newState.blockCommRoot);
    }

    function verifyProof(LightClientState memory state, IPlonkVerifier.PlonkProof memory proof)
    internal
    virtual
    {
        IPlonkVerifier.VerifyingKey memory vk = LightClientStateUpdateVK.getVk();
        uint256[] memory publicInput = new uint256[](8);
        publicInput[0] = votingThreshold;
        publicInput[1] = uint256(state.viewNum);
        publicInput[2] = uint256(state.blockHeight);
        publicInput[3] = BN254.ScalarField.unwrap(state.blockCommRoot);
        publicInput[4] = BN254.ScalarField.unwrap(state.feeLedgerComm);
        publicInput[5] = BN254.ScalarField.unwrap(states[finalizedState].stakeTableBlsKeyComm);
        publicInput[6] = BN254.ScalarField.unwrap(states[finalizedState].stakeTableSchnorrKeyComm);
        publicInput[7] = BN254.ScalarField.unwrap(states[finalizedState].stakeTableAmountComm);

        if (!PlonkVerifier.verify(vk, publicInput, proof)) {
            revert("InvalidProof");
        }

    }

    function _advanceEpoch() private {
        bytes32 newStakeTableComm = computeStakeTableComm(states[finalizedState]);
        votingStakeTableCommitment = frozenStakeTableCommitment;
        frozenStakeTableCommitment = newStakeTableComm;

        votingThreshold = frozenThreshold;
        frozenThreshold = states[finalizedState].threshold;

        currentEpoch += 1;
        emit EpochChanged(currentEpoch);
    }

    function computeStakeTableComm(LightClientState memory state) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                state.stakeTableBlsKeyComm,
                state.stakeTableSchnorrKeyComm,
                state.stakeTableAmountComm
            )
        );
    }

    function setPermissionedProver(address prover) public onlyOwner {
        if (prover == address(0)) {
            revert("InvalidAddress");
        }
        if (prover == permissionedProver) {
            revert("NoChangeRequired");
        }
        permissionedProver = prover;
        permissionedProverEnabled = true;
        emit PermissionedProverRequired(permissionedProver);
    }

    function disablePermissionedProverMode() public onlyOwner {
        if (permissionedProverEnabled) {
            permissionedProver = address(0);
            permissionedProverEnabled = false;
            emit PermissionedProverNotRequired();
        } else {
            revert("NoChangeRequired");
        }
    }
}