// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {
    ForsVerifier,
    FORS_SIG_LEN
} from "../src/Verifiers/ForsVerifier.sol";

contract ForsReferenceVectorTest is Test {
    function test_pythonReferenceVector_recoversExpectedAddress() public {
        ForsVerifier verifier = new ForsVerifier();

        string memory path = string.concat(
            vm.projectRoot(),
            "/test/vectors/fors-reference-0.json"
        );
        string memory json = vm.readFile(path);

        bytes memory signature = vm.parseJsonBytes(json, ".signature");
        bytes32 digest = vm.parseJsonBytes32(json, ".digest");
        address expected = vm.parseJsonAddress(json, ".address");
        uint256 declaredLength = vm.parseJsonUint(json, ".params.signatureLength");

        assertEq(signature.length, FORS_SIG_LEN);
        assertEq(declaredLength, FORS_SIG_LEN);
        assertEq(verifier.recover(signature, digest), expected);
    }
}
