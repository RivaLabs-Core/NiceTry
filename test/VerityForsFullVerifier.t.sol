// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IVerityForsFullVerifier {
    function recover(bytes calldata signature, bytes32 digest) external returns (address);
}

contract VerityForsFullVerifierTest is Test {
    string private constant VECTOR_PATH = "/test/vectors/fors-reference-0.json";
    string private constant YUL_SOURCE_PATH = "/verity/artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.yul";
    string private constant SOLC_ARTIFACT_PATH =
        "verity/artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json";

    bytes32 private constant EXPECTED_YUL_SHA256 = 0x3f3cb2ecf14df72834ec243d5aab290fc73b1778a7ef47bee3483690743efb9e;

    function test_generatedYulSourceHash_matchesCompiledArtifactFixture() public view {
        string memory yulSource = vm.readFile(string.concat(vm.projectRoot(), YUL_SOURCE_PATH));

        assertEq(sha256(bytes(yulSource)), EXPECTED_YUL_SHA256);
    }

    function test_generatedVerityFullVerifier_recoversReferenceVector() public {
        IVerityForsFullVerifier verifier = IVerityForsFullVerifier(_deployVerityFullVerifier());

        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTOR_PATH));
        bytes memory signature = vm.parseJsonBytes(json, ".signature");
        bytes32 digest = vm.parseJsonBytes32(json, ".digest");
        address expected = vm.parseJsonAddress(json, ".address");

        assertEq(verifier.recover(signature, digest), expected);
    }

    function test_generatedVerityFullVerifier_rejectsBadLength() public {
        IVerityForsFullVerifier verifier = IVerityForsFullVerifier(_deployVerityFullVerifier());

        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTOR_PATH));
        bytes32 digest = vm.parseJsonBytes32(json, ".digest");

        assertEq(verifier.recover(new bytes(0), digest), address(0));
    }

    function _deployVerityFullVerifier() private returns (address verifier) {
        string memory artifact = vm.readFile(string.concat(vm.projectRoot(), "/", SOLC_ARTIFACT_PATH));
        bytes memory creationCode = vm.parseJsonBytes(artifact, ".bytecode.object");
        assertGt(creationCode.length, 0);

        assembly {
            verifier := create(0, add(creationCode, 0x20), mload(creationCode))
        }

        assertTrue(verifier != address(0));
    }
}
