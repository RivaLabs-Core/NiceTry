// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/Verifiers/WotsCVerifier.sol";
import "../src/Verifiers/ForsVerifier.sol";
import {IForsVerifier} from "../src/Interfaces/IForsVerifier.sol";

contract Deploy is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        address owner = 0xf83EE532e16f2998358f93a19DE6d7F6E7d146a4;
        vm.startBroadcast(owner);

        WotsCVerifier wotsVerifier = new WotsCVerifier();
        ForsVerifier  forsVerifier = new ForsVerifier();

        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT_V07),
            IWotsCVerifier(address(wotsVerifier)),
            IForsVerifier(address(forsVerifier))
        );

        console.log("WotsCVerifier deployed at:  ", address(wotsVerifier));
        console.log("ForsVerifier  deployed at:  ", address(forsVerifier));
        console.log("Factory       deployed at:  ", address(factory));
        console.log("  ECDSA implementation at:  ", factory.ECDSA_IMPL());
        console.log("  WOTS  implementation at:  ", factory.WOTS_IMPL());
        console.log("  FORS  implementation at:  ", factory.FORS_IMPL());
        console.log("EntryPoint:                 ", ENTRYPOINT_V07);

        vm.stopBroadcast();
    }
}

