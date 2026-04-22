// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/WotsCVerifier.sol";

contract Deploy is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        address owner = 0xf83EE532e16f2998358f93a19DE6d7F6E7d146a4;
        vm.startBroadcast(owner);

        WotsCVerifier verifier = new WotsCVerifier();

        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT_V07),
            IWotsCVerifier(address(verifier))
        );

        console.log("WotsCVerifier deployed at:", address(verifier));
        console.log("Factory deployed at:        ", address(factory));
        console.log("  ECDSA implementation at:  ", factory.ECDSA_IMPL());
        console.log("  WOTS  implementation at:  ", factory.WOTS_IMPL());
        console.log("EntryPoint:                 ", ENTRYPOINT_V07);

        vm.stopBroadcast();
    }
}

