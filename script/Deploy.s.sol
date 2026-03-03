// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";

contract Deploy is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        address Owner = 0xf83EE532e16f2998358f93a19DE6d7F6E7d146a4;
        vm.startBroadcast(Owner);

        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT_V07)
        );

        console.log("Factory deployed at:", address(factory));
        console.log("EntryPoint:", ENTRYPOINT_V07);

        vm.stopBroadcast();
    }
}

