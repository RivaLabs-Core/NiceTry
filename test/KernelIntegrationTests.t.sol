// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

// Real Kernel v3.1 pieces (vendored via submodule at lib/kernel)
import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IValidator, IHook} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ValidationId} from "kernel/types/Types.sol";
import {EntryPointLib} from "kernel/sdk/TestBase/erc4337Util.sol";
import {IEntryPoint} from "kernel/interfaces/IEntryPoint.sol";

import {KernelRotatingECDSAValidator} from "../src/Module/KernelRotatingECDSAValidator.sol";

/// @dev Step 2a: install-only integration test.
///
/// Deploys a real ERC-4337 v0.7 EntryPoint at the canonical address, a fresh
/// Kernel v3.1 implementation + factory, and our KernelRotatingECDSAValidator.
/// Creates a Kernel account with our validator installed as the root validator
/// via Kernel's own `initialize(...)` flow, and verifies our validator's
/// internal state was populated correctly.
///
/// This proves the install plumbing works end-to-end against a real Kernel —
/// no mocks. UserOp flow comes in step 2b.
contract KernelIntegrationTest is Test {
    IEntryPoint entrypoint;
    KernelFactory factory;
    KernelRotatingECDSAValidator validator;
    Kernel account;

    uint256 constant OWNER_PK = 0xA11CE;
    address owner;

    function setUp() public {
        // Deploy canonical EntryPoint v0.7 at 0x0000000071727De22E5E9d8BAf0edAc6f37da032
        entrypoint = IEntryPoint(EntryPointLib.deploy());

        // Kernel impl + factory
        Kernel impl = new Kernel(entrypoint);
        factory = new KernelFactory(address(impl));

        // Our validator (standalone — one instance can serve any number of Kernel accounts)
        validator = new KernelRotatingECDSAValidator();

        owner = vm.addr(OWNER_PK);

        // Build initData: Kernel.initialize(rootValidator, hook, validatorData, hookData, initConfig)
        //   rootValidator = 0x01 || validatorAddr (VALIDATION_TYPE_VALIDATOR)
        //   hook          = IHook(0) (no hook)
        //   validatorData = abi.encode(owner) — consumed by our onInstall's abi.decode
        //   hookData      = empty
        //   initConfig    = empty (no extra module installs)
        ValidationId rootValidator =
            ValidatorLib.validatorToIdentifier(IValidator(address(validator)));

        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidator,
            IHook(address(0)),
            abi.encode(owner),
            bytes(""),
            new bytes[](0)
        );

        // Deploy the Kernel account through its factory.
        address accountAddr = factory.createAccount(initData, bytes32(0));
        account = Kernel(payable(accountAddr));
    }

    // =========================================================================
    // Install flow
    // =========================================================================

    function test_install_setsOwnerInValidator() public view {
        assertEq(validator.owners(address(account)), owner);
    }

    function test_install_validatorIsInitialized() public view {
        assertTrue(validator.isInitialized(address(account)));
    }

    function test_install_accountCodeDeployed() public view {
        assertTrue(address(account).code.length > 0);
    }

    function test_install_rootValidatorMatchesOurs() public view {
        // Kernel's rootValidator() returns the ValidationId. Extract the low 20 bytes.
        ValidationId rv = account.rootValidator();
        address installed = ValidationId.unwrap(rv) == bytes21(0)
            ? address(0)
            : address(ValidatorLib.getValidator(rv));
        assertEq(installed, address(validator));
    }
}
