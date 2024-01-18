// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "solmate/src/test/utils/mocks/MockERC20.sol";
import "evc/EthereumVaultConnector.sol";

import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";

import {VaultSimpleWithPermit} from "../src/VaultSimpleWithPermit.sol";
import "permit2/src/interfaces/IPermit2.sol";

contract VaultSimpleWithPermitTest is Test, DeployPermit2, PermitSignature {
    IEVC evc;
    MockERC20 underlying;
    VaultSimpleWithPermit vault;
    IPermit2 permit2;

    address alice;
    uint256 alicePK;

    error NotAuthorized();
    error ControllerDisabled();

    function setUp() public {
        deployPermit2();
        permit2 = IPermit2(PERMIT2_ADDRESS);
        evc = new EthereumVaultConnector();
        underlying = new MockERC20("Mock Token", "TKN", 18);
        vault = new VaultSimpleWithPermit(evc, underlying, "Mock Token Vault", "vTKN", permit2);

        (alice, alicePK) = makeAddrAndKey("alice");

        // alice max-approves Permit2
        vm.prank(alice);
        underlying.approve(address(permit2), type(uint256).max);
    }

    function testSingleDepositWithPermitWithdraw() public {
        uint256 amount = 1e18;

        uint256 aliceUnderlyingAmount = amount;
        underlying.mint(alice, aliceUnderlyingAmount);

        // -------------------------
        // --- Permit2 Signature ---
        // -------------------------
        // Alice signs permit to spend 1e18 tokens
        uint256 nonce = 0;
        ISignatureTransfer.PermitTransferFrom memory permitData = defaultERC20PermitTransfer(address(underlying), nonce);
        bytes memory sig = getPermitTransferSignature2(permitData, alicePK, permit2.DOMAIN_SEPARATOR());

        uint256 alicePreDepositBal = underlying.balanceOf(alice);

        vm.prank(alice);
        uint256 aliceShareAmount = vault.depositWithPermit(aliceUnderlyingAmount, alice, permitData, sig);

        // Expect exchange rate to be 1:1 on initial deposit.
        assertEq(aliceUnderlyingAmount, aliceShareAmount);
        assertEq(vault.previewWithdraw(aliceShareAmount), aliceUnderlyingAmount);
        assertEq(vault.previewDeposit(aliceUnderlyingAmount), aliceShareAmount);
        assertEq(vault.totalSupply(), aliceShareAmount);
        assertEq(vault.totalAssets(), aliceUnderlyingAmount);
        assertEq(vault.balanceOf(alice), aliceShareAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), aliceUnderlyingAmount);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal - aliceUnderlyingAmount);

        vm.prank(alice);
        vault.withdraw(aliceUnderlyingAmount, alice, alice);

        assertEq(vault.totalAssets(), 0);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal);
    }

    function testSingleMintWithPermitRedeem() public {
        uint256 amount = 1e18;

        uint256 aliceShareAmount = amount;
        underlying.mint(alice, aliceShareAmount);

        // -------------------------
        // --- Permit2 Signature ---
        // -------------------------
        // Alice signs permit to spend 1e18 tokens
        uint256 nonce = 0;
        ISignatureTransfer.PermitTransferFrom memory permitData = defaultERC20PermitTransfer(address(underlying), nonce);
        bytes memory sig = getPermitTransferSignature2(permitData, alicePK, permit2.DOMAIN_SEPARATOR());

        uint256 alicePreDepositBal = underlying.balanceOf(alice);

        vm.prank(alice);
        uint256 aliceUnderlyingAmount = vault.mintWithPermit(aliceShareAmount, alice, permitData, sig);

        // Expect exchange rate to be 1:1 on initial mint.
        assertEq(aliceShareAmount, aliceUnderlyingAmount);
        assertEq(vault.previewWithdraw(aliceShareAmount), aliceUnderlyingAmount);
        assertEq(vault.previewDeposit(aliceUnderlyingAmount), aliceShareAmount);
        assertEq(vault.totalSupply(), aliceShareAmount);
        assertEq(vault.totalAssets(), aliceUnderlyingAmount);
        assertEq(vault.balanceOf(alice), aliceUnderlyingAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), aliceUnderlyingAmount);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal - aliceUnderlyingAmount);

        vm.prank(alice);
        vault.redeem(aliceShareAmount, alice, alice);

        assertEq(vault.totalAssets(), 0);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal);
    }

    function getPermitTransferSignature2(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        bytes32 domainSeparator
    ) internal view returns (bytes memory sig) {
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, address(vault), permit.nonce, permit.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }
}
