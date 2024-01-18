# permit2-evc-demo

*Extending EVC's `VaultSimple` to support depositing/minting with Permit2 token transfers*

---

## Example Usage

```solidity
// Alice signs permit to spend 1e18 tokens
uint256 nonce = 0;
ISignatureTransfer.PermitTransferFrom memory permitData = defaultERC20PermitTransfer(address(underlying), nonce);
bytes memory sig = getPermitTransferToSignature(permitData, alicePK, address(vault), permit2.DOMAIN_SEPARATOR());

uint256 depositAmount = 1e18;

vm.prank(alice);
vault.depositWithPermit(depositAmount, alice, permitData, sig);
```

# Guide

This repo and example focuses on `SignatureTransfer`, one half of `Permit2`. As its name implies, `SignatureTransfer` relies on signatures to allow contracts/recipients to take a user's tokens. The other feature `AllowanceTransfer` behaves similar to `ERC20.approve` and is not covered in this demo.

Add `permit2` to your contract(s)
```solidity
import "permit2/src/interfaces/IPermit2.sol";

/// @title VaultSimpleWithPermit
/// @notice This contract extends VaultSimple to support Permit2 deposits
contract VaultSimpleWithPermit is VaultSimple {
    IPermit2 public immutable permit2;

    constructor(IEVC _evc, ERC20 _asset, string memory _name, string memory _symbol, IPermit2 _permit2)
        VaultSimple(_evc, _asset, _name, _symbol)
    {
        permit2 = _permit2;
    }
}
```

If you contract relies on multiple `ERC20.transferFrom`, it's helpful to define a helper function:
```solidity
/// @dev Replaces ERC20.transferFrom with signatured-based Permit2
function _permitTransferFrom(
    address owner,
    uint256 amount,
    ISignatureTransfer.PermitTransferFrom calldata permitData,
    bytes calldata signature
) internal {
    // transfering `permitData.permitted.token`` of `amount` to `address(this)`
    ISignatureTransfer.SignatureTransferDetails memory transferDetails =
        ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: amount});
    permit2.permitTransferFrom(permitData, transferDetails, owner, signature);
}
```

Functions dependent on `ERC20.transferFrom` will require additional parameters:
```solidity
function depositWithPermit(
    ...
    uint256 depositAmount,
    ISignatureTransfer.PermitTransferFrom calldata permitData,
    bytes calldata signature
) public {
    ...

    // transferFrom with Permit2 instead of ERC20.safeTransferFrom
    _permitTransferFrom(msg.sender, depositAmount, permitData, signature);

    ...
}
```

## Testing Guide

Permit2 provides useful test helpers to be aware of

```solidity
// Deployer that uses vm.etch to avoid compiling Permit2 with IR (its slow!)
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";

// Helper functions to build structs and generate signatures
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";

contract VaultSimpleWithPermitTest is Test, DeployPermit2, PermitSignature {
    ...
    IPermit2 permit2;

    // user and their private key, used for signing
    address alice;
    uint256 alicePK;

    function setUp() public {
        deployPermit2();
        permit2 = IPermit2(PERMIT2_ADDRESS);
        
        ...

        (alice, alicePK) = makeAddrAndKey("alice");

        // alice max-approves Permit2
        vm.prank(alice);
        underlying.approve(address(permit2), type(uint256).max);
    }

    function testExample() public {
        // alice creates a message and signs it, the default amount is 1e18
        uint256 nonce = 0;
        ISignatureTransfer.PermitTransferFrom memory permitData = defaultERC20PermitTransfer(address(underlying), nonce);
        bytes memory sig = getPermitTransferToSignature(permitData, alicePK, address(contract), permit2.DOMAIN_SEPARATOR());

        uint256 amount = 1e18;

        // alice uses the signature
        vm.prank(alice);
        uint256 aliceShareAmount = contract.depositWithPermit(amount, alice, permitData, sig);

        ...
    }

    // Helper function to generate a signature for an arbitrary recipient `to`
    function getPermitTransferToSignature(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        address to,
        bytes32 domainSeparator
    ) internal pure returns (bytes memory sig) {
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, to, permit.nonce, permit.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }
}
```




---

*requires [foundry](https://book.getfoundry.sh)*

Additional resources

* [uniswap/permit2](https://github.com/uniswap/permit2)
* [evc.wtf](https://evc.wtf)
* [EVC](https://github.com/euler-xyz/ethereum-vault-connector)
* [EVC Playground](https://github.com/euler-xyz/evc-playground)
