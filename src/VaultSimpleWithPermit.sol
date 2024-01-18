// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "evc-playground/vaults/VaultSimple.sol";
import "permit2/src/interfaces/IPermit2.sol";

/// @title VaultSimpleWithPermit
/// @notice This contract extends VaultSimple to support Permit2 deposits
contract VaultSimpleWithPermit is VaultSimple {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;

    IPermit2 public immutable permit2;

    constructor(IEVC _evc, ERC20 _asset, string memory _name, string memory _symbol, IPermit2 _permit2)
        VaultSimple(_evc, _asset, _name, _symbol)
    {
        permit2 = _permit2;
    }

    /// @dev Replaces asset.transferFrom with signatured-based Permit2
    function _permitTransferFrom(
        address msgSender,
        uint256 amount,
        ISignatureTransfer.PermitTransferFrom calldata permitData,
        bytes calldata signature
    ) internal {
        require(permitData.permitted.token == address(asset), "INVALID_TOKEN");
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: amount});
        permit2.permitTransferFrom(permitData, transferDetails, msgSender, signature);
    }

    /// @dev Deposits a certain amount of assets for a receiver, using Permit2.
    /// @param assets The assets to deposit.
    /// @param receiver The receiver of the deposit.
    /// @return shares The shares equivalent to the deposited assets.
    function depositWithPermit(
        uint256 assets,
        address receiver,
        ISignatureTransfer.PermitTransferFrom calldata permitData,
        bytes calldata signature
    ) public callThroughEVC nonReentrant returns (uint256 shares) {
        address msgSender = _msgSender();

        takeVaultSnapshot();

        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        // transferFrom with Permit2 instead of ERC20.safeTransferFrom
        _permitTransferFrom(msgSender, assets, permitData, signature);

        _mint(receiver, shares);

        emit Deposit(msgSender, receiver, assets, shares);

        requireAccountAndVaultStatusCheck(address(0));
    }

    /// @dev Mints a certain amount of shares for a receiver, using Permit2.
    /// @param shares The shares to mint.
    /// @param receiver The receiver of the mint.
    /// @return assets The assets equivalent to the minted shares.
    function mintWithPermit(
        uint256 shares,
        address receiver,
        ISignatureTransfer.PermitTransferFrom calldata permitData,
        bytes calldata signature
    ) public virtual callThroughEVC nonReentrant returns (uint256 assets) {
        address msgSender = _msgSender();

        takeVaultSnapshot();

        assets = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

        // Need to transfer before minting or ERC777s could reenter.
        // transferFrom with Permit2 instead of ERC20.safeTransferFrom
        _permitTransferFrom(msgSender, assets, permitData, signature);

        _mint(receiver, shares);

        emit Deposit(msgSender, receiver, assets, shares);

        requireAccountAndVaultStatusCheck(address(0));
    }
}
