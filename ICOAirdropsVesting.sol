// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @author Jorge Gomes Durán (jorge@smartrights.io)
/// @title A vesting contract to lock tokens for iCommunity token Icom

contract ICOAirdropsVesting {

    address immutable private icomToken;
    address immutable private owner;
    uint32 private listingDate;
    uint32 constant private MAX_LISTING_DATE = 1672441200;  // 2022/12/31 00:00:00

    mapping(bytes32 => bool) private signatures;

    event ICOTokensSent(uint256 _unlockDate);

    constructor(address _token) {
        icomToken = _token;
        owner = msg.sender;
    }

    function setListingDate(uint32 _listingDate) external {
        require(msg.sender == owner, "OnlyOwner");
        require(_listingDate < MAX_LISTING_DATE, "CantDelayMoreListing");
        require(block.timestamp < _listingDate, "CantListInPast");

        listingDate = _listingDate;
    }

    function airdrop(bytes calldata _message, bytes calldata _messageLength, bytes calldata _signature) external {
        require(listingDate > 0, "NoListingDate");
        require(_processedSignature(_signature) == false, "Processed");
        require(block.timestamp > listingDate + 150 days, "TokensVested");   // TODO

        address _signer = _decodeSignature(_message, _messageLength, _signature);
        require(_signer == owner, "BadOwner");

        (address[] memory _users, uint256[] memory _amounts, uint16[] memory _nonces) = abi.decode(_message, (address[], uint256[], uint16[]));
        require(_users.length == _amounts.length, "BadLengths");

        for (uint i=0; i<_users.length; i++) {
            IERC20(icomToken).transfer(_users[i], _amounts[i]);
        }

        signatures[keccak256(_signature)] = true;

        emit ICOTokensSent(block.timestamp);
    }

    function _processedSignature(bytes calldata _signature) internal view returns(bool) {
        return signatures[keccak256(_signature)];
    }

    function _decodeSignature(bytes memory _message, bytes memory _messageLength, bytes memory _signature) internal pure returns (address) {
        if (_signature.length != 65) return (address(0));

        bytes32 messageHash = keccak256(abi.encodePacked(hex"19457468657265756d205369676e6564204d6573736167653a0a", _messageLength, _message));
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);

        if (v != 27 && v != 28) return address(0);
        
        return ecrecover(messageHash, v, r, s);
    }
}
