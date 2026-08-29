// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./IncrementalMerkleTree.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[6] calldata _pubSignals
    ) external view returns (bool);
}


/// @title VortexoFunZK
/// @notice zk-SNARK privacy protocol: deposit native assets, withdraw to any
///         address with a zero-knowledge proof. Revert-reason prefixes are "VF:".
contract VortexoFunZK is IncrementalMerkleTree {
    address public owner;
    uint256 public feePercentage = 2;
    uint256 public totalFeesCollected;

    IGroth16Verifier public immutable verifier;

    mapping(uint8 => uint256) public poolBalance;
    mapping(bytes32 => bool) public nullifierHashes;

    uint8 public constant DENOM_01 = 1;
    uint8 public constant DENOM_1 = 2;
    uint8 public constant DENOM_10 = 3;
    uint8 public constant DENOM_100 = 4;

    bool private locked;

    event Deposit(uint32 indexed leafIndex, uint256 indexed commitment, uint8 denomination, uint256 timestamp);
    event Withdrawal(address indexed recipient, bytes32 indexed nullifierHash, uint8 denomination, uint256 amount, uint256 fee, address relayer);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event FeeUpdated(uint256 oldFee, uint256 newFee);

    modifier onlyOwner() {
        require(msg.sender == owner, "VF: caller is not owner");
        _;
    }

    modifier noReentrancy() {
        require(!locked, "VF: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _poseidonHasher, address _verifier) IncrementalMerkleTree(_poseidonHasher) {
        owner = msg.sender;
        verifier = IGroth16Verifier(_verifier);
    }

    function getDenominationValue(uint8 denom) public pure returns (uint256) {
        if (denom == DENOM_01) return 0.1 ether;
        if (denom == DENOM_1) return 1 ether;
        if (denom == DENOM_10) return 10 ether;
        if (denom == DENOM_100) return 100 ether;
        revert("VF: invalid denomination");
    }

    function deposit(uint256 commitment, uint8 denom) external payable noReentrancy {
        require(denom >= 1 && denom <= 4, "VF: invalid denomination");
        uint256 expectedAmount = getDenominationValue(denom);
        require(msg.value == expectedAmount, "VF: incorrect amount");

        uint256 fee = (msg.value * feePercentage) / 100;
        uint256 netAmount = msg.value - fee;

        uint32 leafIndex = _insert(commitment, denom);
        poolBalance[denom] += netAmount;
        totalFeesCollected += fee;

        emit Deposit(leafIndex, commitment, denom, block.timestamp);

      
        if (fee > 0) {
            (bool feeSuccess, ) = owner.call{value: fee}("");
            require(feeSuccess, "VF: fee transfer failed");
        }
    }

    function withdraw(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256 root,
        bytes32 nullifierHash,
        address payable recipient,
        address payable relayer,
        uint256 fee,
        uint8 denom
    ) external noReentrancy {
        require(denom >= 1 && denom <= 4, "VF: invalid denomination");
        
        require(isKnownRoot(root, denom), "VF: unknown root");
        require(!nullifierHashes[nullifierHash], "VF: note already spent");

        uint256 amount = getDenominationValue(denom);

        uint256 netAmount = (amount * (100 - feePercentage)) / 100;
        require(fee <= netAmount, "VF: fee exceeds amount");

        uint[6] memory publicSignals = [
            root,
            uint256(nullifierHash),
            uint256(uint160(address(recipient))),
            uint256(uint160(address(relayer))),
            fee,
            uint256(denom)
        ];

       
        require(verifier.verifyProof(_pA, _pB, _pC, publicSignals), "VF: invalid proof");

        nullifierHashes[nullifierHash] = true;
        poolBalance[denom] -= netAmount;

        uint256 recipientAmount = netAmount - fee;

       
        (bool sentToRecipient, ) = recipient.call{value: recipientAmount}("");
        require(sentToRecipient, "VF: transfer to recipient failed");

        if (fee > 0) {
            (bool sentToRelayer, ) = relayer.call{value: fee}("");
            require(sentToRelayer, "VF: transfer to relayer failed");
        }

        emit Withdrawal(recipient, nullifierHash, denom, recipientAmount, fee, relayer);
    }

    function isSpent(bytes32 nullifierHash) external view returns (bool) {
        return nullifierHashes[nullifierHash];
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "VF: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function updateFee(uint256 newFee) external onlyOwner {
        require(newFee <= 5, "VF: fee too high (max 5%)");
      
        require(
            nextIndex[DENOM_01] == 0 &&
            nextIndex[DENOM_1] == 0 &&
            nextIndex[DENOM_10] == 0 &&
            nextIndex[DENOM_100] == 0,
            "VF: fee locked after first deposit"
        );
        emit FeeUpdated(feePercentage, newFee);
        feePercentage = newFee;
    }

    receive() external payable {
        revert("VF: direct transfers not allowed");
    }
}
