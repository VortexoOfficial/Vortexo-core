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
///         
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

    
    uint256 public constant RELAYER_REGISTRATION_FEE = 0.01 ether;
    uint8 public constant MAX_FEE_TIER = 3;
    uint256 public relayerFeesCollected;

    struct Relayer {
        uint8 feeTier;    
        string endpoint;  
        bool active;
    }

    mapping(address => Relayer) public relayers;
    address[] private relayerAddresses;

    event RelayerRegistered(address indexed relayer, uint8 feeTier, string endpoint);
    event RelayerUpdated(address indexed relayer, uint8 feeTier, string endpoint);
    event RelayerDeactivated(address indexed relayer);
    event RelayerReactivated(address indexed relayer);

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

        if (fee == 0) {
            // Self-withdrawal: the user submits the proof themselves, pays gas
            // directly, and keeps the full net amount. No relayer involved.
            // (The `relayer` public signal is simply the user's own address.)
        } else {
            // Relayer-assisted withdrawal: the fee is the relayer's reward.
            // Enforce the marketplace rules on-chain — the relayer must be a
            // registered (0.01 ETH paid) active relayer, and the fee must be
            // EXACTLY denomination * relayer's tier / 1000. No relayer can
            // ever charge more than 0.3%, and no user can underpay a tier.
            require(relayers[relayer].active, "VF: relayer not registered");
            require(fee == (amount * relayers[relayer].feeTier) / 1000, "VF: invalid relayer fee");
            require(fee <= netAmount, "VF: fee exceeds amount");
        }

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

  

    /// @notice Register as a relayer. Pays the one-time 0.01 ETH fee to the
    ///         owner and records the chosen fee tier + server endpoint.
    /// @param _feeTier 1 = 0.1%, 2 = 0.2%, 3 = 0.3% (maximum allowed).
    /// @param _endpoint HTTPS URL of this relayer's API server.
    function registerRelayer(uint8 _feeTier, string calldata _endpoint) external payable noReentrancy {
        require(msg.value == RELAYER_REGISTRATION_FEE, "VF: registration costs exactly 0.01 ETH");
        require(_feeTier >= 1 && _feeTier <= MAX_FEE_TIER, "VF: fee tier must be 1-3");
        require(!relayers[msg.sender].active, "VF: already registered");
        require(bytes(_endpoint).length > 0, "VF: endpoint required");

        relayers[msg.sender] = Relayer({ feeTier: _feeTier, endpoint: _endpoint, active: true });
        relayerAddresses.push(msg.sender);

        relayerFeesCollected += msg.value;

        emit RelayerRegistered(msg.sender, _feeTier, _endpoint);
    }

    /// @notice Change your fee tier (e.g. compete for users by lowering it).
    function updateRelayerFee(uint8 _feeTier) external {
        require(relayers[msg.sender].active, "VF: not a registered relayer");
        require(_feeTier >= 1 && _feeTier <= MAX_FEE_TIER, "VF: fee tier must be 1-3");
        relayers[msg.sender].feeTier = _feeTier;
        emit RelayerUpdated(msg.sender, _feeTier, relayers[msg.sender].endpoint);
    }

    /// @notice Update your server endpoint (e.g. after moving to a new host).
    function updateRelayerEndpoint(string calldata _endpoint) external {
        require(relayers[msg.sender].active, "VF: not a registered relayer");
        require(bytes(_endpoint).length > 0, "VF: endpoint required");
        relayers[msg.sender].endpoint = _endpoint;
        emit RelayerUpdated(msg.sender, relayers[msg.sender].feeTier, _endpoint);
    }

    /// @notice Leave the marketplace (keeps your registration, stops appearing active).
    function deactivateRelayer() external {
        require(relayers[msg.sender].active, "VF: not a registered relayer");
        relayers[msg.sender].active = false;
        emit RelayerDeactivated(msg.sender);
    }

    /// @notice Come back online without paying again — registration is for life.
    function reactivateRelayer() external {
        require(bytes(relayers[msg.sender].endpoint).length > 0, "VF: never registered");
        require(!relayers[msg.sender].active, "VF: already active");
        relayers[msg.sender].active = true;
        emit RelayerReactivated(msg.sender);
    }

    /// @notice Full list of wallets that have ever registered as relayers.
    function getRelayers() external view returns (address[] memory) {
        return relayerAddresses;
    }

    function getRelayerCount() external view returns (uint256) {
        return relayerAddresses.length;
    }

    /// @notice Registry entry for one relayer.
    /// @return feeTier per-mille tier (1..3)
    /// @return endpoint the relayer's API server URL
    /// @return active whether the relayer is currently in the marketplace
    function getRelayerInfo(address _relayer) external view returns (uint8 feeTier, string memory endpoint, bool active) {
        Relayer storage r = relayers[_relayer];
        return (r.feeTier, r.endpoint, r.active);
    }

    /// @notice The exact fee a given relayer earns for withdrawing a given
    ///         denomination — the same formula enforced inside withdraw().
    function getRelayerFeeForDenom(address _relayer, uint8 denom) external view returns (uint256) {
        require(relayers[_relayer].active, "VF: relayer not registered");
        require(denom >= 1 && denom <= 4, "VF: invalid denomination");
        return (getDenominationValue(denom) * relayers[_relayer].feeTier) / 1000;
    }

    /// @notice Owner withdraws the relayer registration fees accumulated in
    ///         the contract, at any time.
    function withdrawRelayerFees() external onlyOwner noReentrancy {
        uint256 amount = relayerFeesCollected;
        require(amount > 0, "VF: no relayer fees to withdraw");
        relayerFeesCollected = 0;
        (bool sent, ) = owner.call{value: amount}("");
        require(sent, "VF: fee withdrawal failed");
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
