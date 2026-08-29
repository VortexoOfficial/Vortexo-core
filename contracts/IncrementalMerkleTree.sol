// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPoseidonT3 {
    function poseidon(uint256[2] calldata input) external pure returns (uint256);
}

/// @title IncrementalMerkleTree
/// @notice Maintains FOUR fully independent Merkle trees
abstract contract IncrementalMerkleTree {
    uint32 public constant LEVELS = 20;
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    uint256 private constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IPoseidonT3 public immutable poseidonHasher;

    
    mapping(uint32 => uint256) public zeros;

   
    mapping(uint8 => uint256) public nextIndex;
    mapping(uint8 => mapping(uint32 => uint256)) public filledSubtrees;
    mapping(uint8 => uint256[ROOT_HISTORY_SIZE]) public roots;
    mapping(uint8 => uint32) public currentRootIndex;
    mapping(uint8 => mapping(uint32 => mapping(uint256 => uint256))) public treeNodes;
    mapping(uint8 => mapping(uint256 => uint256)) public commitmentToLeafIndexPlusOne;

    constructor(address _poseidonHasher) {
        poseidonHasher = IPoseidonT3(_poseidonHasher);

        uint256 currentZero = uint256(
            keccak256(abi.encodePacked("vortexofun.zk.empty.leaf", block.chainid))
        ) % FIELD_SIZE;

        for (uint32 i = 0; i < LEVELS; i++) {
            zeros[i] = currentZero;
            currentZero = hashLeftRight(currentZero, currentZero);
        }

      
        for (uint8 denom = 1; denom <= 4; denom++) {
            for (uint32 i = 0; i < LEVELS; i++) {
                filledSubtrees[denom][i] = zeros[i];
            }
            roots[denom][0] = currentZero;
        }
    }

    function hashLeftRight(uint256 left, uint256 right) public view returns (uint256) {
        return poseidonHasher.poseidon([left, right]);
    }

    function _insert(uint256 leaf, uint8 denom) internal returns (uint32 insertedIndex) {
        uint32 currentIndex = uint32(nextIndex[denom]);
        require(currentIndex != uint32(2 ** LEVELS), "VF: Merkle tree is full");

       
        require(leaf != 0, "VF: commitment cannot be zero");

       
        require(commitmentToLeafIndexPlusOne[denom][leaf] == 0, "VF: commitment already used");

        uint256 currentHash = leaf;
        uint256 idx = currentIndex;

        for (uint32 i = 0; i < LEVELS; i++) {
            treeNodes[denom][i][idx] = currentHash;

            if (idx % 2 == 0) {
                filledSubtrees[denom][i] = currentHash;
                currentHash = hashLeftRight(currentHash, zeros[i]);
            } else {
                currentHash = hashLeftRight(filledSubtrees[denom][i], currentHash);
            }
            idx /= 2;
        }

        uint32 newRootIndex = uint32((currentRootIndex[denom] + 1) % ROOT_HISTORY_SIZE);
        currentRootIndex[denom] = newRootIndex;
        roots[denom][newRootIndex] = currentHash;
        nextIndex[denom] = currentIndex + 1;

        commitmentToLeafIndexPlusOne[denom][leaf] = uint256(currentIndex) + 1;

        return currentIndex;
    }

    function getLeafIndex(uint256 commitment, uint8 denom) external view returns (bool exists, uint32 leafIndex) {
        uint256 stored = commitmentToLeafIndexPlusOne[denom][commitment];
        if (stored == 0) return (false, 0);
        return (true, uint32(stored - 1));
    }

    function getMerklePath(uint32 leafIndex, uint8 denom)
        external
        view
        returns (uint256[] memory pathElements, uint8[] memory pathIndices)
    {
        require(leafIndex < nextIndex[denom], "VF: leaf index out of range");

        pathElements = new uint256[](LEVELS);
        pathIndices = new uint8[](LEVELS);

        uint256 idx = leafIndex;
        for (uint32 i = 0; i < LEVELS; i++) {
            bool isRight = (idx % 2 == 1);
            uint256 siblingPos = isRight ? idx - 1 : idx + 1;

            uint256 storedValue = treeNodes[denom][i][siblingPos];
            pathElements[i] = storedValue != 0 ? storedValue : zeros[i];
            pathIndices[i] = isRight ? 1 : 0;

            idx /= 2;
        }
    }

    function isKnownRoot(uint256 root, uint8 denom) public view returns (bool) {
        if (root == 0) return false;
        uint32 i = currentRootIndex[denom];
        for (uint32 count = 0; count < ROOT_HISTORY_SIZE; count++) {
            if (roots[denom][i] == root) return true;
            if (i == 0) {
                i = uint32(ROOT_HISTORY_SIZE - 1);
            } else {
                i--;
            }
        }
        return false;
    }

    function getLastRoot(uint8 denom) public view returns (uint256) {
        return roots[denom][currentRootIndex[denom]];
    }
}
