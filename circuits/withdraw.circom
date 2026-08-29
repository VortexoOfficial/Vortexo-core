pragma circom 2.0.0;

include "poseidon.circom";
include "merkleTree.circom";

// depth = Merkle tree depth
template Withdraw(depth) {
    // Public inputs — these MUST all be used in a constraint below.
    signal input root;
    signal input nullifierHash;
    signal input recipient;   // address, as a field element
    signal input relayer;     // address, as a field element
    signal input fee;
    signal input denom;

    // Private inputs
    signal input secret;
    signal input nullifier;
    signal input depositDenom; // The denomination used when depositing (private witness)
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // 1) Recompute the commitment from the private note values INCLUDING denomination.
    //    This cryptographically binds the commitment to a specific denomination pool,
    //    preventing cross-denomination attacks (e.g., depositing 0.1 ETH, withdrawing 100 ETH).
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifier;
    commitmentHasher.inputs[2] <== depositDenom;
    signal commitment;
    commitment <== commitmentHasher.out;

    // 2) CRITICAL SECURITY CONSTRAINT: Ensure the claimed withdrawal denomination matches
    //    the deposit denomination. Without this, an attacker could deposit in one pool
    //    and withdraw from a different (larger) pool.
    denom === depositDenom;

    // 3) Recompute nullifierHash from the private nullifier and constrain
    //    it against the public nullifierHash input. This is what lets the
    //    contract detect double-spends WITHOUT learning which commitment
    //    this nullifier belongs to.
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash === nullifierHasher.out;

    // 3) Prove `commitment` is a real leaf in the tree that produced `root`.
    component tree = MerkleTreeChecker(depth);
    tree.leaf <== commitment;
    for (var i = 0; i < depth; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    root === tree.root;

    // 4) Bind recipient, relayer, fee, denom into the proof so they cannot
    //    be swapped after the proof is generated. Squaring is a cheap,
    //    standard trick to force the circuit to actually use each public
    //    signal in a constraint (an unconstrained public input is the
    //    classic way these systems get silently broken — changing it in
    //    calldata would otherwise NOT invalidate the proof).
    signal recipientSquare;
    recipientSquare <== recipient * recipient;

    signal relayerSquare;
    relayerSquare <== relayer * relayer;

    signal feeSquare;
    feeSquare <== fee * fee;

    signal denomSquare;
    denomSquare <== denom * denom;
}

component main {public [root, nullifierHash, recipient, relayer, fee, denom]} = Withdraw(20);
