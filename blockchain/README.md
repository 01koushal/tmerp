# Smart-contract integration plan

The Flask prototype currently runs without a blockchain node. For a trust-minimized deployment, add a Solidity contract with:
- createEvidence(bytes32 evidenceId, bytes32 merkleRoot, uint256 threshold, address[] reviewers)
- approve(bytes32 evidenceId)
- challenge(bytes32 evidenceId, bytes32 reasonHash)
- resolveChallenge(bytes32 evidenceId, bool uphold)
- release state guarded by threshold and no active challenges

Use Hardhat for local development and Web3.py from Flask. Store only hashes and event metadata on-chain. Do not treat the current SQLite audit table as immutable or trustless.
