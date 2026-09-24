// Copyright (c) 2026 The Tcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef TCOIN_BLOCKSIGN_H
#define TCOIN_BLOCKSIGN_H

#include "key.h"
#include "primitives/block.h"
#include "pubkey.h"
#include "uint256.h"

#include <optional>
#include <string>
#include <vector>

/**
 * Tcoin block signatures.
 *
 * Mining on Tcoin is centralized: on a network with authorized block signers
 * (CChainParams::BlockSignerPubKeys), a block is valid only if it carries a
 * signature by one of them, whatever its proof of work. Anyone can still run a
 * node and a wallet, and every node checks every block and transaction.
 *
 * The signature is a 65-byte compact ECDSA signature, placed in the coinbase
 * scriptSig right after the BIP 34 height:
 *
 *     scriptSig = <height> <signature> [extra nonce and flags]
 *
 * It signs BlockSignatureHash(hashPrevBlock, hashMerkleRoot). The coinbase must
 * be a v5 transaction: a v5 txid (ZIP 244) does not cover the scriptSig, so
 * writing the signature does not change the merkle root that it signs. The
 * signature therefore fixes the parent block and every transaction, including
 * every coinbase output; what it leaves free (time, nonce, Equihash solution)
 * only lets someone re-mine the same signed block, never a different one.
 */

/** Size of a compact ECDSA signature, as produced by CKey::SignCompact. */
static const size_t BLOCK_SIGNATURE_SIZE = 65;

/**
 * Computes the message that a block signer signs.
 *
 * @param hashPrevBlock   hash of the parent block
 * @param hashMerkleRoot  merkle root of the block's transactions (v5 txids)
 * @return                a double-SHA256 hash of a domain tag and both inputs
 */
uint256 BlockSignatureHash(const uint256& hashPrevBlock, const uint256& hashMerkleRoot);

/**
 * Reads the block signature from a coinbase transaction.
 *
 * @param coinbase  the first transaction of a block
 * @return          the second push of the scriptSig if it is exactly
 *                  BLOCK_SIGNATURE_SIZE bytes long, std::nullopt otherwise
 */
std::optional<std::vector<unsigned char>> ExtractBlockSignature(const CTransaction& coinbase);

/**
 * Checks that a block is signed by one of the authorized block signers.
 *
 * The caller must already have checked that the block has a coinbase and, for
 * the result to mean anything, that hashMerkleRoot matches the transactions
 * (CheckBlock does both).
 *
 * @param block     the block to check
 * @param signers   the authorized signers' compressed public keys
 * @param strError  set to the reason for rejection when the check fails
 * @return          true if the coinbase is v5 and carries a valid signature by
 *                  one of the signers
 */
bool CheckBlockSignature(
    const CBlock& block,
    const std::vector<CPubKey>& signers,
    std::string& strError);

/**
 * Signs a block template and writes the signature into its coinbase.
 *
 * Sets block.hashMerkleRoot, then replaces the coinbase scriptSig with
 * <nHeight> <signature>. hashPrevBlock and every transaction must be final;
 * NU5 block commitments (auth data root) must be recomputed afterwards,
 * because they cover the scriptSig.
 *
 * @param block    the block template; its first transaction must be a v5 coinbase
 * @param nHeight  the height of the block
 * @param key      the signer's private key
 * @return         false if the coinbase is not v5 or signing fails; the block
 *                 is then left unchanged
 */
bool SignBlock(CBlock& block, int nHeight, const CKey& key);

/**
 * The key this node signs its block templates with, loaded at startup from
 * -blocksignkeyfile. Empty on nodes that do not produce blocks.
 */
extern std::optional<CKey> g_blockSigningKey;

#endif // TCOIN_BLOCKSIGN_H
