// Copyright (c) 2026 The Tcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "blocksign.h"

#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"

#include <algorithm>

std::optional<CKey> g_blockSigningKey;

/** Domain tag, so that a block signature can never be valid as any other signature. */
static const std::string BLOCK_SIGNATURE_TAG = "Tcoin block signature";

/**
 * Returns true if the transaction is a v5 transaction, whose txid does not
 * cover transparent scriptSigs (ZIP 244).
 */
static bool IsV5Transaction(const CTransaction& tx)
{
    return tx.fOverwintered && tx.nVersion >= ZIP225_MIN_TX_VERSION;
}

uint256 BlockSignatureHash(const uint256& hashPrevBlock, const uint256& hashMerkleRoot)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << BLOCK_SIGNATURE_TAG << hashPrevBlock << hashMerkleRoot;
    return ss.GetHash();
}

std::optional<std::vector<unsigned char>> ExtractBlockSignature(const CTransaction& coinbase)
{
    if (!coinbase.IsCoinBase()) {
        return std::nullopt;
    }
    const CScript& scriptSig = coinbase.vin[0].scriptSig;
    CScript::const_iterator pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;

    // The first push is the BIP 34 height, the second one the signature.
    if (!scriptSig.GetOp(pc, opcode, data)) {
        return std::nullopt;
    }
    if (!scriptSig.GetOp(pc, opcode, data) || data.size() != BLOCK_SIGNATURE_SIZE) {
        return std::nullopt;
    }
    return data;
}

bool CheckBlockSignature(
    const CBlock& block,
    const std::vector<CPubKey>& signers,
    std::string& strError)
{
    const CTransaction& coinbase = block.vtx[0];
    if (!IsV5Transaction(coinbase)) {
        strError = "coinbase of a signed block must be a v5 transaction";
        return false;
    }

    auto signature = ExtractBlockSignature(coinbase);
    if (!signature.has_value()) {
        strError = "block signature missing from coinbase";
        return false;
    }

    CPubKey signer;
    uint256 hash = BlockSignatureHash(block.hashPrevBlock, block.hashMerkleRoot);
    if (!signer.RecoverCompact(hash, signature.value())) {
        strError = "block signature is malformed";
        return false;
    }
    if (std::find(signers.begin(), signers.end(), signer) == signers.end()) {
        strError = "block is not signed by an authorized block signer";
        return false;
    }
    return true;
}

bool SignBlock(CBlock& block, int nHeight, const CKey& key)
{
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase() || !IsV5Transaction(block.vtx[0])) {
        return false;
    }

    // With a v5 coinbase the merkle root does not depend on the scriptSig, so
    // it is the same before and after the signature is written.
    uint256 hashMerkleRoot = BlockMerkleRoot(block);
    std::vector<unsigned char> signature;
    if (!key.SignCompact(BlockSignatureHash(block.hashPrevBlock, hashMerkleRoot), signature)) {
        return false;
    }

    CMutableTransaction coinbase(block.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << nHeight << signature;
    block.vtx[0] = coinbase;
    block.hashMerkleRoot = hashMerkleRoot;
    return true;
}
