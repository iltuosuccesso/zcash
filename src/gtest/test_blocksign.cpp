// Copyright (c) 2026 The Tcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <gtest/gtest.h>

#include "blocksign.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "key.h"
#include "main.h"
#include "random.h"
#include "util/test.h"

namespace {

/**
 * Builds an unsigned block whose only transaction is a coinbase paying 1 coin.
 *
 * @param params     consensus parameters used to pick the transaction version
 * @param nHeight    height of the block
 * @param requireV4  true to force a v4 coinbase instead of the default v5
 * @return           the block, with a random parent hash
 */
CBlock MakeBlock(const Consensus::Params& params, int nHeight, bool requireV4)
{
    CMutableTransaction coinbase = CreateNewContextualCMutableTransaction(params, nHeight, requireV4);
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << nHeight << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = COIN;
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CBlock block;
    block.hashPrevBlock = GetRandHash();
    block.vtx.push_back(coinbase);
    return block;
}

/**
 * Creates a new compressed key pair.
 *
 * @return  the private key; its public key is key.GetPubKey()
 */
CKey MakeKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

} // namespace

class BlockSignTest : public ::testing::Test {
protected:
    const Consensus::Params* params;
    void SetUp() override { params = &RegtestActivateNU5(); }
    void TearDown() override { RegtestDeactivateNU5(); }
};

TEST_F(BlockSignTest, SignedBlockIsAccepted)
{
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);

    ASSERT_TRUE(SignBlock(block, 10, key));
    EXPECT_EQ(block.hashMerkleRoot, BlockMerkleRoot(block));

    std::string strError;
    EXPECT_TRUE(CheckBlockSignature(block, {key.GetPubKey()}, strError)) << strError;
}

TEST_F(BlockSignTest, SignatureSurvivesExtraNonce)
{
    // The miner changes the scriptSig after signing (IncrementExtraNonce).
    // With a v5 coinbase this must change neither the merkle root nor the
    // validity of the signature.
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);
    ASSERT_TRUE(SignBlock(block, 10, key));
    uint256 signedRoot = block.hashMerkleRoot;

    auto signature = ExtractBlockSignature(block.vtx[0]);
    ASSERT_TRUE(signature.has_value());
    CMutableTransaction coinbase(block.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << 10 << signature.value() << CScriptNum(12345);
    block.vtx[0] = coinbase;

    EXPECT_EQ(BlockMerkleRoot(block), signedRoot);
    std::string strError;
    EXPECT_TRUE(CheckBlockSignature(block, {key.GetPubKey()}, strError)) << strError;
}

TEST_F(BlockSignTest, UnauthorizedSignerIsRejected)
{
    CKey key = MakeKey();
    CKey authorized = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);
    ASSERT_TRUE(SignBlock(block, 10, key));

    std::string strError;
    EXPECT_FALSE(CheckBlockSignature(block, {authorized.GetPubKey()}, strError));
    EXPECT_EQ(strError, "block is not signed by an authorized block signer");
}

TEST_F(BlockSignTest, ChangedCoinbaseOutputIsRejected)
{
    // Someone who copies a signed coinbase cannot redirect its reward.
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);
    ASSERT_TRUE(SignBlock(block, 10, key));

    CMutableTransaction coinbase(block.vtx[0]);
    coinbase.vout[0].scriptPubKey = CScript() << OP_FALSE;
    block.vtx[0] = coinbase;
    block.hashMerkleRoot = BlockMerkleRoot(block);

    std::string strError;
    EXPECT_FALSE(CheckBlockSignature(block, {key.GetPubKey()}, strError));
}

TEST_F(BlockSignTest, OtherParentIsRejected)
{
    // A signature is valid for one parent only, so it cannot extend another chain.
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);
    ASSERT_TRUE(SignBlock(block, 10, key));

    block.hashPrevBlock = GetRandHash();

    std::string strError;
    EXPECT_FALSE(CheckBlockSignature(block, {key.GetPubKey()}, strError));
}

TEST_F(BlockSignTest, MissingSignatureIsRejected)
{
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, false);
    block.hashMerkleRoot = BlockMerkleRoot(block);

    EXPECT_FALSE(ExtractBlockSignature(block.vtx[0]).has_value());
    std::string strError;
    EXPECT_FALSE(CheckBlockSignature(block, {key.GetPubKey()}, strError));
    EXPECT_EQ(strError, "block signature missing from coinbase");
}

TEST_F(BlockSignTest, V4CoinbaseCannotBeSigned)
{
    // A v4 txid covers the scriptSig, so writing the signature would change
    // the merkle root it signs.
    CKey key = MakeKey();
    CBlock block = MakeBlock(*params, 10, true);

    EXPECT_FALSE(SignBlock(block, 10, key));
    std::string strError;
    EXPECT_FALSE(CheckBlockSignature(block, {key.GetPubKey()}, strError));
    EXPECT_EQ(strError, "coinbase of a signed block must be a v5 transaction");
}
