// Copyright (c) 2026 The Tcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Checks the Tcoin consensus parameters of mainnet and testnet: emission,
// absence of Zcash funding, network upgrades, block time and network identity.

#include <gtest/gtest.h>

#include "amount.h"
#include "chainparams.h"
#include "consensus/upgrades.h"
#include "key.h"
#include "key_io.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

/**
 * Returns the two public Tcoin networks, which share the same consensus rules.
 *
 * A function rather than a global vector: CBaseChainParams::MAIN and TESTNET
 * are defined in another file, and a global initialized from them could be
 * built before them, with empty names.
 *
 * @return  the network names MAIN and TESTNET
 */
std::vector<std::string> TcoinNetworks()
{
    return {CBaseChainParams::MAIN, CBaseChainParams::TESTNET};
}

} // namespace

TEST(TcoinParams, EmissionSchedule)
{
    for (const auto& network : TcoinNetworks()) {
        SCOPED_TRACE(network);
        SelectParams(network);
        const Consensus::Params& params = Params().GetConsensus();

        EXPECT_EQ(params.GetBlockSubsidy(0), 0);
        EXPECT_EQ(params.GetBlockSubsidy(1), 10000000 * COIN);
        EXPECT_EQ(params.GetBlockSubsidy(2), 125 * COIN / 10);
        EXPECT_EQ(params.GetBlockSubsidy(7200001), 125 * COIN / 10);
        EXPECT_EQ(params.GetBlockSubsidy(7200002), COIN / 10);
        EXPECT_EQ(params.GetBlockSubsidy(100000000), COIN / 10);

        // Premine plus the fixed-subsidy blocks issue exactly 100M coins.
        CAmount issued = params.GetBlockSubsidy(1) +
            CAmount(params.nLastFixedSubsidyHeight - 1) * params.nFixedBlockSubsidy;
        EXPECT_EQ(issued, 100000000 * COIN);

        // Chain-wide totals must have room for the tail emission; single
        // amounts keep the limit of the Rust libraries.
        EXPECT_GT(MAX_SUPPLY, issued);
        EXPECT_EQ(MAX_MONEY, 21000000 * COIN);
    }
}

TEST(TcoinParams, NoFundingStreamsOrFoundersReward)
{
    for (const auto& network : TcoinNetworks()) {
        SCOPED_TRACE(network);
        SelectParams(network);
        const Consensus::Params& params = Params().GetConsensus();

        // Canopy from block 1 switches the Founders' Reward rule off.
        EXPECT_TRUE(params.NetworkUpgradeActive(1, Consensus::UPGRADE_CANOPY));
        for (int nHeight : {1, 2, 1000, 3000000, 7200001, 7200002}) {
            EXPECT_TRUE(params.GetActiveFundingStreams(nHeight).empty()) << nHeight;
            EXPECT_TRUE(params.GetLockboxDisbursementsForHeight(nHeight).empty()) << nHeight;
        }
    }
}

TEST(TcoinParams, AllUpgradesActiveFromBlockOne)
{
    for (const auto& network : TcoinNetworks()) {
        SCOPED_TRACE(network);
        SelectParams(network);
        const Consensus::Params& params = Params().GetConsensus();

        for (auto idx : {
                Consensus::UPGRADE_OVERWINTER, Consensus::UPGRADE_SAPLING,
                Consensus::UPGRADE_BLOSSOM, Consensus::UPGRADE_HEARTWOOD,
                Consensus::UPGRADE_CANOPY, Consensus::UPGRADE_NU5,
                Consensus::UPGRADE_NU6, Consensus::UPGRADE_NU6_1,
                Consensus::UPGRADE_NU6_2}) {
            EXPECT_FALSE(params.NetworkUpgradeActive(0, idx)) << idx;
            EXPECT_TRUE(params.NetworkUpgradeActive(1, idx)) << idx;
            EXPECT_FALSE(params.vUpgrades[idx].hashActivationBlock.has_value()) << idx;
        }
        EXPECT_FALSE(params.TemporaryOrchardDisablingSoftForkActive(1000000));
    }
}

TEST(TcoinParams, BlockTimeAndEquihash)
{
    for (const auto& network : TcoinNetworks()) {
        SCOPED_TRACE(network);
        SelectParams(network);
        const Consensus::Params& params = Params().GetConsensus();

        EXPECT_EQ(params.PoWTargetSpacing(1), 75);
        EXPECT_EQ(params.PoWTargetSpacing(7200002), 75);
        EXPECT_EQ(params.nEquihashN, 144);
        EXPECT_EQ(params.nEquihashK, 5);
    }
}

TEST(TcoinParams, NetworkIdentityDiffersFromZcash)
{
    const unsigned char zcashMain[4] = {0x24, 0xe9, 0x27, 0x64};
    const unsigned char zcashTest[4] = {0xfa, 0x1a, 0xf9, 0xbf};

    SelectParams(CBaseChainParams::MAIN);
    EXPECT_NE(std::memcmp(Params().MessageStart(), zcashMain, 4), 0);
    EXPECT_NE(Params().BIP44CoinType(), 133u);
    EXPECT_TRUE(Params().DNSSeeds().empty());

    SelectParams(CBaseChainParams::TESTNET);
    EXPECT_NE(std::memcmp(Params().MessageStart(), zcashTest, 4), 0);
    EXPECT_TRUE(Params().DNSSeeds().empty());
}

TEST(TcoinParams, TransparentAddressPrefixes)
{
    CKey key = CKey::TestOnlyRandomKey(true);
    CTxDestination p2pkh = key.GetPubKey().GetID();
    CTxDestination p2sh = CScriptID(CScript() << OP_TRUE);

    SelectParams(CBaseChainParams::MAIN);
    KeyIO mainIO(Params());
    EXPECT_EQ(mainIO.EncodeDestination(p2pkh).substr(0, 2), "TL");
    EXPECT_EQ(mainIO.EncodeDestination(p2sh).substr(0, 2), "TS");

    SelectParams(CBaseChainParams::TESTNET);
    KeyIO testIO(Params());
    EXPECT_EQ(testIO.EncodeDestination(p2pkh).substr(0, 2), "tL");
    EXPECT_EQ(testIO.EncodeDestination(p2sh).substr(0, 2), "tS");
}
