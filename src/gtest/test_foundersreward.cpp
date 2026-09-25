#include <gtest/gtest.h>

#include "main.h"
#include "util/moneystr.h"
#include "chainparams.h"
#include "consensus/funding.h"
#include "fs.h"
#include "key_io.h"
#include "util/strencodings.h"
#include "zcash/Address.hpp"
#include "wallet/wallet.h"
#include "amount.h"
#include <memory>
#include <string>
#include <set>
#include <vector>
#include "util/system.h"
#include "util/test.h"

// To run tests:
// ./zcash-gtest --gtest_filter="FoundersRewardTest.*"

//
// Enable this test to generate and print 48 testnet 2-of-3 multisig addresses.
// The output can be copied into chainparams.cpp.
// The temporary wallet file can be renamed as wallet.dat and used for testing with zcashd.
//
#if 0
TEST(FoundersRewardTest, create_testnet_2of3multisig) {
    SelectParams(CBaseChainParams::TESTNET);
    fs::path pathTemp = fs::temp_directory_path() / fs::unique_path();
    fs::create_directories(pathTemp);
    mapArgs["-datadir"] = pathTemp.string();
    bool fFirstRun;
    auto pWallet = std::make_shared<CWallet>("wallet.dat");
    ASSERT_EQ(DB_LOAD_OK, pWallet->LoadWallet(fFirstRun));
    pWallet->TopUpKeyPool();
    std::cout << "Test wallet and logs saved in folder: " << pathTemp.native() << std::endl;
    
    int numKeys = 48;
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(3);
    CPubKey newKey;
    std::vector<std::string> addresses;
    KeyIO keyIO(Params());
    for (int i = 0; i < numKeys; i++) {
        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[0] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[1] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        ASSERT_TRUE(pWallet->GetKeyFromPool(newKey));
        pubkeys[2] = newKey;
        pWallet->SetAddressBook(newKey.GetID(), "", "receive");

        CScript result = GetScriptForMultisig(2, pubkeys);
        ASSERT_FALSE(result.size() > MAX_SCRIPT_ELEMENT_SIZE);
        CScriptID innerID(result);
        pWallet->AddCScript(result);
        pWallet->SetAddressBook(innerID, "", "receive");

        std::string address = keyIO.EncodeDestination(innerID);
        addresses.push_back(address);
    }
    
    // Print out the addresses, 4 on each line.
    std::string s = "vFoundersRewardAddress = {\n";
    int i=0;
    int colsPerRow = 4;
    ASSERT_TRUE(numKeys % colsPerRow == 0);
    int numRows = numKeys/colsPerRow;
    for (int row=0; row<numRows; row++) {
        s += "    ";
        for (int col=0; col<colsPerRow; col++) {
            s += "\"" + addresses[i++] + "\", ";
        }
        s += "\n";
    }
    s += "    };";
    std::cout << s << std::endl;

    pWallet->Flush(true);
}
#endif


static int GetLastFoundersRewardHeight(const Consensus::Params& params) {
    int blossomActivationHeight = Params().GetConsensus().vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
    bool blossom = blossomActivationHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
    return params.GetLastFoundersRewardBlockHeight(blossom ? blossomActivationHeight : 0);
}

// Utility method to check the number of unique addresses from height 1 to maxHeight
void checkNumberOfUniqueAddresses(int nUnique) {
    std::set<std::string> addresses;
    for (int i = 1; i <= GetLastFoundersRewardHeight(Params().GetConsensus()); i++) {
        addresses.insert(Params().GetFoundersRewardAddressAtHeight(i));
    }
    EXPECT_EQ(addresses.size(), nUnique);
}

int GetMaxFundingStreamHeight(const Consensus::Params& params) {
    int result = 0;
    for (auto fs : params.vFundingStreams) {
        if (fs && result < fs.value().GetEndHeight() - 1) {
            result = fs.value().GetEndHeight() - 1;
        }
    }

    return result;
}


TEST(FoundersRewardTest, RegtestGetLastBlockBlossom) {
    int blossomActivationHeight = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL / 2; // = 75
    auto params = RegtestActivateBlossom(false, blossomActivationHeight).GetConsensus();
    int lastFRHeight = params.GetLastFoundersRewardBlockHeight(blossomActivationHeight);
    EXPECT_EQ(0, params.Halving(lastFRHeight));
    EXPECT_EQ(1, params.Halving(lastFRHeight + 1));
    RegtestDeactivateBlossom();
}

// Tcoin: mainnet and testnet have no Founders' Reward (see test_tcoin_params.cpp);
// only regtest keeps the Zcash rule, so only regtest is tested here.
#define NUM_REGTEST_FOUNDER_ADDRESSES 1

TEST(FoundersRewardTest, Regtest) {
    SelectParams(CBaseChainParams::REGTEST);
    checkNumberOfUniqueAddresses(NUM_REGTEST_FOUNDER_ADDRESSES);
}



// Verify that post-Canopy, block rewards are split according to ZIP 207.
TEST(FundingStreamsRewardTest, Zip207Distribution) {
    auto consensus = RegtestActivateCanopy(false, 200);

    int minHeight = GetLastFoundersRewardHeight(consensus) + 1;

    KeyIO keyIO(Params());
    auto sk = libzcash::SaplingSpendingKey(uint256());
    for (int idx = Consensus::FIRST_FUNDING_STREAM; idx < Consensus::MAX_FUNDING_STREAMS; idx++) {
        // we can just use the same addresses for all streams, all we're trying to do here
        // is validate that the streams add up to the 20% of block reward.
        auto shieldedAddr = keyIO.EncodePaymentAddress(sk.default_address());
        UpdateFundingStreamParameters(
            (Consensus::FundingStreamIndex) idx,
            Consensus::FundingStream::ParseFundingStream(
                consensus,
                Params(),
                minHeight, 
                minHeight + 12, 
                {
                    "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi",
                    shieldedAddr,
                },
                false
            )
        );
    }

    int maxHeight = GetMaxFundingStreamHeight(consensus);
    std::map<std::string, CAmount> ms;
    for (int nHeight = minHeight; nHeight <= maxHeight; nHeight++) {
        auto blockSubsidy = consensus.GetBlockSubsidy(nHeight);
        auto elems = consensus.GetActiveFundingStreamElements(nHeight, blockSubsidy);

        CAmount totalFunding = 0;
        for (Consensus::FundingStreamElement elem : elems) {
            totalFunding += elem.second;
        }
        EXPECT_EQ(totalFunding, blockSubsidy / 5);
    }

    RegtestDeactivateCanopy();
}

TEST(FundingStreamsRewardTest, ParseFundingStream) {
    auto consensus = RegtestActivateCanopy(false, 200);

    int minHeight = GetLastFoundersRewardHeight(consensus) + 1;

    KeyIO keyIO(Params());
    auto sk = libzcash::SaplingSpendingKey(uint256());
    auto shieldedAddr = keyIO.EncodePaymentAddress(sk.default_address());
    ASSERT_THROW(
        Consensus::FundingStream::ParseFundingStream(
            consensus,
            Params(),
            minHeight, 
            minHeight + 13, 
            {
                "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi",
                shieldedAddr,
            },
            false
        ),
        std::runtime_error
    );

    RegtestDeactivateCanopy();
}
