// Copyright (c) 2026 The Tcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Tcoin genesis block miner.
//
// The genesis block of a new network needs an Equihash solution whose hash
// meets the genesis target. These tests find one and print the lines to paste
// into chainparams.cpp. They are disabled because they run for minutes to
// hours; run them once per network, on purpose:
//
//     TCOIN_GENESIS_THREADS=8 ./src/zcash-gtest \
//         --gtest_also_run_disabled_tests --gtest_filter='TcoinGenesis.*Mainnet'
//
// Each thread of the Equihash 144,5 solver uses about 1 GB of memory.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <gtest/gtest.h>

#include "arith_uint256.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "pow.h"
#include "primitives/block.h"
#include "streams.h"
#include "tinyformat.h"
#include "util/strencodings.h"
#include "util/time.h"
#include "version.h"

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#ifdef ENABLE_MINING

namespace {

/**
 * Reads the number of solver threads from TCOIN_GENESIS_THREADS.
 *
 * @return  the value of the variable if it is a positive number, 4 otherwise
 */
unsigned int GenesisThreads()
{
    const char* value = std::getenv("TCOIN_GENESIS_THREADS");
    int threads = value ? std::atoi(value) : 0;
    return threads > 0 ? threads : 4;
}

/**
 * Finds an Equihash solution for a genesis block that meets its own target.
 *
 * Every thread tries a different sequence of nonces (thread i tries i,
 * i + nThreads, i + 2 * nThreads, ...) and all of them stop as soon as one
 * finds a block.
 *
 * @param base      the genesis block from chainparams, with nTime set; its
 *                  nNonce and nSolution are ignored
 * @param params    consensus parameters giving the Equihash N and K
 * @param nThreads  number of solver threads
 * @return          a copy of base with nNonce and nSolution filled in
 */
CBlock MineGenesis(const CBlock& base, const Consensus::Params& params, unsigned int nThreads)
{
    const unsigned int n = params.nEquihashN;
    const unsigned int k = params.nEquihashK;
    const arith_uint256 target = arith_uint256().SetCompact(base.nBits);

    std::atomic<bool> found{false};
    std::mutex resultMutex;
    CBlock result;

    auto worker = [&](unsigned int index) {
        CBlock candidate = base;
        arith_uint256 nonce = index;
        while (!found) {
            candidate.nNonce = ArithToUint256(nonce);

            // H(I||V||...), where I is the header without nonce and solution.
            eh_HashState state = EhInitialiseState(n, k);
            CEquihashInput I{candidate};
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << I;
            state.Update((unsigned char*)&ss[0], ss.size());
            state.Update(candidate.nNonce.begin(), candidate.nNonce.size());

            std::function<bool(std::vector<unsigned char>)> validBlock =
                [&](std::vector<unsigned char> soln) {
                    candidate.nSolution = soln;
                    if (UintToArith256(candidate.GetHash()) > target) {
                        return false;
                    }
                    std::lock_guard<std::mutex> lock(resultMutex);
                    if (!found) {
                        result = candidate;
                        found = true;
                    }
                    return true;
                };
            std::function<bool(EhSolverCancelCheck)> cancelled =
                [&](EhSolverCancelCheck) { return found.load(); };

            try {
                EhOptimisedSolve(n, k, state, validBlock, cancelled);
            } catch (EhSolverCancelledException&) {
                // Another thread found the block.
            }
            nonce += nThreads;
        }
    };

    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < nThreads; i++) {
        threads.emplace_back(worker, i);
    }
    for (auto& thread : threads) {
        thread.join();
    }
    return result;
}

/**
 * Mines the genesis block of a network, checks it and prints the lines to
 * paste into that network's section of chainparams.cpp.
 *
 * @param network  CBaseChainParams::MAIN or CBaseChainParams::TESTNET
 */
void MineAndPrintGenesis(const std::string& network)
{
    SelectParams(network);
    const CChainParams& chainparams = Params();
    const Consensus::Params& consensus = chainparams.GetConsensus();

    CBlock base = chainparams.GenesisBlock();
    base.nTime = GetTime();

    unsigned int nThreads = GenesisThreads();
    std::cout << "Mining the '" << network << "' genesis block (Equihash "
              << consensus.nEquihashN << "," << consensus.nEquihashK << ", "
              << nThreads << " threads)..." << std::endl;
    CBlock genesis = MineGenesis(base, consensus, nThreads);

    ASSERT_TRUE(CheckEquihashSolution(&genesis, consensus));
    ASSERT_TRUE(CheckProofOfWork(genesis.GetHash(), genesis.nBits, consensus));

    std::cout << "\nReplace the genesis block of the '" << network
              << "' network in chainparams.cpp with:\n\n"
              << "        genesis = CreateGenesisBlock(\n"
              << "            TCOIN_GENESIS_TIMESTAMP,\n"
              << "            " << genesis.nTime << ",\n"
              << "            uint256S(\"0x" << genesis.nNonce.GetHex() << "\"),\n"
              << "            ParseHex(\"" << HexStr(genesis.nSolution) << "\"),\n"
              << "            " << strprintf("0x%08x", genesis.nBits) << ", 4, 0);\n"
              << "        consensus.hashGenesisBlock = genesis.GetHash();\n"
              << "        assert(consensus.hashGenesisBlock == uint256S(\"0x"
              << genesis.GetHash().GetHex() << "\"));\n"
              << "        assert(genesis.hashMerkleRoot == uint256S(\"0x"
              << genesis.hashMerkleRoot.GetHex() << "\"));\n"
              << std::endl;
}

} // namespace

TEST(TcoinGenesis, DISABLED_MineMainnet)
{
    MineAndPrintGenesis(CBaseChainParams::MAIN);
}

TEST(TcoinGenesis, DISABLED_MineTestnet)
{
    MineAndPrintGenesis(CBaseChainParams::TESTNET);
}

#endif // ENABLE_MINING
