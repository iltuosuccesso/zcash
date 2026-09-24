// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2017-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <stdlib.h>
#include <string>

typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

extern const std::string CURRENCY_UNIT;
extern const std::string MINOR_CURRENCY_UNIT;

/** No amount larger than this (in zatoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Zcash
 * currently happens to be less than 21,000,000 ZEC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
/*
 * Tcoin: total issuance reaches 100M TLC after the fixed-subsidy period and
 * then grows by 0.1 TLC per block (see Consensus::Params::GetBlockSubsidy).
 * The chain supply is itself checked against MAX_MONEY, so the bound must be
 * above 100M or the chain would stop at the first tail-emission block. 200M
 * leaves room for about 2,400 years of tail emission.
 *
 * The Rust libraries still cap a single shielded value or transaction amount
 * at the Zcash limit of 21M coins.
 */
static const CAmount MAX_MONEY = 200000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
inline bool MoneyDeltaRange(const CAmount& nValue) { return (nValue >= -MAX_MONEY && nValue <= MAX_MONEY); }

/** The legacy default fee that was defined in ZIP 313. */
static const CAmount LEGACY_DEFAULT_FEE = 1000;

/** Type-safe wrapper class to for fee rates
 * (how much to pay based on transaction size)
 */
class CFeeRate
{
private:
    CAmount nSatoshisPerK; // unit is zatoshis-per-1,000-bytes
public:
    CFeeRate() : nSatoshisPerK(0) { }
    explicit CFeeRate(const CAmount& _nSatoshisPerK): nSatoshisPerK(_nSatoshisPerK) { }
    CFeeRate(const CAmount& nFeePaid, size_t nSize);
    CFeeRate(const CFeeRate& other) { nSatoshisPerK = other.nSatoshisPerK; }

    CAmount GetFeeForRelay(size_t size) const; // unit returned is zatoshis
    CAmount GetFee(size_t size) const; // unit returned is zatoshis
    CAmount GetFeePerK() const { return GetFee(1000); } // zatoshis-per-1000-bytes

    friend bool operator<(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    CFeeRate& operator+=(const CFeeRate& a) { nSatoshisPerK += a.nSatoshisPerK; return *this; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSatoshisPerK);
    }
};

#endif //  BITCOIN_AMOUNT_H
