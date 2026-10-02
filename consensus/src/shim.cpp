// A thin C interface over the Sequentia node's script interpreter, linked from
// the node's own consensus library. It differs from the node's public
// libelementsconsensus API in what that API cannot do: it takes every spent
// output (taproot and Simplicity sign and read all of them) and any script
// verification flag the interpreter knows.

#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <uint256.h>
#include <version.h>

#include <cstring>
#include <string>
#include <exception>
#include <vector>

extern bool g_con_elementsmode;

namespace {
// Transaction serialisation and the interpreter both follow this global, which
// the consensus library leaves at the Bitcoin default. Every Sequentia chain
// runs in Elements mode.
struct ElementsMode {
    ElementsMode() { g_con_elementsmode = true; }
} g_elements_mode;

// Creates the verification context that pubkey.cpp and Simplicity's
// signature jets read; the node's bitcoinconsensus.cpp holds the same handle.
ECCVerifyHandle g_ecc_verify_handle;
}

extern "C" {

/// Result codes of arca_verify_input. A script error is reported through
/// script_error, with ARCA_SCRIPT_INVALID returned.
enum {
    ARCA_OK = 0,
    ARCA_SCRIPT_INVALID = 1,
    ARCA_ERR_TX_DESERIALIZE = 2,
    ARCA_ERR_SPENT_DESERIALIZE = 3,
    ARCA_ERR_TX_INDEX = 4,
    ARCA_ERR_SPENT_COUNT = 5,
};

int arca_verify_input(const unsigned char* genesis_hash,
                      const unsigned char* tx_bytes, size_t tx_len,
                      const unsigned char* spent_bytes, size_t spent_len,
                      unsigned int n_in, unsigned int flags, int* script_error)
{
    *script_error = SCRIPT_ERR_UNKNOWN_ERROR;
    CMutableTransaction mtx;
    try {
        CDataStream s(Span<const uint8_t>{tx_bytes, tx_len}, SER_NETWORK, PROTOCOL_VERSION);
        s >> mtx;
        if (!s.empty()) return ARCA_ERR_TX_DESERIALIZE;
    } catch (const std::exception&) {
        return ARCA_ERR_TX_DESERIALIZE;
    }
    std::vector<CTxOut> spent;
    try {
        CDataStream s(Span<const uint8_t>{spent_bytes, spent_len}, SER_NETWORK, PROTOCOL_VERSION);
        s >> spent;
        if (!s.empty()) return ARCA_ERR_SPENT_DESERIALIZE;
    } catch (const std::exception&) {
        return ARCA_ERR_SPENT_DESERIALIZE;
    }
    const CTransaction tx(mtx);
    if (n_in >= tx.vin.size()) return ARCA_ERR_TX_INDEX;
    if (spent.size() != tx.vin.size()) return ARCA_ERR_SPENT_COUNT;

    const CTxOut prevout = spent[n_in];
    PrecomputedTransactionData txdata(uint256{genesis_hash, 32});
    txdata.Init(tx, std::move(spent), /*force=*/true);

    const CScriptWitness* witness = tx.witness.vtxinwit.size() > n_in ? &tx.witness.vtxinwit[n_in].scriptWitness : nullptr;
    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    const bool ok = VerifyScript(tx.vin[n_in].scriptSig, prevout.scriptPubKey, witness, flags,
                                 TransactionSignatureChecker(&tx, n_in, prevout.nValue, txdata, MissingDataBehavior::FAIL),
                                 &err);
    *script_error = err;
    return ok ? ARCA_OK : ARCA_SCRIPT_INVALID;
}

/// The node's description of a script error, as its RPCs print it.
const char* arca_script_error_string(int script_error)
{
    static thread_local std::string s;
    s = ScriptErrorString(static_cast<ScriptError>(script_error));
    return s.c_str();
}

/// The script flags the node's mempool applies before its consensus check.
unsigned int arca_standard_flags() { return STANDARD_SCRIPT_VERIFY_FLAGS; }

/// The flags of every script rule a block enforces on a Sequentia chain where
/// all deployments are active, which is every chain started from genesis.
unsigned int arca_consensus_flags()
{
    return SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG |
           SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
           SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_NULLDUMMY | SCRIPT_SIGHASH_RANGEPROOF |
           SCRIPT_VERIFY_SIMPLICITY | SCRIPT_VERIFY_SIMPLICITY_BUDGET4;
}

} // extern "C"
