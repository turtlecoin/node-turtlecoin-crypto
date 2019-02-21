// Copyright (c) 2017-2018, The Monero Project
// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <stdexcept>

#include "CryptoTypes.h"

namespace Crypto
{
extern std::mutex multisig_lock;

class multisig
{
    multisig();
    ~multisig();

  public:
    static SecretKey generate_blinded_secret_key(const SecretKey &);
    static void generate_n_n(const SecretKey &, const std::vector<PublicKey> &, std::vector<SecretKey> &, SecretKey &,
                             PublicKey &);
    static void generate_n1_n(const SecretKey &, const std::vector<PublicKey> &, std::vector<SecretKey> &, SecretKey &,
                              PublicKey &);
    static std::vector<PublicKey> generate_derivations(const SecretKey &, const std::vector<PublicKey> &);
    static SecretKey calculate_signer_key(const std::vector<SecretKey> &);
    static std::vector<SecretKey> calculate_keys(const std::vector<PublicKey> &);
    static SecretKey generate_view_key(const SecretKey &, const std::vector<SecretKey> &);
    static PublicKey generate_m_n_public_spend_key(const std::vector<PublicKey> &);
    static bool generate_key_image(const std::vector<SecretKey> &, const size_t &, const PublicKey &, KeyImage &);
    static bool generate_key_image(const SecretKey &, const PublicKey &, KeyImage &);
    static void generate_LR(const PublicKey &, const SecretKey &, PublicKey &, KeyImage &);
    static bool generate_composite_key_image(const SecretKey &, const SecretKey &, const PublicKey &,
                                             const std::vector<SecretKey>, const PublicKey &, const PublicKey &, size_t,
                                             const std::vector<KeyImage> &, KeyImage &);
    static uint32_t rounds_required(uint32_t participants, uint32_t threshold)
    {
        if (participants >= threshold)
        {
            throw std::out_of_range("Participants must be grather than or equal than the threshold");
        }
        return participants - threshold + 1;
    };
};
} // namespace Crypto
