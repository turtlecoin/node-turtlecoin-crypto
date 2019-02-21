// Copyright (c) 2017-2018, The Monero Project
// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <exception>

#include <mutex>

#include <unordered_set>

#include "crypto.h"

#include "multisig.h"

namespace Crypto
{

using std::lock_guard;
using std::mutex;

extern "C"
{
#include "crypto-ops.h"
}
mutex multisig_lock;

/*
   Below, you will find a number of support methods that are currently
   only used as part of the multisignature wallet functions. As such,
   these may be moved at a later time if it is later determined that
   other methods need to pull this data in and cannot easily reference
   the methods here */

/* Hashes input then converts it to a scalar */
template <typename T> inline void hash_to_scalar(const void *data, T &result)
{
    cn_fast_hash(data, sizeof(data), reinterpret_cast<Hash &>(result));
    sc_reduce32(reinterpret_cast<unsigned char *>(&result));
}
/* Sets the supplied object to a base Identity value */ template <typename T> inline void setIdentity(T &empty)
{
    empty = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

/* Sets the supplied object to a zero (empty) value */
template <typename T> inline void setZero(T &empty)
{
    empty = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

/* Allows for a polymorphic multiplication of scalar keys */
template <typename T, typename U, typename V> inline void scalarMultKey(const T &P, const U &a, V &aP)
{
    ge_p3 A;

    ge_p2 R;

    if (ge_frombytes_vartime(&A, reinterpret_cast<const unsigned char *>(&P)) != 0)
        throw std::runtime_error("Could not get the result of ge_frombytes_vartime for value P");

    ge_scalarmult(&R, reinterpret_cast<const unsigned char *>(&a), &A);

    ge_tobytes(reinterpret_cast<unsigned char *>(&aP), &R);
}

/* Casts a public key to a secret key */
const SecretKey toSecretKey(const PublicKey &key) { return reinterpret_cast<const unsigned char *>(&key); }

/* Casts a secret key to a public key */
const PublicKey toPublicKey(const SecretKey &key) { return reinterpret_cast<const unsigned char *>(&key); }

/* Adds two public keys together */
inline void addKeys(const PublicKey &A, const PublicKey &B, PublicKey &AB)
{
    ge_p3 B2, A2;

    if (ge_frombytes_vartime(&A2, reinterpret_cast<const unsigned char *>(&A)) != 0)
        throw std::runtime_error("Could not get the result of ge_frombytes_vartime for value A");

    if (ge_frombytes_vartime(&B2, reinterpret_cast<const unsigned char *>(&B)) != 0)
        throw std::runtime_error("Could not get the result of ge_frombytes_vartime for value B");

    ge_cached tmp2;

    ge_p3_to_cached(&tmp2, &B2);
    ge_p1p1 tmp3;

    ge_add(&tmp3, &A2, &tmp2);
    ge_p1p1_to_p3(&A2, &tmp3);
    ge_p3_tobytes(reinterpret_cast<unsigned char *>(&AB), &A2);
}

/* Adds two keyImage together */
inline void addKeys(const KeyImage &A, const KeyImage &B, KeyImage &AB)
{
    ge_p3 B2, A2;

    if (ge_frombytes_vartime(&A2, reinterpret_cast<const unsigned char *>(&A)) != 0)
        throw std::runtime_error("Could not get the result of ge_frombytes_vartime for value A");

    if (ge_frombytes_vartime(&B2, reinterpret_cast<const unsigned char *>(&B)) != 0)
        throw std::runtime_error("Could not get the result of ge_frombytes_vartime for value B");

    ge_cached tmp2;

    ge_p3_to_cached(&tmp2, &B2);
    ge_p1p1 tmp3;

    ge_add(&tmp3, &A2, &tmp2);
    ge_p1p1_to_p3(&A2, &tmp3);
    ge_p3_tobytes(reinterpret_cast<unsigned char *>(&AB), &A2);
}

/* Generates a "blind" secret key */
SecretKey multisig::generate_blinded_secret_key(const SecretKey &secretKey)
{
    SecretKey result;

    hash_to_scalar(reinterpret_cast<const unsigned char *>(&secretKey), result);

    return result;
}

/* I'd be lying if I said I understand what this did, but it seems to
   take a secret key and returns the base point as a public key
   perhaps this is the infamous G that all that math references */
inline void scalarmultBase(PublicKey &aG, const SecretKey &a)
{
    ge_p3 point;

    sc_reduce32copy(reinterpret_cast<unsigned char *>(&aG), reinterpret_cast<const unsigned char *>(&a));

    ge_scalarmult_base(&point, reinterpret_cast<const unsigned char *>(&aG));

    ge_p3_tobytes(reinterpret_cast<unsigned char *>(&aG), &point);
}

/*
   Our actual class (multisig) methods start here, there's a lot
   going on here and I'll do my best to explain it as we go */

/* Generates a set of multisigKeys, our spend secretKey and
   the combined spend public key for the key set for
   a N of N wallet */
void multisig::generate_n_n(const SecretKey &spendKey, const std::vector<PublicKey> &spendKeys,
                            std::vector<SecretKey> &multisigKeys, SecretKey &spendSecretKey, PublicKey &spendPublicKey)
{
    multisigKeys.clear();

    const SecretKey spend_secret_key = spendKey;

    if (secret_key_to_public_key(spend_secret_key, spendPublicKey) != 1)
        throw std::runtime_error("Failed to derive public key from private key");

    for (const auto &key : spendKeys)
        addKeys(spendPublicKey, key, spendPublicKey);

    multisigKeys.push_back(spend_secret_key);
    spendSecretKey = spend_secret_key;
}

/* Generates a set of multisigKeys, our spend secretKey and
   the combined spend public key for the key set for
   a M of N wallet */
void multisig::generate_n1_n(const SecretKey &spendKey, const std::vector<PublicKey> &spendKeys,
                             std::vector<SecretKey> &multisigKeys, SecretKey &spendSecretKey, PublicKey &spendPublicKey)
{
    multisigKeys.clear();

    setIdentity(spendPublicKey);
    setZero(spendSecretKey);

    SecretKey secretKey = spendKey;

    for (const auto &key : spendKeys)
    {
        SecretKey secret_key;

        scalarMultKey(key, secretKey, secret_key);

        multisigKeys.push_back(secret_key);
        sc_add(reinterpret_cast<unsigned char *>(&spendSecretKey),
               reinterpret_cast<const unsigned char *>(&spendSecretKey),
               reinterpret_cast<const unsigned char *>(&secret_key));
    }
}

/* Generates the multisigKeys for our secret spendKey and
   the public spend keys of others */
std::vector<PublicKey> multisig::generate_derivations(const SecretKey &spendKey,
                                                      const std::vector<PublicKey> &spendPublicKeys)
{
    std::vector<PublicKey> multisigKeys;

    SecretKey secretKey = spendKey;

    for (const auto &key : spendPublicKeys)
    {
        PublicKey public_key;

        scalarMultKey(key, secretKey, public_key);

        multisigKeys.push_back(public_key);
    }

    return multisigKeys;
}

/* Generates the signer key of the supplied list of multisig keys */
SecretKey multisig::calculate_signer_key(const std::vector<SecretKey> &multisigKeys)
{
    SecretKey secretKey;

    setZero(secretKey);

    for (const auto &key : multisigKeys)
        sc_add(reinterpret_cast<unsigned char *>(&secretKey), reinterpret_cast<const unsigned char *>(&secretKey),
               reinterpret_cast<const unsigned char *>(&key));

    return secretKey;
}

/* Calculates the multisig secretKeys based on the supplied
   public multisig keys */
std::vector<SecretKey> multisig::calculate_keys(const std::vector<PublicKey> &derivations)
{
    std::vector<SecretKey> multisigKeys;
    multisigKeys.reserve(derivations.size());

    for (const auto &key : derivations)
        multisigKeys.emplace_back(toSecretKey(key));

    return multisigKeys;
}

/* Generates the multisig view secretKey based on our view SecretKey
   and the view secretKeys of others in our party */
SecretKey multisig::generate_view_key(const SecretKey &secretKey, const std::vector<SecretKey> &secretKeys)
{
    SecretKey viewKey = secretKey;

    for (const auto &key : secretKeys)
        sc_add(reinterpret_cast<unsigned char *>(&viewKey), reinterpret_cast<const unsigned char *>(&viewKey),
               reinterpret_cast<const unsigned char *>(&key));

    return viewKey;
}

/* Generates the spend publicKey based on the supplied publicKeys */
PublicKey multisig::generate_m_n_public_spend_key(const std::vector<PublicKey> &publicKeys)
{
    PublicKey spendKey;

    setIdentity(spendKey);

    for (const auto &key : publicKeys)
    {
        addKeys(spendKey, key, spendKey);
    }

    return spendKey;
}

/* Generates a keyImage based on the secret multisigKeys, the keyIndex,
   and the output key */
bool multisig::generate_key_image(const std::vector<SecretKey> &multisigKeys, const size_t &keyIndex,
                                  const PublicKey &outputKey, KeyImage &keyImage)
{
    if (keyIndex >= multisigKeys.size())
        return false;

    Crypto::generate_key_image(outputKey, multisigKeys[keyIndex], keyImage);

    return true;
}

/* Generates a keyImage based on the secretKey and outputKey supplied */
bool multisig::generate_key_image(const SecretKey &secretKey, const PublicKey &outputKey, KeyImage &keyImage)
{
    Crypto::generate_key_image(outputKey, secretKey, keyImage);

    return true;
}

/* Generates a key image after doing something -- Let me think
   about what this is doing */
void multisig::generate_LR(const PublicKey &outputKey, const SecretKey &secretKey, PublicKey &L, KeyImage &R)
{
    scalarmultBase(L, secretKey);
    Crypto::generate_key_image(outputKey, secretKey, R);
}

/* This is basically just a copy of our normal generate key
   image method that has been pulled in here to make the code
   easier to follow */
inline bool generate_key_image_helper(const SecretKey &viewSecretKey, const SecretKey &spendSecretKey,
                                      const PublicKey &spendPublicKey, const PublicKey &outputKey,
                                      const PublicKey &transactionPublicKey, size_t realOutputIndex,
                                      PublicKey &publicEphemeral, SecretKey &secretEphemeral, KeyImage &keyImage)
{
    KeyDerivation recvDerivation;

    bool r = Crypto::generate_key_derivation(transactionPublicKey, viewSecretKey, recvDerivation);

    if (!r)
        return false;

    Crypto::derive_secret_key(recvDerivation, realOutputIndex, spendSecretKey, secretEphemeral);

    Crypto::derive_public_key(recvDerivation, realOutputIndex, spendPublicKey, publicEphemeral);

    if (outputKey != publicEphemeral)
        return false;

    generate_key_image(publicEphemeral, secretEphemeral, keyImage);

    return true;
}

bool multisig::generate_composite_key_image(const SecretKey &viewSecretKey, const SecretKey &spendSecretKey,
                                            const PublicKey &spendPublicKey, const std::vector<SecretKey> multisigKeys,
                                            const PublicKey &outputKey, const PublicKey &transactionPublicKey,
                                            size_t realOutputIndex, const std::vector<KeyImage> &partialKeyImages,
                                            KeyImage &keyImage)
{
    PublicKey publicEphemeral;

    SecretKey secretEphemeral;

    if (!generate_key_image_helper(viewSecretKey, spendSecretKey, spendPublicKey, outputKey, transactionPublicKey,
                                   realOutputIndex, publicEphemeral, secretEphemeral, keyImage))
        return false;

    std::unordered_set<KeyImage> used;

    for (const auto &multisigKey : multisigKeys)
    {
        KeyImage partialKeyImage;

        bool r = generate_key_image(multisigKey, outputKey, partialKeyImage);

        if (!r)
            return false;

        used.insert(partialKeyImage);
    }

    for (const auto &partialKeyImage : partialKeyImages)
    {
        if (used.find(partialKeyImage) == used.end())
        {
            used.insert(partialKeyImage);
            addKeys(keyImage, partialKeyImage, keyImage);
        }
    }

    return true;
}
} // namespace Crypto
