// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <nan.h>
#include <iostream>
#include <stdio.h>
#include <v8.h>
#include "crypto.h"
#include "hash.h"
#include "StringTools.h"

using BinaryArray = std::vector<uint8_t>;

/*
*
* Helper methods
*
*/

inline v8::Local<v8::Array> prepareResult(const bool success, const v8::Local<v8::Value> val)
{
  v8::Local<v8::Array> result = Nan::New<v8::Array>(2);

  /* We do the inverse of success because we want the results in [err, value] format */
  Nan::Set(result, 0, Nan::New(!success));
  Nan::Set(result, 1, val);

  return result;
}

/*
*
* Core Cryptographic Operations
*
*/

void checkKey(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New(false);

    std::string publicKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!publicKey.empty())
        {
            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            bool success = Crypto::check_key(c_public_key);

            functionReturnValue = Nan::New(success);
        }
    }

    info.GetReturnValue().Set(functionReturnValue);
}

/* bool: checkRingSignature*/

void checkSignature(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New(false);

    std::string prefixHash = std::string();
    std::string publicKey = std::string();
    std::string signature = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            signature = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty()
            && !signature.empty())
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::Signature c_signature;
            Common::podFromHex(signature, c_signature);

            bool success = Crypto::check_signature(c_prefixHash, c_public_key, c_signature);

            functionReturnValue = Nan::New(success);
        }
    }

    info.GetReturnValue().Set(functionReturnValue);
}

void derivePublicKey(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string publicKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !publicKey.empty())
        {
            Crypto::KeyDerivation c_derivation;
            Common::podFromHex(derivation, c_derivation);

            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::PublicKey c_result;
            bool success =
                Crypto::derive_public_key(c_derivation, outputIndex,
                                          c_public_key, c_result);

            if (success)
            {
                std::string result = Common::podToHex(c_result);

                functionReturnValue = Nan::New(result).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void deriveSecretKey(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !secretKey.empty())
        {
            Crypto::KeyDerivation c_derivation;
            Common::podFromHex(derivation, c_derivation);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::SecretKey c_result;
            try
            {
                Crypto::derive_secret_key(c_derivation, outputIndex,
                                          c_secret_key, c_result);
            }
            catch(const std::exception & e) {
                return Nan::ThrowError(e.what());
            }

            std::string result = Common::podToHex(c_result);

            functionReturnValue = Nan::New(result).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateKeys(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    Crypto::PublicKey pub;
    Crypto::SecretKey sec;

    Crypto::generate_keys(pub, sec);

    std::string publicKey = Common::toHex(&pub, sizeof(pub));
    std::string secretKey = Common::toHex(&sec, sizeof(sec));

    v8::Local < v8::Object > jsonObject = Nan::New < v8::Object > ();

    v8::Local < v8::String > publicKeyProp =
        Nan::New("publicKey").ToLocalChecked();
    v8::Local < v8::String > secretKeyProp =
        Nan::New("secretKey").ToLocalChecked();

    v8::Local < v8::Value > publicKeyValue =
        Nan::New(publicKey).ToLocalChecked();
    v8::Local < v8::Value > secretKeyValue =
        Nan::New(secretKey).ToLocalChecked();

    Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
    Nan::Set(jsonObject, secretKeyProp, secretKeyValue);

    info.GetReturnValue().Set(prepareResult(true, jsonObject));
}

void generateKeyDerivation(const Nan::FunctionCallbackInfo <
                           v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string secretKey = std::string();
    std::string publicKey = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!secretKey.empty() && !publicKey.empty())
        {
            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::KeyDerivation derivation;
            bool success =
                Crypto::generate_key_derivation(c_public_key, c_secret_key,
                                                derivation);

            if (success)
            {
                std::string c_result = Common::podToHex(derivation);
                functionReturnValue = Nan::New(c_result).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateKeyImage(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string publicKey = std::string();
    std::string secretKey = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!publicKey.empty() && !secretKey.empty())
        {
            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::KeyImage c_key_image;
            try
            {
                Crypto::generate_key_image(c_public_key, c_secret_key,
                                           c_key_image);
            }
            catch(const std::exception & e) {
                return Nan::ThrowError(e.what());
            }

            std::string result = Common::podToHex(c_key_image);

            functionReturnValue = Nan::New(result).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateRingSignatures(const Nan::FunctionCallbackInfo <
                            v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string prefixHash = std::string();
    std::string keyImage = std::string();
    std::string transactionSecretKey = std::string();
    std::vector < Crypto::PublicKey > publicKeys;

    uint64_t realOutput = 0;

    if (info.Length() == 5)
    {
        if (info[0]->IsString())
        {
            prefixHash =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImage = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsArray())
        {
            v8::Local < v8::Array > array =
                v8::Local < v8::Array >::Cast(info[2]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string l_hash =
                    std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(l_hash, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (info[3]->IsString())
        {
            transactionSecretKey =
                std::string(*Nan::Utf8String(info[3]->ToString()));
        }

        if (info[4]->IsNumber())
        {
            realOutput = (uint64_t) info[4]->NumberValue();
        }

        if (!prefixHash.empty() && !keyImage.empty()
            && !transactionSecretKey.empty() && publicKeys.size() != 0)
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::KeyImage c_keyImage;
            Common::podFromHex(keyImage, c_keyImage);

            Crypto::SecretKey c_transactionSecretKey;
            Common::podFromHex(transactionSecretKey,
                               c_transactionSecretKey);

            std::vector < Crypto::Signature > c_sigs;

            const bool success =
                Crypto::crypto_ops::generateRingSignatures(c_prefixHash,
                                                           c_keyImage,
                                                           publicKeys,
                                                           c_transactionSecretKey,
                                                           realOutput,
                                                           c_sigs);

            if (success)
            {
                v8::Local < v8::Array > sigs =
                    Nan::New < v8::Array > (c_sigs.size());

                for (size_t i = 0; i < c_sigs.size(); i++)
                {
                    std::string c_result =
                        Common::toHex(&c_sigs[i], sizeof(c_sigs[i]));
                    v8::Local < v8::String > result =
                        Nan::New(c_result).ToLocalChecked();
                    Nan::Set(sigs, i, result);
                }

                functionReturnValue = sigs;

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void generateSignature(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string prefixHash = std::string();
    std::string publicKey = std::string();
    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty()
            && !secretKey.empty())
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::Signature c_sig;
            try
            {
                Crypto::generate_signature(c_prefixHash, c_public_key,
                                           c_secret_key, c_sig);
            }
            catch(const std::exception & e) {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(c_sig);
            functionReturnValue = Nan::New(c_result).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void hashToScalar(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string data = std::string();
    std::string scalar = std::string();

    if (info.Length() == 1)
    {
        data = std::string(*Nan::Utf8String(info[0]->ToString()));
    }

    if (!data.empty())
    {
        const BinaryArray & rawData = Common::fromHex(data);

        Crypto::EllipticCurveScalar l_scalar;

        try
        {
            Crypto::hashToScalar(rawData.data(), rawData.size(), l_scalar);
        } catch(const std::exception & e) {
            return Nan::ThrowError(e.what());
        }

        scalar = Common::podToHex(l_scalar);

        functionReturnValue = Nan::New(scalar).ToLocalChecked();

        functionSuccess = true;
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void scReduce32(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string data = std::string();
    std::string scalar = std::string();

    if (info.Length() == 1)
    {
        data = std::string(*Nan::Utf8String(info[0]->ToString()));
    }

    if (!data.empty())
    {
        Crypto::EllipticCurveScalar l_scalar;
        Common::podFromHex(data, l_scalar);

        try
        {
            Crypto::scReduce32(l_scalar);
        }
        catch(const std::exception & e) {
            return Nan::ThrowError(e.what());
        }

        scalar = Common::podToHex(l_scalar);

        functionReturnValue = Nan::New(scalar).ToLocalChecked();

        functionSuccess = true;
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void secretKeyToPublicKey(const Nan::FunctionCallbackInfo < v8::Value >
                          &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string secretKey = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!secretKey.empty())
        {
            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::PublicKey c_public_key;

            bool success = Crypto::secret_key_to_public_key(c_secret_key, c_public_key);

            if (success)
            {
                std::string c_result = Common::podToHex(c_public_key);

                functionReturnValue = Nan::New(c_result).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void underivePublicKey(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string derivedKey = std::string();

    if (info.Length() == 3)
    {

        if (info[0]->IsString())
        {
            derivation =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t) info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            derivedKey =
                std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !derivedKey.empty())
        {
            Crypto::KeyDerivation c_derivation;
            Common::podFromHex(derivation, c_derivation);

            Crypto::PublicKey c_derived_key;
            Common::podFromHex(derivedKey, c_derived_key);

            Crypto::PublicKey c_result;
            bool success =
                Crypto::underive_public_key(c_derivation, outputIndex,
                                            c_derived_key, c_result);

            if (success)
            {
                std::string result = Common::podToHex(c_result);
                functionReturnValue = Nan::New(result).ToLocalChecked();

                functionSuccess = true;
            }
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

/*
*
* Hashing Operations
*
*/

void cn_fast_hash(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    /* Setup our return object */
    v8::Local<v8::Value> functionReturnValue = Nan::New("").ToLocalChecked();
    bool functionSuccess = false;

    std::string hash = std::string();
    std::string data = std::string();

    if (info.Length() == 1)
    {
        if (info[0]->IsString())
        {
            data = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (!data.empty())
        {
            const BinaryArray & rawData = Common::fromHex(data);

            Crypto::Hash c_hash = Crypto::Hash();
            try
            {
                Crypto::cn_fast_hash(rawData.data(), rawData.size(),
                                     c_hash);
            } catch(const std::exception & e) {
                return Nan::ThrowError(e.what());
            }

            hash = Common::podToHex(c_hash);

            functionReturnValue = Nan::New(hash).ToLocalChecked();

            functionSuccess = true;
        }
    }

    info.GetReturnValue().Set(prepareResult(functionSuccess, functionReturnValue));
}

void InitModule(v8::Local < v8::Object > exports)
{
    /* Core Cryptographic Operations */
    exports->Set(Nan::New("checkKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (checkKey)->GetFunction());

    exports->Set(Nan::New("checkSignature").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (checkSignature)->GetFunction());

    exports->Set(Nan::New("derivePublicKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (derivePublicKey)->GetFunction());

    exports->Set(Nan::New("deriveSecretKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (deriveSecretKey)->GetFunction());

    exports->Set(Nan::New("generateKeys").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateKeys)->GetFunction());

    exports->Set(Nan::New("generateKeyDerivation").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateKeyDerivation)->GetFunction());

    exports->Set(Nan::New("generateKeyImage").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateKeyImage)->GetFunction());

    exports->Set(Nan::New("generateRingSignatures").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateRingSignatures)->GetFunction());

    exports->Set(Nan::New("generateSignature").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateSignature)->GetFunction());

    exports->Set(Nan::New("hashToScalar").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (hashToScalar)->GetFunction());

    exports->Set(Nan::New("scReduce32").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (scReduce32)->GetFunction());

    exports->Set(Nan::New("secretKeyToPublicKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (secretKeyToPublicKey)->GetFunction());

    exports->Set(Nan::New("underivePublicKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (underivePublicKey)->GetFunction());

    /* Hashing Operations */
    exports->Set(Nan::New("cnFastHash").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (cn_fast_hash)->GetFunction());
}

NODE_MODULE(turtlecoincrypto, InitModule);
