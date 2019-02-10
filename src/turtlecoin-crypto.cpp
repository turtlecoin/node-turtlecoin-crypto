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

using BinaryArray = std::vector < uint8_t >;

void generate_keys(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    Crypto::PublicKey pub;
    Crypto::SecretKey sec;

    Crypto::generate_keys(pub, sec);

    std::string publicKey = Common::toHex(&pub, sizeof(pub));
    std::string privateKey = Common::toHex(&sec, sizeof(sec));

    v8::Local < v8::Object > jsonObject = Nan::New < v8::Object > ();

    v8::Local < v8::String > publicKeyProp =
        Nan::New("publicKey").ToLocalChecked();
    v8::Local < v8::String > privateKeyProp =
        Nan::New("privateKey").ToLocalChecked();

    v8::Local < v8::Value > publicKeyValue =
        Nan::New(publicKey).ToLocalChecked();
    v8::Local < v8::Value > privateKeyValue =
        Nan::New(privateKey).ToLocalChecked();

    Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
    Nan::Set(jsonObject, privateKeyProp, privateKeyValue);

    info.GetReturnValue().Set(jsonObject);
}

void generateRingSignatures(const Nan::FunctionCallbackInfo < v8::Value >
                            &info)
{
    std::string prefixHash;
    std::string keyImage;
    std::string transactionSecretKey;
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

            const auto[success, c_sigs] =
                Crypto::crypto_ops::generateRingSignatures(c_prefixHash,
                                                           c_keyImage,
                                                           publicKeys,
                                                           c_transactionSecretKey,
                                                           realOutput);

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

                info.GetReturnValue().Set(sigs);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generateKeyDerivation(const Nan::FunctionCallbackInfo < v8::Value >
                           &info)
{
    std::string privateKey = std::string();
    std::string publicKey = std::string();

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            privateKey =
                std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (!privateKey.empty() && !publicKey.empty())
        {
            Crypto::KeyDerivation derivation;

            Crypto::PublicKey c_public_key;
            Common::podFromHex(privateKey, c_public_key);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(publicKey, c_secret_key);

            Crypto::generate_key_derivation(c_public_key, c_secret_key,
                                            derivation);

            std::string result = Common::podToHex(derivation);

            v8::Local < v8::String > returnValue =
                Nan::New(result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generateKeyImage(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
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

            Crypto::generate_key_image(c_public_key, c_secret_key,
                                       c_key_image);

            std::string result = Common::podToHex(c_key_image);

            v8::Local < v8::String > returnValue =
                Nan::New(result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void cn_fast_hash(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
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
            Crypto::cn_fast_hash(rawData.data(), rawData.size(), c_hash);

            hash = Common::podToHex(c_hash);

            v8::Local < v8::String > returnValue =
                Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void underivePublicKey(const Nan::FunctionCallbackInfo < v8::Value > &info)
{
    if (info.Length() == 3)
    {
        size_t outputIndex = 0;
        std::string derivation = std::string();
        std::string derivedKey = std::string();

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

            Crypto::underive_public_key(c_derivation, outputIndex,
                                        c_derived_key, c_result);

            std::string result = Common::podToHex(c_result);

            v8::Local < v8::String > returnValue =
                Nan::New(result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void cn_turtle_lite_slow_hash_v2(const Nan::FunctionCallbackInfo <
                                 v8::Value > &info)
{
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
            Crypto::cn_turtle_lite_slow_hash_v2(rawData.data(),
                                                rawData.size(), c_hash);

            hash = Common::podToHex(c_hash);

            v8::Local < v8::String > returnValue =
                Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void InitModule(v8::Local < v8::Object > exports)
{
    exports->Set(Nan::New("generateKeys").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generate_keys)->GetFunction());

    exports->Set(Nan::New("generateKeyDerivation").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateKeyDerivation)->GetFunction());

    exports->Set(Nan::New("generateKeyImage").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateKeyImage)->GetFunction());

    exports->Set(Nan::New("generateRingSignatures").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (generateRingSignatures)->GetFunction());

    exports->Set(Nan::New("cnFastHash").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (cn_fast_hash)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v2").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (cn_turtle_lite_slow_hash_v2)->GetFunction());

    exports->Set(Nan::New("underivePublicKey").ToLocalChecked(),
                 Nan::New < v8::FunctionTemplate >
                 (underivePublicKey)->GetFunction());
}

NODE_MODULE(turtlecoincrypto, InitModule);
