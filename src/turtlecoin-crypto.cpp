// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "StringTools.h"
#include "crypto.h"
#include "hash.h"
#include <iostream>
#include <nan.h>
#include <stdio.h>
#include <v8.h>

using BinaryArray = std::vector<uint8_t>;

void calculate_signer_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::vector<Crypto::SecretKey> secretKeys;

    if (info.Length() == 1)
    {
        if (info[0]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_secretKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::SecretKey l_secretKey;
                Common::podFromHex(s_secretKey, l_secretKey);

                secretKeys.push_back(l_secretKey);
            }
        }

        if (secretKeys.size() != 0)
        {
            Crypto::SecretKey m_secretKey;

            try
            {
                m_secretKey = Crypto::multisig::calculate_signer_key(secretKeys);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(m_secretKey);
            v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void check_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
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

            v8::Local<v8::Boolean> returnValue = Nan::New(success);

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void check_ring_signature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string prefixHash = std::string();
    std::string keyImage = std::string();
    std::vector<Crypto::PublicKey> outputKeys;
    std::vector<Crypto::Signature> signatures;

    if (info.Length() == 4)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImage = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[2]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_publicKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(s_publicKey, l_publicKey);

                outputKeys.push_back(l_publicKey);
            }
        }

        if (info[3]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[3]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_signature = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::Signature l_signature;
                Common::podFromHex(s_signature, l_signature);

                signatures.push_back(l_signature);
            }
        }

        if (!prefixHash.empty() && !keyImage.empty() && outputKeys.size() != 0 && signatures.size() != 0)
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::KeyImage c_keyImage;
            Common::podFromHex(keyImage, c_keyImage);

            bool success = Crypto::crypto_ops::checkRingSignature(c_prefixHash, c_keyImage, outputKeys, signatures);

            v8::Local<v8::Boolean> returnValue = Nan::New(success);

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void check_signature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string prefixHash = std::string();
    std::string publicKey = std::string();
    std::string signature = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            signature = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty() && !signature.empty())
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::Signature c_signature;
            Common::podFromHex(signature, c_signature);

            bool success = Crypto::check_signature(c_prefixHash, c_public_key, c_signature);

            v8::Local<v8::Boolean> returnValue = Nan::New(success);

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void derive_public_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string publicKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t)info[1]->NumberValue();
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
            bool success = Crypto::derive_public_key(c_derivation, outputIndex, c_public_key, c_result);

            if (success)
            {
                std::string result = Common::podToHex(c_result);
                v8::Local<v8::String> returnValue = Nan::New(result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void derive_secret_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            derivation = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t)info[1]->NumberValue();
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
                Crypto::derive_secret_key(c_derivation, outputIndex, c_secret_key, c_result);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string result = Common::podToHex(c_result);
            v8::Local<v8::String> returnValue = Nan::New(result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_blinded_public_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
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

            Crypto::SecretKey m_secret_key = Crypto::multisig::generate_blinded_secret_key(c_secret_key);
            Crypto::PublicKey m_public_key;
            bool success = Crypto::secret_key_to_public_key(m_secret_key, m_public_key);

            if (success)
            {
                std::string c_result = Common::podToHex(m_public_key);

                v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_blinded_secret_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
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

            Crypto::SecretKey m_secret_key;

            try
            {
                m_secret_key = Crypto::multisig::generate_blinded_secret_key(c_secret_key);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(m_secret_key);

            v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_composite_key_image(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string viewSecretKey = std::string();
    std::string spendSecretKey = std::string();
    std::string spendPublicKey = std::string();
    std::vector<Crypto::SecretKey> multisigKeys;
    std::string outputKey = std::string();
    std::string transactionPublicKey = std::string();
    size_t realOutputIndex = 0;
    std::vector<Crypto::KeyImage> partialKeyImages;

    if (info.Length() == 8)
    {
        if (info[0]->IsString())
        {
            viewSecretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            spendSecretKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            spendPublicKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (info[3]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[3]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_item = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::SecretKey l_item;
                Common::podFromHex(s_item, l_item);

                multisigKeys.push_back(l_item);
            }
        }

        if (info[4]->IsString())
        {
            outputKey = std::string(*Nan::Utf8String(info[4]->ToString()));
        }

        if (info[5]->IsString())
        {
            transactionPublicKey = std::string(*Nan::Utf8String(info[5]->ToString()));
        }

        if (info[6]->IsString())
        {
            realOutputIndex = (size_t)info[6]->NumberValue();
        }

        if (info[7]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[7]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_item = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::KeyImage l_item;
                Common::podFromHex(s_item, l_item);

                partialKeyImages.push_back(l_item);
            }
        }

        if (!viewSecretKey.empty() && !spendSecretKey.empty() && !spendPublicKey.empty() && multisigKeys.size() != 0 &&
            !outputKey.empty() && !transactionPublicKey.empty() && partialKeyImages.size() != 0)
        {
            Crypto::SecretKey m_viewSecretKey;
            Common::podFromHex(viewSecretKey, m_viewSecretKey);

            Crypto::SecretKey m_spendSecretKey;
            Common::podFromHex(spendSecretKey, m_spendSecretKey);

            Crypto::PublicKey m_spendPublicKey;
            Common::podFromHex(spendPublicKey, m_spendPublicKey);

            Crypto::PublicKey m_outputKey;
            Common::podFromHex(outputKey, m_outputKey);

            Crypto::PublicKey m_transactionPublicKey;
            Common::podFromHex(transactionPublicKey, m_transactionPublicKey);

            Crypto::KeyImage r_keyImage;

            bool success = Crypto::multisig::generate_composite_key_image(
                m_viewSecretKey, m_spendSecretKey, m_spendPublicKey, multisigKeys, m_outputKey, m_transactionPublicKey,
                realOutputIndex, partialKeyImages, r_keyImage);

            if (success)
            {
                std::string result = Common::podToHex(r_keyImage);

                v8::Local<v8::String> returnValue = Nan::New(result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_derivations(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey = std::string();
    std::vector<Crypto::PublicKey> publicKeys;

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[1]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_publicKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(s_publicKey, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (!secretKey.empty() && publicKeys.size() != 0)
        {
            Crypto::SecretKey m_secret_key;
            Common::podFromHex(secretKey, m_secret_key);

            std::vector<Crypto::PublicKey> outKeys;

            try
            {
                outKeys = Crypto::multisig::generate_derivations(m_secret_key, publicKeys);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            v8::Local<v8::Array> c_outKeys = Nan::New<v8::Array>(outKeys.size());

            for (size_t i = 0; i < outKeys.size(); i++)
            {
                std::string c_result = Common::toHex(&outKeys[i], sizeof(outKeys[i]));
                v8::Local<v8::String> result = Nan::New(c_result).ToLocalChecked();
                Nan::Set(c_outKeys, i, result);
            }

            info.GetReturnValue().Set(c_outKeys);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_key_derivation(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey = std::string();
    std::string publicKey = std::string();

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

        if (!secretKey.empty() && !publicKey.empty())
        {
            Crypto::PublicKey c_public_key;
            Common::podFromHex(publicKey, c_public_key);

            Crypto::SecretKey c_secret_key;
            Common::podFromHex(secretKey, c_secret_key);

            Crypto::KeyDerivation derivation;
            bool success = Crypto::generate_key_derivation(c_public_key, c_secret_key, derivation);

            if (success)
            {
                std::string c_result = Common::podToHex(derivation);
                v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_keys(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    Crypto::PublicKey pub;
    Crypto::SecretKey sec;

    Crypto::generate_keys(pub, sec);

    std::string publicKey = Common::toHex(&pub, sizeof(pub));
    std::string secretKey = Common::toHex(&sec, sizeof(sec));

    v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

    v8::Local<v8::String> publicKeyProp = Nan::New("publicKey").ToLocalChecked();
    v8::Local<v8::String> secretKeyProp = Nan::New("secretKey").ToLocalChecked();

    v8::Local<v8::Value> publicKeyValue = Nan::New(publicKey).ToLocalChecked();
    v8::Local<v8::Value> secretKeyValue = Nan::New(secretKey).ToLocalChecked();

    Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
    Nan::Set(jsonObject, secretKeyProp, secretKeyValue);

    info.GetReturnValue().Set(jsonObject);
}

void generate_key_image(const Nan::FunctionCallbackInfo<v8::Value> &info)
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
            try
            {
                Crypto::generate_key_image(c_public_key, c_secret_key, c_key_image);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string result = Common::podToHex(c_key_image);

            v8::Local<v8::String> returnValue = Nan::New(result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_lr(const Nan::FunctionCallbackInfo<v8::Value> &info)
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

            Crypto::PublicKey l_result;
            Crypto::KeyImage r_result;

            try
            {
                Crypto::multisig::generate_LR(c_public_key, c_secret_key, l_result, r_result);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string result_l = Common::podToHex(l_result);
            std::string result_r = Common::podToHex(r_result);

            v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

            v8::Local<v8::String> publicKeyProp = Nan::New("publicKey").ToLocalChecked();
            v8::Local<v8::String> keyImageProp = Nan::New("keyImage").ToLocalChecked();

            v8::Local<v8::Value> publicKeyValue = Nan::New(result_l).ToLocalChecked();
            v8::Local<v8::Value> keyImageValue = Nan::New(result_r).ToLocalChecked();

            Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
            Nan::Set(jsonObject, keyImageProp, keyImageValue);

            info.GetReturnValue().Set(jsonObject);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_m_n_public_spend_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::vector<Crypto::PublicKey> publicKeys;

    if (info.Length() == 1)
    {
        if (info[0]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_publicKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(s_publicKey, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (publicKeys.size() != 0)
        {
            Crypto::PublicKey m_publicKey;

            try
            {
                m_publicKey = Crypto::multisig::generate_m_n_public_spend_key(publicKeys);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(m_publicKey);
            v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_n_n(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey = std::string();
    std::vector<Crypto::PublicKey> publicKeys;

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[1]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_publicKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(s_publicKey, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (!secretKey.empty() && publicKeys.size() != 0)
        {
            Crypto::SecretKey l_secretKey;
            Common::podFromHex(secretKey, l_secretKey);

            std::vector<Crypto::SecretKey> m_multisigKeys;
            Crypto::SecretKey m_secretKey;
            Crypto::PublicKey m_publicKey;

            try
            {
                Crypto::multisig::generate_n_n(l_secretKey, publicKeys, m_multisigKeys, m_secretKey, m_publicKey);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string r_secretKey = Common::podToHex(m_secretKey);
            std::string r_publicKey = Common::podToHex(m_publicKey);

            v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

            v8::Local<v8::String> secretKeyProp = Nan::New("secretSpendKey").ToLocalChecked();
            v8::Local<v8::String> publicKeyProp = Nan::New("publicSpendKey").ToLocalChecked();
            v8::Local<v8::String> multisigKeysProp = Nan::New("multisigKeys").ToLocalChecked();

            v8::Local<v8::Value> secretKeyValue = Nan::New(r_secretKey).ToLocalChecked();
            v8::Local<v8::Value> publicKeyValue = Nan::New(r_publicKey).ToLocalChecked();

            v8::Local<v8::Array> multisigKeysValue = Nan::New<v8::Array>(m_multisigKeys.size());

            for (size_t i = 0; i < m_multisigKeys.size(); i++)
            {
                std::string m_result = Common::podToHex(m_multisigKeys[i]);
                v8::Local<v8::String> result = Nan::New(m_result).ToLocalChecked();
                Nan::Set(multisigKeysValue, i, result);
            }

            Nan::Set(jsonObject, secretKeyProp, secretKeyValue);
            Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
            Nan::Set(jsonObject, multisigKeysProp, multisigKeysValue);

            info.GetReturnValue().Set(jsonObject);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_n1_n(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey = std::string();
    std::vector<Crypto::PublicKey> publicKeys;

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[1]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_publicKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(s_publicKey, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (!secretKey.empty() && publicKeys.size() != 0)
        {
            Crypto::SecretKey l_secretKey;
            Common::podFromHex(secretKey, l_secretKey);

            std::vector<Crypto::SecretKey> m_multisigKeys;
            Crypto::SecretKey m_secretKey;
            Crypto::PublicKey m_publicKey;

            try
            {
                Crypto::multisig::generate_n1_n(l_secretKey, publicKeys, m_multisigKeys, m_secretKey, m_publicKey);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string r_secretKey = Common::podToHex(m_secretKey);
            std::string r_publicKey = Common::podToHex(m_publicKey);

            v8::Local<v8::Object> jsonObject = Nan::New<v8::Object>();

            v8::Local<v8::String> secretKeyProp = Nan::New("secretSpendKey").ToLocalChecked();
            v8::Local<v8::String> publicKeyProp = Nan::New("publicSpendKey").ToLocalChecked();
            v8::Local<v8::String> multisigKeysProp = Nan::New("multisigKeys").ToLocalChecked();

            v8::Local<v8::Value> secretKeyValue = Nan::New(r_secretKey).ToLocalChecked();
            v8::Local<v8::Value> publicKeyValue = Nan::New(r_publicKey).ToLocalChecked();

            v8::Local<v8::Array> multisigKeysValue = Nan::New<v8::Array>(m_multisigKeys.size());

            for (size_t i = 0; i < m_multisigKeys.size(); i++)
            {
                std::string m_result = Common::podToHex(m_multisigKeys[i]);
                v8::Local<v8::String> result = Nan::New(m_result).ToLocalChecked();
                Nan::Set(multisigKeysValue, i, result);
            }

            Nan::Set(jsonObject, secretKeyProp, secretKeyValue);
            Nan::Set(jsonObject, publicKeyProp, publicKeyValue);
            Nan::Set(jsonObject, multisigKeysProp, multisigKeysValue);

            info.GetReturnValue().Set(jsonObject);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_ring_signatures(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string prefixHash = std::string();
    std::string keyImage = std::string();
    std::string transactionSecretKey = std::string();
    std::vector<Crypto::PublicKey> publicKeys;

    uint64_t realOutput = 0;

    if (info.Length() == 5)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            keyImage = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[2]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string l_hash = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::PublicKey l_publicKey;
                Common::podFromHex(l_hash, l_publicKey);

                publicKeys.push_back(l_publicKey);
            }
        }

        if (info[3]->IsString())
        {
            transactionSecretKey = std::string(*Nan::Utf8String(info[3]->ToString()));
        }

        if (info[4]->IsNumber())
        {
            realOutput = (uint64_t)info[4]->NumberValue();
        }

        if (!prefixHash.empty() && !keyImage.empty() && !transactionSecretKey.empty() && publicKeys.size() != 0)
        {
            Crypto::Hash c_prefixHash;
            Common::podFromHex(prefixHash, c_prefixHash);

            Crypto::KeyImage c_keyImage;
            Common::podFromHex(keyImage, c_keyImage);

            Crypto::SecretKey c_transactionSecretKey;
            Common::podFromHex(transactionSecretKey, c_transactionSecretKey);

            std::vector<Crypto::Signature> c_sigs;

            const bool success = Crypto::crypto_ops::generateRingSignatures(c_prefixHash, c_keyImage, publicKeys,
                                                                            c_transactionSecretKey, realOutput, c_sigs);

            if (success)
            {
                v8::Local<v8::Array> sigs = Nan::New<v8::Array>(c_sigs.size());

                for (size_t i = 0; i < c_sigs.size(); i++)
                {
                    std::string c_result = Common::toHex(&c_sigs[i], sizeof(c_sigs[i]));
                    v8::Local<v8::String> result = Nan::New(c_result).ToLocalChecked();
                    Nan::Set(sigs, i, result);
                }

                info.GetReturnValue().Set(sigs);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_signature(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string prefixHash = std::string();
    std::string publicKey = std::string();
    std::string secretKey = std::string();

    if (info.Length() == 3)
    {
        if (info[0]->IsString())
        {
            prefixHash = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsString())
        {
            publicKey = std::string(*Nan::Utf8String(info[1]->ToString()));
        }

        if (info[2]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!prefixHash.empty() && !publicKey.empty() && !secretKey.empty())
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
                Crypto::generate_signature(c_prefixHash, c_public_key, c_secret_key, c_sig);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(c_sig);
            v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void generate_view_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string secretKey = std::string();
    std::vector<Crypto::SecretKey> secretKeys;

    if (info.Length() == 2)
    {
        if (info[0]->IsString())
        {
            secretKey = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsArray())
        {
            v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[1]);
            for (size_t i = 0; i < array->Length(); i++)
            {
                std::string s_secretKey = std::string(*Nan::Utf8String(array->Get(i)));

                Crypto::SecretKey l_secretKey;
                Common::podFromHex(s_secretKey, l_secretKey);

                secretKeys.push_back(l_secretKey);
            }
        }

        if (!secretKey.empty() && secretKeys.size() != 0)
        {
            Crypto::SecretKey l_secretKey;
            Common::podFromHex(secretKey, l_secretKey);

            Crypto::SecretKey m_secretKey;

            try
            {
                m_secretKey = Crypto::multisig::generate_view_key(l_secretKey, secretKeys);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            std::string c_result = Common::podToHex(m_secretKey);
            v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void hash_to_scalar(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    std::string data = std::string();
    std::string scalar = std::string();

    if (info.Length() == 1)
    {
        data = std::string(*Nan::Utf8String(info[0]->ToString()));
    }

    if (!data.empty())
    {
        const BinaryArray &rawData = Common::fromHex(data);

        Crypto::EllipticCurveScalar l_scalar;

        try
        {
            Crypto::hashToScalar(rawData.data(), rawData.size(), l_scalar);
        }
        catch (const std::exception &e)
        {
            return Nan::ThrowError(e.what());
        }

        scalar = Common::podToHex(l_scalar);
        v8::Local<v8::String> returnValue = Nan::New(scalar).ToLocalChecked();

        info.GetReturnValue().Set(returnValue);
        return;
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void rounds_required(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    uint32_t participants = 0;
    uint32_t threshold = 0;
    uint32_t required_rounds = 0;

    if (info.Length() == 2)
    {
        if (info[0]->IsNumber())
        {
            participants = (size_t)info[1]->NumberValue();
        }

        if (info[1]->IsNumber())
        {
            threshold = (size_t)info[1]->NumberValue();
        }

        required_rounds = Crypto::multisig::rounds_required(participants, threshold);

        v8::Local<v8::Number> returnValue = Nan::New(required_rounds);

        info.GetReturnValue().Set(returnValue);
        return;
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void sc_reduce32(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
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
        catch (const std::exception &e)
        {
            return Nan::ThrowError(e.what());
        }

        scalar = Common::podToHex(l_scalar);
        v8::Local<v8::String> returnValue = Nan::New(scalar).ToLocalChecked();

        info.GetReturnValue().Set(returnValue);
        return;
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void secret_key_to_public_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
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
                v8::Local<v8::String> returnValue = Nan::New(c_result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void underive_public_key(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
    size_t outputIndex = 0;

    std::string derivation = std::string();
    std::string derivedKey = std::string();

    if (info.Length() == 3)
    {

        if (info[0]->IsString())
        {
            derivation = std::string(*Nan::Utf8String(info[0]->ToString()));
        }

        if (info[1]->IsNumber())
        {
            outputIndex = (size_t)info[1]->NumberValue();
        }

        if (info[2]->IsString())
        {
            derivedKey = std::string(*Nan::Utf8String(info[2]->ToString()));
        }

        if (!derivation.empty() && !derivedKey.empty())
        {
            Crypto::KeyDerivation c_derivation;
            Common::podFromHex(derivation, c_derivation);

            Crypto::PublicKey c_derived_key;
            Common::podFromHex(derivedKey, c_derived_key);

            Crypto::PublicKey c_result;
            bool success = Crypto::underive_public_key(c_derivation, outputIndex, c_derived_key, c_result);

            if (success)
            {
                std::string result = Common::podToHex(c_result);
                v8::Local<v8::String> returnValue = Nan::New(result).ToLocalChecked();

                info.GetReturnValue().Set(returnValue);
                return;
            }
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

/* Hash Methods */

void cn_fast_hash(const Nan::FunctionCallbackInfo<v8::Value> &info)
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
            const BinaryArray &rawData = Common::fromHex(data);

            Crypto::Hash c_hash = Crypto::Hash();
            try
            {
                Crypto::cn_fast_hash(rawData.data(), rawData.size(), c_hash);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            hash = Common::podToHex(c_hash);
            v8::Local<v8::String> returnValue = Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void cn_turtle_lite_slow_hash_v0(const Nan::FunctionCallbackInfo<v8::Value> &info)
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
            const BinaryArray &rawData = Common::fromHex(data);

            Crypto::Hash c_hash = Crypto::Hash();

            try
            {
                Crypto::cn_turtle_lite_slow_hash_v0(rawData.data(), rawData.size(), c_hash);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            hash = Common::podToHex(c_hash);
            v8::Local<v8::String> returnValue = Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void cn_turtle_lite_slow_hash_v1(const Nan::FunctionCallbackInfo<v8::Value> &info)
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
            const BinaryArray &rawData = Common::fromHex(data);

            Crypto::Hash c_hash = Crypto::Hash();

            try
            {
                Crypto::cn_turtle_lite_slow_hash_v1(rawData.data(), rawData.size(), c_hash);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            hash = Common::podToHex(c_hash);
            v8::Local<v8::String> returnValue = Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void cn_turtle_lite_slow_hash_v2(const Nan::FunctionCallbackInfo<v8::Value> &info)
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
            const BinaryArray &rawData = Common::fromHex(data);

            Crypto::Hash c_hash = Crypto::Hash();

            try
            {
                Crypto::cn_turtle_lite_slow_hash_v2(rawData.data(), rawData.size(), c_hash);
            }
            catch (const std::exception &e)
            {
                return Nan::ThrowError(e.what());
            }

            hash = Common::podToHex(c_hash);
            v8::Local<v8::String> returnValue = Nan::New(hash).ToLocalChecked();

            info.GetReturnValue().Set(returnValue);
            return;
        }
    }

    info.GetReturnValue().Set(Nan::Undefined());
}

void InitModule(v8::Local<v8::Object> exports)
{
    exports->Set(Nan::New("calculateSignerKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(calculate_signer_key)->GetFunction());

    exports->Set(Nan::New("checkKey").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(check_key)->GetFunction());

    exports->Set(Nan::New("checkRingSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(check_ring_signature)->GetFunction());

    exports->Set(Nan::New("checkSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(check_signature)->GetFunction());

    exports->Set(Nan::New("derivePublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(derive_public_key)->GetFunction());

    exports->Set(Nan::New("deriveSecretKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(derive_secret_key)->GetFunction());

    exports->Set(Nan::New("generateBlindedPublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_blinded_public_key)->GetFunction());

    exports->Set(Nan::New("generateBlindedSecretKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_blinded_secret_key)->GetFunction());

    exports->Set(Nan::New("generateCompositeKeyImage").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_composite_key_image)->GetFunction());

    exports->Set(Nan::New("generateDerivations").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_derivations)->GetFunction());

    exports->Set(Nan::New("generateKeyDerivation").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_key_derivation)->GetFunction());

    exports->Set(Nan::New("generateKeys").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_keys)->GetFunction());

    exports->Set(Nan::New("generateKeyImage").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_key_image)->GetFunction());

    exports->Set(Nan::New("generateLR").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(generate_lr)->GetFunction());

    exports->Set(Nan::New("generateMNPublicSpendKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_m_n_public_spend_key)->GetFunction());

    exports->Set(Nan::New("generateNN").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(generate_n_n)->GetFunction());

    exports->Set(Nan::New("generateN1N").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_n1_n)->GetFunction());

    exports->Set(Nan::New("generateRingSignatures").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_ring_signatures)->GetFunction());

    exports->Set(Nan::New("generateSignature").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_signature)->GetFunction());

    exports->Set(Nan::New("generateViewKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(generate_view_key)->GetFunction());

    exports->Set(Nan::New("hashToScalar").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(hash_to_scalar)->GetFunction());

    exports->Set(Nan::New("roundsRequired").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(rounds_required)->GetFunction());

    exports->Set(Nan::New("scReduce32").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(sc_reduce32)->GetFunction());

    exports->Set(Nan::New("secretKeyToPublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(secret_key_to_public_key)->GetFunction());

    exports->Set(Nan::New("underivePublicKey").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(underive_public_key)->GetFunction());

    /* Hash Functions */

    exports->Set(Nan::New("cnFastHash").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(cn_fast_hash)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v0").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(cn_turtle_lite_slow_hash_v0)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v1").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(cn_turtle_lite_slow_hash_v1)->GetFunction());

    exports->Set(Nan::New("cn_turtle_lite_slow_hash_v2").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(cn_turtle_lite_slow_hash_v2)->GetFunction());
}

NODE_MODULE(turtlecoincrypto, InitModule);
