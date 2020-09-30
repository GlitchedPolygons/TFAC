/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <string.h>

#include "tfac.h"
#include "base32.h"
#include "picohash.h"

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

#define TFAC_MIN(x, y) (((x) < (y)) ? (x) : (y))

static const char* DIGITS_FORMAT[] = { "%ull", "%ull", "%02u", "%03u", "%04u", "%05u", "%06u", "%07u", "%08u", "%09u", "%010u", "%011u", "%012u", "%013u", "%014u", "%015u", "%016u", "%017u", "%018u" };
static const uint64_t DIGITS_POW[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000, 1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000 };

static const size_t HASH_ALGO_DIGEST_LENGTHS[] = { 20, 28, 32 };
static void (*HASH_ALGOS[])(picohash_ctx_t*) = {
    &picohash_init_sha1,
    &picohash_init_sha224,
    &picohash_init_sha256,
};

static uint64_t truncate(const uint8_t* hmac, const size_t hmac_length, const uint8_t digits)
{
    uint8_t offset = hmac[hmac_length - 1] & 0x0F;
    uint64_t trunc = 0;

    trunc <<= 8;
    trunc |= hmac[offset++];
    trunc <<= 8;
    trunc |= hmac[offset++];
    trunc <<= 8;
    trunc |= hmac[offset++];
    trunc <<= 8;
    trunc |= hmac[offset++];

    trunc &= 0x7FFFFFFF;
    return trunc % DIGITS_POW[TFAC_MIN(TFAC_MAX_DIGITS, digits)];
}

uint64_t tfac_hotp_raw(const uint8_t* secret_key, size_t secret_key_length, uint8_t digits, uint64_t counter, enum tfac_hash_algo hash_algo)
{
    assert(sizeof(counter) == 8);

    uint8_t c[8];
    for (size_t i = 0; i < 8; i++)
    {
        c[i] = (counter >> ((sizeof(counter) - i - 1) * 8)) & 0xFF;
    }

    uint8_t hash[32];
    picohash_ctx_t ctx;

    picohash_init_hmac(&ctx, HASH_ALGOS[hash_algo], secret_key, secret_key_length);
    picohash_update(&ctx, c, sizeof(counter));
    picohash_final(&ctx, hash);

    return truncate(hash, HASH_ALGO_DIGEST_LENGTHS[hash_algo], digits);
}

struct tfac_token tfac_hotp(const char* secret_key_base32, const uint8_t digits, const uint64_t counter, const enum tfac_hash_algo hash_algo)
{
    struct tfac_token out;
    memset(&out, 0x00, sizeof(out));

    uint8_t key[256];
    const int key_length = base32_decode((uint8_t*)secret_key_base32, key, sizeof(key));

    out.number = tfac_hotp_raw(key, key_length, digits, counter, hash_algo);
    snprintf(out.string, sizeof(out.string), DIGITS_FORMAT[TFAC_MIN(TFAC_MAX_DIGITS, digits)], out.number);

    return out;
}

uint64_t tfac_totp_raw(const uint8_t* secret_key, const size_t secret_key_length, const uint8_t digits, const uint8_t steps, const enum tfac_hash_algo hash_algo)
{
    return tfac_hotp_raw(secret_key, secret_key_length, digits, (uint64_t)(time(0) / steps), hash_algo);
}

struct tfac_token tfac_totp(const char* secret_key_base32, const uint8_t digits, const uint8_t steps, const enum tfac_hash_algo hash_algo)
{
    struct tfac_token out;
    memset(&out, 0x00, sizeof(out));

    uint8_t key[256];
    const int key_length = base32_decode((uint8_t*)secret_key_base32, key, sizeof(key));

    out.number = tfac_totp_raw(key, key_length, digits, steps, hash_algo);
    snprintf(out.string, sizeof(out.string), DIGITS_FORMAT[TFAC_MIN(TFAC_MAX_DIGITS, digits)], out.number);

    return out;
}

static void tfac_dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, (ULONG)output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = fopen("/dev/urandom", "r");
        if (rnd != NULL)
        {
            fread(output_buffer, sizeof(uint8_t), output_buffer_size, rnd);
            fclose(rnd);
        }
#endif
    }
}

struct tfac_secret tfac_generate_secret()
{
    struct tfac_secret out;
    memset(&out, 0x00, sizeof(out));

    tfac_dev_urandom(out.secret_key, sizeof(out.secret_key));
    base32_encode(out.secret_key, sizeof(out.secret_key), (uint8_t*)out.secret_key_base32, sizeof(out.secret_key_base32));

    return out;
}

#undef TFAC_MIN
