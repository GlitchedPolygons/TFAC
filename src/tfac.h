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

/**
 * @file tfac.h
 * @author Raphael Beck
 * @brief 2FA (Two-Factor Authentication) for C using TOTP/HOTP.
 */

#ifndef TFAC_H
#define TFAC_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(TFAC_DLL)
#ifdef TFAC_BUILD_DLL
#define TFAC_API __declspec(dllexport)
#else
#define TFAC_API __declspec(dllimport)
#endif
#else
#define TFAC_API
#endif

#include <time.h>
#include <stdint.h>
#include <stddef.h>

/**
 * The maximum amount of digits in the output token. <p>
 * Any digits parameter passed to the hotp/totp functions that exceeds this value is clamped to it.
 */
#define TFAC_MAX_DIGITS 18

/**
 * Maximum size of 2FA secrets. Keys that exceed this length will be truncated!
 */
#define TFAC_MAX_SECRET_KEY_SIZE 256

/**
 * The default hash algorithm to use for the HMAC is SHA-1.
 */
#define TFAC_DEFAULT_HASH_ALGO 0

/**
 * Default amount of token digits for typical Google Authenticator tokens (6 digits).
 */
#define TFAC_DEFAULT_DIGITS 6

/**
 * Default step count for typical Google Authenticator token formats (30 seconds).
 */
#define TFAC_DEFAULT_STEPS 30

/**
 * The hash algorithm to use for the HMAC (default is SHA-1).
 */
enum tfac_hash_algo
{
    TFAC_SHA1 = 0,
    TFAC_SHA224 = 1,
    TFAC_SHA256 = 2,
};

/**
 * A tfac result's token (NUL-terminated string containing the TOTP/HOTP).
 */
struct tfac_token
{
    /**
     * NUL-terminated string containing the 2FA token.
     */
    char string[32];

    /**
     * The raw number behind the token
     * (if the token starts with one or more zeros,
     * this padding is obviously not going to be in here;
     * e.g. the token <c>"001337"</c> would be the number <c>1337</c> here).
     */
    uint64_t number;
};

/**
 * A secret to use for generating HOTP/TOTP tokens.
 * This is returned by the tfac_generate_secret() function.
 */
struct tfac_secret
{
    /**
     * The base32-encoded 2FA secret.
     * This is a NUL-terminated string.
     */
    char secret_key_base32[48 + 1];

    /**
     * The raw 2FA secret key bytes.
     */
    uint8_t secret_key[30];
};

/**
 * Structure containing TFAC library version information.
 */
struct tfac_version_number
{
    /**
     * Major version number.
     */
    uint32_t major;

    /**
     * Minor version number.
     */
    uint32_t minor;

    /**
     * Hotfix/patch number.
     */
    uint32_t patch;

    /**
     * Nicely formatted version number string.
     */
    char string[32];
};

/**
 * Generate a random 2FA secret to use for HOTP/TOTP token generation.
 * @return tfac_secret instance containing both the base32-encoded as well as the raw secret key bytes.
 */
TFAC_API struct tfac_secret tfac_generate_secret();

/**
 * Generate a TOTP token using a given secret key (which is a base32-encoded, NUL-terminated string).
 * @param secret_key_base32 The base32-encoded, NUL-terminated string containing the secret key to use for generating the token.
 * @param digits How many digits should the output token contain? If unsure, pass #TFAC_DEFAULT_DIGITS (which is <c>6</c>).
 * @param steps The step count: default is 30 seconds (#TFAC_DEFAULT_STEPS).
 * @param hash_algo Which hashing algorithm to use for the <c>HMAC</c>: default is <c>SHA-1</c> (#TFAC_DEFAULT_HASH_ALGO).
 * @return The TOTP token.
 */
TFAC_API struct tfac_token tfac_totp(const char* secret_key_base32, uint8_t digits, uint8_t steps, enum tfac_hash_algo hash_algo);

/**
 * Raw TOTP generator function: this returns the raw, unsigned integer behind a TOTP token. <p>
 * Leading zeros won't (obviously) be included, so if the generated TOTP happens to be <c>"001502"</c> this will return <c>1502</c>.
 * @param secret_key The byte array containing the 2FA secret key to use for token generation.
 * @param secret_key_length Length of the \p secret_key byte array.
 * @param digits How many digits should the output token contain? If unsure, pass #TFAC_DEFAULT_DIGITS (which is <c>6</c>).
 * @param steps The step count: default is 30 seconds (#TFAC_DEFAULT_STEPS).
 * @param hash_algo Which hashing algorithm to use for the <c>HMAC</c>: default is <c>SHA-1</c> (#TFAC_DEFAULT_HASH_ALGO).
 * @param utc The UTC timestamp for which to generate the TOTP. Pass <c>time(0)</c> to generate a currently valid token!
 * @return The TOTP token as an unsigned 64-bit integer.
 */
TFAC_API uint64_t tfac_totp_raw(const uint8_t* secret_key, size_t secret_key_length, uint8_t digits, uint8_t steps, enum tfac_hash_algo hash_algo, time_t utc);

/**
 * Verifies a TOTP using the given \p secret_key_base32. If the token is validated successfully, it is obliterated and cannot be validated again: further tries will fail.
 * @param secret_key_base32 The 2FA secret (Base32-encoded, NUL-terminated string).
 * @param totp The token to verify.
 * @param digits How many digits the token to validate is supposed to contain.
 * @param steps The steps parameter that was used to generate the token,
 * @param hash_algo The hash algorithm that the token was created with (default is SHA-1: #TFAC_DEFAULT_HASH_ALGO).
 * @return <c>1</c> if the token was valid; <c>0</c> if verification failed or if the token has already been used.
 */
TFAC_API uint8_t tfac_verify_totp(const char* secret_key_base32, const char* totp, uint8_t digits, uint8_t steps, enum tfac_hash_algo hash_algo);

/**
 * Generate an HOTP using a given secret key (which is a base32-encoded, NUL-terminated string).
 * @param secret_key_base32 The base32-encoded, NUL-terminated string containing the secret key to use for generating the token.
 * @param digits How many digits should the output token contain? If unsure, pass #TFAC_DEFAULT_DIGITS.
 * @param counter The counter value to use for HOTP generation (64-bit unsigned integer).
 * @param hash_algo Which hashing algorithm to use for the <c>HMAC</c>: default is <c>SHA-1</c> (#TFAC_DEFAULT_HASH_ALGO).
 * @return The HOTP token.
 */
TFAC_API struct tfac_token tfac_hotp(const char* secret_key_base32, uint8_t digits, uint64_t counter, enum tfac_hash_algo hash_algo);

/**
 * Raw HOTP generator function: this returns the raw, unsigned integer behind an HOTP token. <p>
 * Leading zeros won't (obviously) be included, so if the generated TOTP happens to be <c>"000420"</c> this will return <c>420</c>.
 * @param secret_key The byte array containing the 2FA secret key to use for generating the token.
 * @param secret_key_length Length of the \p secret_key byte array.
 * @param digits How many digits should the output token contain? If unsure, pass #TFAC_DEFAULT_DIGITS (which is <c>6</c>).
 * @param counter The counter value to use for HOTP generation (64-bit unsigned integer).
 * @param hash_algo Which hashing algorithm to use for the <c>HMAC</c>: default is <c>SHA-1</c> (#TFAC_DEFAULT_HASH_ALGO).
 * @return The HOTP token as an unsigned 64-bit integer.
 */
TFAC_API uint64_t tfac_hotp_raw(const uint8_t* secret_key, size_t secret_key_length, uint8_t digits, uint64_t counter, enum tfac_hash_algo hash_algo);

/**
 * Gets the current TFAC library version number.
 * @return A tfac_version_number instance containing raw numbers as well as a nicely formatted string (in the format of \c MAJOR.MINOR.HOTFIX ).
 */
TFAC_API struct tfac_version_number tfac_get_version_number();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // TFAC_H