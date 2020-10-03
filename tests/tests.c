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
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "acutest.h"
#include "../src/tfac.h"

#if defined(_WIN32)
#include <windows.h>
#define tfac_tests_sleep Sleep
#else
#include <unistd.h>
#define tfac_tests_sleep(t) sleep((t / 1000))
#endif

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_CHECK(1);
}

static void totp_generates_and_validates_correctly()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_SHA1);
    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2 = tfac_totp(s2.secret_key_base32, 8, 25, TFAC_SHA256);
    TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));

    const struct tfac_secret s3 = tfac_generate_secret();
    const struct tfac_token t3 = tfac_totp(s3.secret_key_base32, 12, 12, TFAC_SHA1);
    TEST_CHECK(tfac_verify_totp(s3.secret_key_base32, t3.string, 12, TFAC_SHA1));
}

static void totp_reusage_fails()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_SHA1);
    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));
    TEST_CHECK(!tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2 = tfac_totp(s2.secret_key_base32, 8, 25, TFAC_SHA256);
    TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
}

static void totp_reusage_fails_even_with_lots_of_traffic()
{
    for (size_t i = 0; i < 16384; i++)
    {
        const struct tfac_secret s1 = tfac_generate_secret();
        const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO);

        TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));
        TEST_CHECK(!tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));

        const struct tfac_secret s2 = tfac_generate_secret();
        const struct tfac_token t2 = tfac_totp(s2.secret_key_base32, 8, 25, TFAC_SHA256);

        TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
        TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
        TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
        TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    }
}

static void totp_too_many_digits_validation_fails()
{
    TEST_CHECK(!tfac_verify_totp("7LJ26BSA4LKA5HMJ62OA65GU443MD6VCGS3DJH765TURZFVL", "0384674762807506494875736506294931874314002487965614145678029857", 30, TFAC_SHA1));
}

static void totp_validate_wrong_token_fails()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO);

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2 = tfac_totp(s2.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO);

    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));
    TEST_CHECK(!tfac_verify_totp(s1.secret_key_base32, t2.string, TFAC_DEFAULT_STEPS, TFAC_SHA1));
}

static void totp_validate_expired_token_fails_except_allowed_error_margin()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1_1 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 1, TFAC_DEFAULT_HASH_ALGO);

    tfac_tests_sleep(3000);

    const struct tfac_token t1_2 = tfac_totp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 1, TFAC_DEFAULT_HASH_ALGO);
    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1_2.string, 1, TFAC_SHA1));
    TEST_CHECK(!tfac_verify_totp(s1.secret_key_base32, t1_1.string, 1, TFAC_SHA1));

    // Test the allowed +/- 1 stepcount cycle error margin:

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2_1 = tfac_totp(s2.secret_key_base32, TFAC_DEFAULT_DIGITS, 1, TFAC_DEFAULT_HASH_ALGO);
    tfac_tests_sleep(1000);
    const struct tfac_token t2_2 = tfac_totp(s2.secret_key_base32, TFAC_DEFAULT_DIGITS, 1, TFAC_DEFAULT_HASH_ALGO);
    TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2_1.string, 1, TFAC_SHA1));
    TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2_2.string, 1, TFAC_SHA1));
}

static void hotp_generates_correctly_and_validates_correctly()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1 = tfac_hotp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 123, TFAC_DEFAULT_HASH_ALGO);
    const struct tfac_token t2 = tfac_hotp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 123, TFAC_DEFAULT_HASH_ALGO);

    TEST_CHECK(t1.number == t2.number);
    TEST_CHECK(strcmp(t1.string, t2.string) == 0);
}

static void hotp_validate_wrong_token_fails()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1_1 = tfac_hotp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 123, TFAC_DEFAULT_HASH_ALGO);
    const struct tfac_token t1_2 = tfac_hotp(s1.secret_key_base32, TFAC_DEFAULT_DIGITS, 124, TFAC_DEFAULT_HASH_ALGO);

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2_1 = tfac_hotp(s2.secret_key_base32, TFAC_DEFAULT_DIGITS, 456, TFAC_DEFAULT_HASH_ALGO);
    const struct tfac_token t2_2 = tfac_hotp(s2.secret_key_base32, TFAC_DEFAULT_DIGITS, 457, TFAC_DEFAULT_HASH_ALGO);

    TEST_CHECK(t1_1.number == t1_1.number);
    TEST_CHECK(t1_1.number != t1_2.number);
    TEST_CHECK(strcmp(t1_1.string, t1_1.string) == 0);
    TEST_CHECK(strcmp(t1_1.string, t1_2.string) != 0);

    TEST_CHECK(t2_1.number == t2_1.number);
    TEST_CHECK(t2_1.number != t2_2.number);
    TEST_CHECK(strcmp(t2_1.string, t2_1.string) == 0);
    TEST_CHECK(strcmp(t2_1.string, t2_2.string) != 0);

    TEST_ASSERT(t1_1.number != t2_1.number);
    TEST_ASSERT(t1_2.number != t2_2.number);
}

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    { "totp_generates_and_validates_correctly", totp_generates_and_validates_correctly }, //
    { "totp_reusage_fails", totp_reusage_fails }, //
    { "totp_too_many_digits_validation_fails", totp_too_many_digits_validation_fails }, //
    { "totp_validate_wrong_token_fails", totp_validate_wrong_token_fails }, //
    { "totp_reusage_fails_even_with_lots_of_traffic", totp_reusage_fails_even_with_lots_of_traffic }, //
    { "hotp_generates_correctly_and_validates_correctly", hotp_generates_correctly_and_validates_correctly }, //
    { "hotp_validate_wrong_token_fails", hotp_validate_wrong_token_fails }, //
    { "totp_validate_expired_token_fails_except_allowed_error_margin", totp_validate_expired_token_fails_except_allowed_error_margin }, //
    // ------------------------------------------------------------------------------------------------------------
    { NULL, NULL } //
};