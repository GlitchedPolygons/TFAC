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

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_CHECK(1);
}

static void totp_generates_and_validates_correctly()
{
    const struct tfac_secret s1 = tfac_generate_secret();
    const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, 6, 30, TFAC_SHA1);
    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, 30, TFAC_SHA1));

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
    const struct tfac_token t1 = tfac_totp(s1.secret_key_base32, 6, 30, TFAC_SHA1);
    TEST_CHECK(tfac_verify_totp(s1.secret_key_base32, t1.string, 30, TFAC_SHA1));
    TEST_CHECK(!tfac_verify_totp(s1.secret_key_base32, t1.string, 30, TFAC_SHA1));

    const struct tfac_secret s2 = tfac_generate_secret();
    const struct tfac_token t2 = tfac_totp(s2.secret_key_base32, 8, 25, TFAC_SHA256);
    TEST_CHECK(tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
    TEST_CHECK(!tfac_verify_totp(s2.secret_key_base32, t2.string, 25, TFAC_SHA256));
}

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    { "totp_generates_and_validates_correctly", totp_generates_and_validates_correctly }, //
    { "totp_reusage_fails", totp_reusage_fails }, //
    { NULL, NULL } //
};