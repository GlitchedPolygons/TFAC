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

#include "tfac.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("No 2FA secret provided! Please pass the Base32-encoded secret key as an argument to generate a TOTP token with it...\n");
        return -1;
    }

    const char* secret_key_base32 = argv[1];
    uint8_t digits = TFAC_DEFAULT_DIGITS;
    uint8_t steps = TFAC_DEFAULT_STEPS;
    enum tfac_hash_algo hash_algo = TFAC_DEFAULT_HASH_ALGO;

    if (argc >= 3)
    {
        digits = (uint8_t)strtoul(argv[2], NULL, 10);
    }

    if (argc >= 4)
    {
        steps = (uint8_t)strtoul(argv[3], NULL, 10);
    }

    if (argc >= 5)
    {
        hash_algo = (enum tfac_hash_algo)strtoul(argv[4], NULL, 10);
    }

    const struct tfac_token token = tfac_totp(secret_key_base32, digits, steps, hash_algo);

    printf("%s\n", token.string);
    // printf("Raw number:   %llu\n", r.number);
    // printf("Token string: %s\n", r.string);
}