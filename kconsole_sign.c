/*
 * kconsole_sign.c
 * Copyright 2015 Yifan Lu
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define KCONSOLE_CACHE_SIZE 1680
#define SHA256_BLOCK_SIZE 64

const unsigned char key[] = {0xB7, 0x39, 0x66, 0x32, 0x0E, 0x28, 0x6A, 0xDC, 0x03, 0xF0, 0x54, 0x65, 0xCA, 0x9E, 0x2F, 0x92, 0x38, 0x8A, 0xEE, 0x23, 0x6D, 0x43, 0x88, 0x31, 0x35, 0xBA, 0xB0, 0xA5, 0xBD, 0x50, 0x43, 0xEA};
const unsigned char expire[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int
main (int argc, const char *argv[])
{
    FILE *infp, *outfp;
    SHA256_CTX sha;
    unsigned char kconsole_cache[KCONSOLE_CACHE_SIZE];
    unsigned char key_blk[SHA256_BLOCK_SIZE];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i;

    if (argc < 3)
    {
        fprintf (stderr, "usage: %s input output\n"
                         "  input   protected_kconsole_cache.dat from Vita\n"
                         "  output  patched kconsole cache with no expiration\n", argv[0]);
        return 1;
    }

    if ((infp = fopen (argv[1], "r")) == NULL)
    {
        perror ("input");
        return 1;
    }

    if ((outfp = fopen (argv[2], "w")) == NULL)
    {
        perror ("output");
        return 1;
    }

    // first time hash
    if (!SHA256_Init (&sha))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    memset (key_blk, 0, SHA256_BLOCK_SIZE);
    memcpy (key_blk, key, sizeof (key));
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        key_blk[i] ^= 0x36;
    }

    if (!SHA256_Update (&sha, key_blk, SHA256_BLOCK_SIZE))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (fread (kconsole_cache, KCONSOLE_CACHE_SIZE, 1, infp) < 1)
    {
        perror ("read input");
        goto error;
    }

    // patch time
    memcpy (&kconsole_cache[KCONSOLE_CACHE_SIZE-sizeof (expire)], expire, sizeof (expire));

    if (!SHA256_Update (&sha, kconsole_cache, KCONSOLE_CACHE_SIZE))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (fwrite (kconsole_cache, KCONSOLE_CACHE_SIZE, 1, outfp) < 1)
    {
        perror ("write output");
        goto error;
    }

    if (!SHA256_Final (hash, &sha))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    // second time hash
    if (!SHA256_Init (&sha))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        key_blk[i] ^= 0x6A;
    }

    if (!SHA256_Update (&sha, key_blk, SHA256_BLOCK_SIZE))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (!SHA256_Update (&sha, hash, SHA256_DIGEST_LENGTH))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (!SHA256_Final (hash, &sha))
    {
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (fwrite (hash, SHA256_DIGEST_LENGTH, 1, outfp) < 1)
    {
        perror ("write output");
        goto error;
    }

error:
    fclose (infp);
    fclose (outfp);
    return 0;
}
