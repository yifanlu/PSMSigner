/*
 * revoke_sign.c
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
#include <stdlib.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

const char pem_key[] = 
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxl+8fRzDzyWb0\n"
    "89L9ssKWMO4IYJATVV/qsGPqL5XtgjqlSY6dV3QHWtdiqm4B9h8cy325+XEORMC8\n"
    "oErllSl7yovu956/D5laLLGqRkyFPcNer+DOjO99bDfJTTV1bSHuwc9oo3mJn6AO\n"
    "WuiY3aguCIYxNgSlDsfavjmCDXa3Q85hFOxJnn7HlM4X6rNxFi9y48LqUrDyWw0L\n"
    "bs+07bqNLoYHXtMoZcNQHqNmGtIHGx4RuFzZ4hduorjNsmSKHiQSz+ydJgJWtLJO\n"
    "tC2EM8zj8zStmlDiMTyAqKPHjENp4FBLoF87PISLsbyf4dTdWk35TvnsU/+tGVyH\n"
    "bVNcEAzvAgMBAAECggEBAKSil//kDIKD/BkrDDc6h9+aHqDPe+EgbVnxCb8pPBFB\n"
    "gEKIbVh5oUvMMA38txzEYNVd5AELOH6kyBRVePlajWmAPLddAOJYgK6y7kVPBFMl\n"
    "Db/yxjJVPxODxjeshtmEQUfIjhGQMvSdcVC9gBFusyFxr41haW7mw+mKHV/uQVbk\n"
    "TM/ZnEaN2Zrl7FfCUwXa3qyMrwj01bbAXXEqdM9ZF3UIXCLzihtNDKPAbpcVoQXH\n"
    "fItXVFeHjXqVCOVcKTI1PgElM6Q7VsVsU4pJGOmKy2gFbKqF4eniDK6gdGitbVpp\n"
    "rlXIrS2P8ZOfT+fSMjLbrr+mJEc2np4LYFlEHcJgtkkCgYEAwMrmf1LasiU/sijh\n"
    "0fOTV6TXefSrOxnpiq9Qs/oTSZ5USTh5FrunF0dX5Isy4XjYKWfIVwVl9LnAXRqR\n"
    "QTiHkbFon2KMYYyQfDUe4T9kuX6cAqp8WjBaivxs8chErM8rzZns62bR1B9+/IX4\n"
    "VIiHA1jfP9eiCl+1lMhhnnNIHX0CgYEA69Ffc2w5UCJ1cHxu8dR9V4otY57vBJFN\n"
    "2Svb8h3kJnO9LfU/RYMeXTgJSklh9Tw/zXPOMEQnxi7LocrDd1713vQTTspT3wWd\n"
    "3AJ25l0BP3NGnbEtGwv6It+VnUULr964vOUv/bl4UMQs52JsnxURts+GPZ3gAF1S\n"
    "U2AVxvVej9sCgYBAk7Yhb99RTKjJRGhfqvbvpIeIkivI4CUaDx85KcrMHfydig0F\n"
    "UFXntj36j6W7YH8HX3v7qhM8pfuJNBzze7vtUT96I8hh5HOBJ0nwqQtUFtSrD/AX\n"
    "RZsOcv8K/coDGGHTvHtfXlFqfCJM85L6vcB7nokpGVFtqCFqdLQ+Ht9JAQKBgQCU\n"
    "Ao/0dCLs5xPrDE7ePk6FmVavxlui9Eh2XI7qQlSmxdIhfGLAEHIIdFlwZOq076Hk\n"
    "JCFwLfcA7vIklI1m6RVNYMiVlWxa+L2CD5HtOMbFumbCJyh2Z2gSZ18SnPme4x30\n"
    "ga1DhRu9JcRBXodqueCqa0qIdgTYdbpsVkyU2gEGLQKBgGotuH/yrXNfifTc6Y24\n"
    "TSaqk/Dq6OvQOEFSIzgOzaQhWvwZjlz3uOnmi3vUo/guG9q/J1JWucWoXNXkkcmb\n"
    "trc3RYwzy6Rn+0uGHGA91e2bn6vT6PLNOgNUE7YCRDJe5DsDYHtUNILNbRVdSvNs\n"
    "rnh1i22Y3zLWChh3swswqgf7\n"
    "-----END PRIVATE KEY-----\n";

int
hash_with_date (const char *path, FILE *fout, unsigned char hash[SHA256_DIGEST_LENGTH])
{
    FILE *fp;
    SHA256_CTX sha;
    char buffer[1024];
    int len;
    time_t rawtime;
    struct tm *timeinfo;

    if (!SHA256_Init (&sha))
    {
        return -1;
    }
    if ((fp = fopen (path, "r")) == NULL)
    {
        return -1;
    }

    // read in the original data
    while ((len = fread (buffer, 1, 1024, fp)) > 0)
    {
        if (fwrite (buffer, 1, len, fout) < len)
        {
            return -1;
        }
        if (!SHA256_Update (&sha, buffer, len))
        {
            return -1;
        }
    }

    // add date stamp
    time (&rawtime);
    timeinfo = gmtime (&rawtime);
    len = strftime (buffer, 1024, "%Y%m%d", timeinfo);
    if (len < 1)
    {
        return -1;
    }
    if (fwrite (buffer, 1, len+1, fout) < len)
    {
        return -1;
    }
    if (!SHA256_Update (&sha, buffer, len+1))
    {
        return -1;
    }

    if (!SHA256_Final (hash, &sha))
    {
        return -1;
    }

    return 0;
}

int
main (int argc, const char *argv[])
{
    BIO *bio;
    RSA *rsa;
    FILE *fout;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char sig[256];
    unsigned int siglen;

    if (argc < 3)
    {
        fprintf (stderr, "usage: %s input output\n"
                         "  input   NSXVID-PSS.VT.WW-GLOBAL.xml file\n"
                         "  output  xml with current UTC date signed\n", argv[0]);
        return 1;
    }

    if ((fout = fopen (argv[2], "w")) == NULL)
    {
        perror ("output");
        return 1;
    }

    if ((bio = BIO_new_mem_buf((void*)pem_key, sizeof (pem_key))) == NULL)
    {
        ERR_print_errors_fp (stderr);
        return 1;
    }

    if (!PEM_read_bio_RSAPrivateKey (bio, &rsa, NULL, NULL))
    {
        ERR_print_errors_fp (stderr);
        return 1;
    }

    if (hash_with_date (argv[1], fout, hash) < 0)
    {
        perror ("sha256");
        ERR_print_errors_fp (stderr);
        goto error;
    }

    if (RSA_sign (NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &siglen, rsa) != 1)
    {
        ERR_print_errors_fp (stderr);
        return 1;
    }

    if (fwrite (sig, 1, sizeof (sig), fout) < sizeof (sig))
    {
        perror ("fwrite");
        return 1;
    }

error:
    fclose (fout);
    RSA_free (rsa);
    return 0;
}
