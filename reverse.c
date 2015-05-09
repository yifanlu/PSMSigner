/*
 * reverse.c
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
#include <stdlib.h>
#include <stdio.h>

int
main (int argc, const char *argv[])
{
    long int len, i;
    FILE *fp = fopen (argv[1], "r");
    char byte;

    for (i = 0; ; i++)
    {
        fseek (fp, -(i+1), SEEK_END);

        fread (&byte, 1, 1, fp);
        fwrite (&byte, 1, 1, stdout);

        if (ftell (fp) == 1)
        {
            break;
        }
    }

    fclose (fp);
    return 0;
}