// args.cpp: 

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "def.h"
#include "global.h"

void usage ()
{
    printf ("%s: The network video stream sniffer and capture.\n" \
            "\t\t<-i | --interface name>\n" \
            "\t\t<-c | --config config file path>\n" \
            "\t\t[-f | --filter bpf rule]\n" \
            "\t\t[-b | --back another ethernet card name to send back ]\n" \
            "\t\t[-p | --cpu-profile profile file path]\n" \
            "\t\t[-d | --debug more debug info output]\n" \
            "\t\t[-h | --help]\n" \
            "\t\t[-v | --version]\n" \
            , PROG_NAME);
    exit (0);
}

void parse_args (int argc, char **argv)
{
    if (1 == argc)
        usage ();
    while (1) {
        static struct option long_options[] = {
            {"version", 0, 0, 'v'},
            {"help", 0, 0, 'h'},
            {"interface", 0, 0, 'i'},
            {"back", 0, 0, 'b'},
            {"filter", 0, 0, 'f'},
            {"config", 0, 0, 'c'},
            {"cpu-profile", 0, 0, 'p'},
            {"debug", 0, 0, 'd'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        int c = getopt_long (argc, argv, "vhdi:b:f:c:p:", long_options, &option_index);
        if (-1 == c)
            break;
        switch (c) {
            case 'v':
                printf ("Version: %s\n", PROG_VERSION);
                exit (0);
            case 'h':
                usage ();
                break;
            case 'b':
                g_back_interface = optarg;
                break;
            case 'i':
                g_interface = optarg;
                break;
            case 'f':
                g_bpf = optarg;
                break;
            case 'c':
                g_conf = optarg;
                break;
            case 'p':
                g_cpu_profile = optarg;
                break;
            case 'd':
                g_debug = true;
                break;
            default:
                usage ();
                break;
        }
    }
    if (!g_interface) {
        printf ("interface not set!\n");
        exit (1);
    }
/*
    if (!g_conf) {
        printf ("config not set!\n");
        exit (1);
    }
*/
}

