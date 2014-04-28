// main.cpp: 
// Copyright (c) 2013 Vobile Inc. All Rights Reserved.
// guo_jiafeng@vobile.cn
// 03/18/2014 15:35:48 PM

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <iostream>

#include <pcap.h>
#include "extern.h"
#include "parse_pkt.h"

using namespace std;

extern void parse_args (int, char**);
extern void get_pkt (u_char*, const struct pcap_pkthdr*, const u_char*);
extern char *datalink2str (int dl_id);
extern int datalink2off (int dl_id);

void *parse_pkt (void *args)
{
    ParsePkt2::get_instance ()->run ();
    return 0;
}

void sig_handler (int sig)
{
    cout << "get signal " << sig <<endl;
    exit (0);
}

int main (int argc, char **argv)
{
    struct sigaction sigact;
    memset (&sigact, 0, sizeof (sigact));
    sigact.sa_handler = sig_handler;
    sigact.sa_flags = SA_RESETHAND;
    sigaction (SIGINT, &sigact, NULL); //set new act as sig_handler when SIGINT and SIGTERM come
    sigaction (SIGTERM, &sigact, NULL);

    signal(SIGCHLD, SIG_IGN);   //set SIG_IGN to ignore this SIGCHLD signal

    parse_args (argc, argv);

    pthread_t tid ;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    int ret = pthread_create (&tid, &attr, &parse_pkt, NULL);
    if (ret) {
        printf ("create thread failed");
        pthread_attr_destroy(&attr);
        return -1;
    }

    char err_buf[PCAP_ERRBUF_SIZE];
    /* open a device, wait until a packet arrives */
    pcap_t *device = pcap_open_live (g_interface, 65535, 1, 0, err_buf);
    if (!device) {
        printf ("error: pcap_open_live(): %s\n", err_buf);
        exit (1);
    }

    /* getting information about the datalink type of the device choosen 
       (not all are supported) */
    int datalink_id = pcap_datalink (device);
    cout << "datalink string: " << (char*) datalink2str (datalink_id) << endl;
    g_datalink_size = datalink2off (datalink_id);
    cout << "datalink header size: " << g_datalink_size << endl;

    /* construct a filter */
    cout << "filter: " << g_bpf <<endl;
    struct bpf_program filter;
    if (pcap_compile (device, &filter, g_bpf, 1, 0)) {
        printf ("compile filter %s failed: %s\n", g_bpf, pcap_geterr (device));
        exit (1);
    }
    if (pcap_setfilter (device, &filter)) {
        printf ("set filter %s failed: %s\n", g_bpf, pcap_geterr (device));
        exit (1);
    }

    /* wait loop forever  -1 means forever until error come */
    int id = 0;
    pcap_loop (device, -1, get_pkt, (u_char*)&id);

    pcap_close (device);

    return 0;
}

