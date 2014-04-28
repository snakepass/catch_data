// Copyright (c) 2013 Vobile Inc. All Rights Reserved.
// wu_shengrui@vobile.cn
// 09/08/2013 01:44:54 AM

#ifndef VS_PARSE_PKT2_H_
#define VS_PARSE_PKT2_H_

#include <map>
#include <string>
#include <vector>
#include <list>
#include <arpa/inet.h>
#include <unistd.h>

#include "def.h"

typedef std::map<std::string, struct Stream> StreamMap;
typedef std::vector<std::vector<u_char> > payloadBuf;
typedef std::list<std::string> PktList;
typedef struct Stream {
    Stream () {};
    Stream (struct in_addr src, struct in_addr dst, uint16_t src_port, uint16_t dst_port) {
        ip_src = src;
        ip_dst = dst;
        port_src = src_port;
        port_dst = dst_port;
        stream_protocol = TODETECT;
        payload_offset = 0;
        last_pkt_time = time (NULL);
        wfd = dummy_rfd = -1;
    };
    struct in_addr ip_src, ip_dst;
    u_int16_t port_src;
    u_int16_t port_dst;
    StreamProtocol stream_protocol;
    int payload_offset;
    time_t last_pkt_time;
    int wfd;
    int dummy_rfd;
    //以下储存视频数据
    std::string fifo;
    payloadBuf buf;
} Stream;

class ParsePkt2 {
    public:
        ParsePkt2 ();
        ~ ParsePkt2 ();
        static ParsePkt2* get_instance ();
        void add_pkt (u_char *payload, unsigned payload_len
                , struct in_addr ip_src, struct in_addr ip_dst
                , u_int16_t port_src, uint16_t port_dst);
        void process_pkt (Stream &stream);
        void run ();
    private:
        void detect_protocol (Stream &stream);
        void print_map ();
        bool is_udpts (Stream &stream);
        bool is_rtp (Stream &stream);
        std::string gen_key (struct in_addr ip_src, struct in_addr ip_dst, uint16_t port_src, uint16_t port_dst);
        void ingest_live (const char * file);
    private:
        StreamMap stream_map;
        PktList pkt_list;
        pthread_mutex_t mutex;
};
#endif
