// def.h: 
// Copyright (c) 2013 Vobile Inc. All Rights Reserved.
// wu_shengrui@vobile.cn
// 09/06/2013 04:46:30 PM

#ifndef VS_DEF_H_
#define VS_DEF_H_

#define PROG_VERSION "1.0.0.0"
#define PROG_NAME "video_sniffer" 
#define IP_SIZE 20
#define DEFAULT_BUF_PKT_CNT 5
#define STREAM_DIR "/home/sniffer/var/stream"
#define SAMPLE_DIR "/home/sniffer/var/sample"
#define LOG_DIR "/home/sniffer/var/log"
#define WRITE_RETRY_TIMES 5

enum StreamProtocol {
    TODETECT = 0,
    UNKNOWN,
    UDP,
    RTP,
};

enum VideoFormat {
    UNSUPPORT = 0,
    TS,
};
#endif
