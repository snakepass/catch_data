
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "parse_pkt.h"
#include "def.h"
#include "extern.h"
#include <iostream>
using namespace std;

ParsePkt2::ParsePkt2 ()
{
    pthread_mutex_init (&mutex, NULL);
}

ParsePkt2::~ParsePkt2 ()
{
    pthread_mutex_destroy (&mutex);
}

ParsePkt2* ParsePkt2::get_instance ()
{
    static ParsePkt2 *instance = NULL;
    if (!instance) {
        instance = new ParsePkt2();
    }
    return instance;
}

void ParsePkt2::ingest_live (const char *file)
{
/*
    time_t last_data_come = time (0);
    while (! g_video_info.fps) {
        if (get_video_info ()) {
            time_t now = time (0);
            if (now - last_data_come > g_wait_timeout) {
                err_exit ("no data timeout");
            }
            sleep (1);
        } else {
            break;
        }
    }
*/

    struct stat st_first;
    struct stat st_last;

    memset(&st_first,0x00,sizeof(st_first));
    memset(&st_last,0x00,sizeof(st_last));
    while(true)
    {
        if(!stat(file,&st_first))
        {
            sleep(1);
            stat(file,&st_last);
            if(st_first.st_size==st_last.st_size&&st_first.st_mtime==st_last.st_mtime)
                break;
        } else {
            printf("%s size:%ld\n",file,st_first.st_size);
            sleep(1);   
        }
    }
}

void ParsePkt2::run ()
{
    while (true) {
        pthread_mutex_lock (&mutex);
        unsigned sz = pkt_list.size ();
        if (sz) {
            if (g_debug)
                cout << "pkt list size: " << sz;
            string key = pkt_list.front ();
            pkt_list.pop_front ();
            Stream &stream = stream_map.find (key)->second;

            time_t now = time (NULL);
            if (now - stream.last_pkt_time > g_ffmpeg_timeout) {
                stream_map.erase (key); // avoid pkt_list too long to block real stream
                pthread_mutex_unlock (&mutex);
                continue;
            }

            unsigned buf_sz = stream.buf.size ();
            if (buf_sz < DEFAULT_BUF_PKT_CNT) {
                pkt_list.push_back (key);
                pthread_mutex_unlock (&mutex);
                continue;
            }
#ifndef NDEBUG
            print_map ();
#endif
            pthread_mutex_unlock (&mutex);
            if (buf_sz >= DEFAULT_BUF_PKT_CNT)
                //这里可以采用一个多线程去处理
                process_pkt (stream);
            else
                usleep (1000 * 500);    // incase cpu too busy
        } else {
            pthread_mutex_unlock (&mutex);
            usleep (1000 * 500);
        }
    }
}

bool ParsePkt2::is_udpts (Stream &stream)
{
    cout << "start to detect udpts" <<endl;
    // FIX ME
    g_enable_ts = 1;
    if (g_enable_ts && stream.port_dst && stream.port_dst % 1000 == 0) {
        cout << "Detect UDPTS stream";
        if ((mkfifo (stream.fifo.c_str (), 0666) < 0) && errno != EEXIST) {
            cout << "create fifo " << stream.fifo << " failed, errno " << errno <<endl;
        } else {
            int dummy_rfd = open (stream.fifo.c_str (), O_RDONLY | O_NONBLOCK);
            (void) dummy_rfd;
            int wfd = open (stream.fifo.c_str (), O_CREAT | O_WRONLY | O_NONBLOCK, S_IRUSR | S_IWUSR | S_IROTH);
            cout << "open stream write fd " << wfd;
            if (wfd < 0) {
                cout << "open fifo " << stream.fifo << " failed, err " << strerror (errno);
            } else {
                fcntl (wfd, F_SETPIPE_SZ, 1048576);
                pthread_mutex_lock (&mutex);
                stream.stream_protocol = UDP;
                stream.payload_offset = 0;
                stream.wfd = wfd;
                stream.dummy_rfd = dummy_rfd;
                pthread_mutex_unlock (&mutex);
            }
        }
/*
        int wfd = 0;
        if((wfd=open(stream.fifo.c_str(),O_RDWR|O_APPEND|O_CREAT,S_IRUSR | S_IWUSR | S_IROTH))<0)
        {
            printf("open %s failed\n",stream.fifo.c_str());
        } else {
             pthread_mutex_lock (&mutex);
             stream.stream_protocol = UDP;
             stream.payload_offset = 0;
             stream.wfd = wfd;
             stream.dummy_rfd = 0;
             pthread_mutex_unlock (&mutex);
        }
*/
    }
    return (UDP == stream.stream_protocol);
}

bool ParsePkt2::is_rtp (Stream &stream)
{
    cout << "start to detect rtp" << endl;
    payloadBuf::iterator iter = stream.buf.begin ();
    u_char pt_const = 0;
    uint16_t sn_const = 0;
    uint32_t ssrc_const = 0;
    for (; iter != stream.buf.end (); ++iter) {
        cout << "parse packet " << iter - stream.buf.begin ();
        u_char *p = &((*iter)[0]);
        if (iter->size () <= 12) {
            cout << "payload size <= 12, not rtp";
            break;
        } else {
            u_char v = *p >> 6;
            u_char cc = *p & 0x0F;
            unsigned rtp_size = 12 + 4 * cc;
            if (v != 2 || rtp_size >= iter->size ()) {
                cout << "version not 2, or payload size < rtp_size, break";
                break;
            }
            if (stream.buf.begin () == iter) {
                pt_const = *(p+1) & 0x7F;
                sn_const = ntohs (*(uint16_t*)(p+2));
                ssrc_const = ntohl (*(uint32_t*)(p+8));
                continue;
            }
            u_char pt = *(p+1) & 0x7F;
            if (pt < 24) {
                // payload is audio
                cout << "payload type " << (int)pt << ", not video, omit";
                break;
            }
            uint16_t sn = ntohs (*(uint16_t*)(p+2));
            //uint32_t timestamp = ntohl (*(uint32_t*)(p+4));
            uint32_t ssrc = ntohl (*(uint32_t*)(p+8));
            if (pt != pt_const || sn != sn_const + (iter - stream.buf.begin ()) || ssrc != ssrc_const) {
                cout << "rtp value not consisent, break ";
                cout << "should be: " << (int)pt_const << ", " << sn_const + (iter - stream.buf.begin ()) << ", " << ssrc_const;
                cout << "actually: " << (int)pt << ", " << sn << ", " << ssrc;
                break;
            }
            if (stream.buf.end () - 1 == iter) {
                cout << "Detect RTP stream, header size " << rtp_size
                    << "payload type " << (int)pt << endl;

                if ((mkfifo (stream.fifo.c_str (), 0666) < 0) && errno != EEXIST) {
                    cout << "create fifo " << stream.fifo << " failed, errno " << errno;
                } else {
                    int dummy_rfd = open (stream.fifo.c_str (), O_RDONLY | O_NONBLOCK);
                    (void) dummy_rfd;
                    int wfd = open (stream.fifo.c_str (), O_CREAT | O_WRONLY | O_NONBLOCK, S_IRUSR | S_IWUSR | S_IROTH);
                    cout << "open stream write fd " << wfd;
                    if (wfd < 0) {
                        cout << "open fifo " << stream.fifo << " failed, err " << strerror (errno);
                    } else {
                        fcntl (wfd, F_SETPIPE_SZ, 1048576);
                        pthread_mutex_lock (&mutex);
                        stream.stream_protocol = RTP;
                        stream.payload_offset = rtp_size;
                        stream.wfd = wfd;
                        stream.dummy_rfd = dummy_rfd;
                        pthread_mutex_unlock (&mutex);
                    }
                }
/*
                int wfd = 0;
                if((wfd=open(stream.fifo.c_str(),O_RDWR|O_APPEND|O_CREAT,S_IRUSR | S_IWUSR | S_IROTH))<0)
                {
                    printf("open %s failed\n",stream.fifo.c_str());
                } else {
                    pthread_mutex_lock (&mutex);
                    stream.stream_protocol = UDP;
                    stream.payload_offset = 0;
                    stream.wfd = wfd;
                    stream.dummy_rfd = 0;
                    pthread_mutex_unlock (&mutex);
                }
*/
            }
        }
    }
    return (RTP == stream.stream_protocol);
}

void ParsePkt2::detect_protocol (Stream &stream)
{
    if (!is_rtp (stream)) {
        if (!is_udpts (stream)) {
            pthread_mutex_lock (&mutex);
            stream.stream_protocol = UNKNOWN;
            pthread_mutex_unlock (&mutex);
        }
    }

    cout << "protocol detected: " << g_stream_proto_dict[stream.stream_protocol] << endl;
}

void ParsePkt2::print_map ()
{
    cout << "stream map size " << stream_map.size ()
        << ", pkt list size " << pkt_list.size ();
    for (StreamMap::iterator iter = stream_map.begin (); iter != stream_map.end (); ++iter) {
        struct Stream &stream = iter->second;
        cout << "===================" << endl;
        char ip_src[16], ip_dst[16];
        sprintf (ip_src, "%s", inet_ntoa (stream.ip_src));
        sprintf (ip_dst, "%s", inet_ntoa (stream.ip_dst));
        cout << ip_src << ":" << stream.port_src
            << " -> " << ip_dst << ":" << stream.port_dst;
        cout << "stream protocol: " << g_stream_proto_dict[stream.stream_protocol];
        cout << "buf size: " << stream.buf.size ();
        cout << "last pkt time: " << stream.last_pkt_time;
        cout << "last pkt time diff: " << time (NULL) - stream.last_pkt_time;
        cout << "payload offset: " << stream.payload_offset;
        cout << "wfd: " << stream.wfd;
        cout << "fifo: " << stream.fifo;
    }
}

inline string ParsePkt2::gen_key (struct in_addr ip_src, struct in_addr ip_dst, uint16_t port_src, uint16_t port_dst)
{
    char key[28];
    sprintf (key, "%0x.%0x.%0x.%0x", ip_src.s_addr, port_src, ip_dst.s_addr, port_dst);
    return string (key, sizeof (key));
}

void ParsePkt2::add_pkt (u_char *payload, unsigned payload_len, struct in_addr ip_src
        , struct in_addr ip_dst , u_int16_t port_src, uint16_t port_dst)
{
#ifndef NDEBUG
    time_t dbg_start = time (NULL);
#endif
    string key = gen_key (ip_src, ip_dst, port_src, port_dst);
    vector<u_char> v (payload, payload + payload_len);

    bool write_fifo = false;
    unsigned payload_offset = 0;
    int fd = -1;
    pthread_mutex_lock (&mutex);
    StreamMap::iterator siter = stream_map.find (key);
    if (siter != stream_map.end ()) {
        time_t now = time (NULL);
        Stream &s = siter->second;
        if (TODETECT != s.stream_protocol && now - s.last_pkt_time > g_ffmpeg_timeout + 5) {
            // the stream has packet again after a while, enable stream detect again
            if (s.wfd != -1) {
                close (s.dummy_rfd);
                close (s.wfd);
            }
            stream_map.erase (siter);
        } else {
            s.last_pkt_time = time (NULL);
            if (s.buf.size () < DEFAULT_BUF_PKT_CNT) {
                s.buf.push_back (v);
            } else if (s.stream_protocol != UNKNOWN && s.wfd >= 0) {
                write_fifo = true;
                payload_offset = s.payload_offset;
                fd = s.wfd;
            }
        }
    } else {
        cout << "new stream " << port_src << "->" << port_dst;
        Stream s (ip_src, ip_dst, port_src, port_dst);
        s.buf.push_back (v);
        s.fifo = string (SAMPLE_DIR) + "/fifo_" + key;
        cout << "fifo: " << s.fifo << endl;
        stream_map[key] = s;
        pkt_list.push_back (key);
    }
    pthread_mutex_unlock (&mutex);
    if (write_fifo && payload_offset < payload_len) {
        // TODO reorder the rtp packet
        /*uint16_t sn = ntohs (*(uint16_t*)(payload+2));
        uint32_t ts = ntohl (*(uint32_t*)(payload+4));
        printf("sn=%u=%u\n", sn, ts);
        fflush(stdout);*/

        int wlen = write (fd, payload + payload_offset, payload_len - payload_offset);
        cout << "write payload bytes: " << wlen << " / " << payload_len - payload_offset << endl;
        if ((unsigned)wlen != payload_len - payload_offset)
            cout << "actually write len " << wlen << ", err " << strerror (errno) << endl;
    }
#ifndef NDEBUG
    time_t dbg_end = time (NULL);
    cout << "add pkt cost time " << dbg_end - dbg_start;
#endif
}

void ParsePkt2::process_pkt (Stream &stream)
{
    detect_protocol (stream);
    char ip_src_str[16], ip_dst_str[16];
    sprintf (ip_src_str, "%s", inet_ntoa (stream.ip_src));
    sprintf (ip_dst_str, "%s", inet_ntoa (stream.ip_dst));
    char source_url[255], dest_url[255];
    sprintf (source_url, "%s:%d", ip_src_str, stream.port_src);
    sprintf (dest_url, "%s:%d", ip_dst_str, stream.port_dst);
    if (UNKNOWN == stream.stream_protocol) {
        cout << "ignore unknown stream: " << source_url << "->" << dest_url << endl;
        return;
    }
 
//从管道文件中去读取内容生成文件
    char dest_file[1024];
    memset(dest_file,0x00,sizeof(dest_file));

    sprintf(dest_file,"%s.ts",stream.fifo.c_str());
    pid_t pid = fork ();
    if (! pid) {    // child
        setpgrp ();
        cout << "child pid " << getpid () << ", pgid " << getpgrp ();
        char g_info_file[1024];
        memset(g_info_file,0x00,sizeof(g_info_file));
        sprintf(g_info_file,"%s.info",stream.fifo.c_str ());
//        string cmd = "./ffmpeg -y -i \"" + stream.fifo + "\" -f rawvideo -pix_fmt gray "
//            + dest_file + " >" + g_info_file + " 2>&1";

        char cmd[1024];
        memset(cmd,0x00,sizeof(cmd));
        //sprintf(cmd, "./ffmpeg -y -i %s -f rawvideo -pix_fmt gray %s > %s 2>&1",
        sprintf(cmd, "./ffmpeg -y -i %s %s > %s 2>&1",
                     stream.fifo.c_str (), dest_file, g_info_file);
        cout << cmd << endl;
        execl ("/bin/bash", "bash", "-c", cmd, (char*) NULL);

        exit (0);
    }
    ingest_live(dest_file);
    kill (-pid, SIGKILL);  // kill ffmpeg


/*  //入基因库生成dna，这里暂时不需要
    char ffmpeg_log[255];
    if (g_debug) {
        sprintf(ffmpeg_log, "%s/%s:%d_%s:%d.%d.log", LOG_DIR, ip_src_str, stream.port_src
                , ip_dst_str, stream.port_dst, stream.stream_protocol);
    } else {
        sprintf (ffmpeg_log, "/dev/null");
    }
    pid_t pid = fork ();
    if (!pid) {
        char cmd[1024];
        //sprintf (cmd, "./bin/read_fifo %s >%s 2>&1"
        //        , stream.fifo.c_str (), ffmpeg_log);
        //cout << "read fifo from " << source_url << " to " << dest_url;
        sprintf (cmd, "./bin/video_ingest -c etc/vs.conf -t sample -l -f \"%s\" -e %s:%s:%s >%s 2>&1"
                , stream.fifo.c_str (), g_stream_proto_dict[stream.stream_protocol], source_url, dest_url, ffmpeg_log);
        cout << "revoke cmd: " << cmd;
        int ret = system (cmd);
        (void) ret;
        cout << "video ingest process exit, " << source_url << "->" << dest_url;
        exit (0);
    }
*/
}

