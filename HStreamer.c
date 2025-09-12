// Single-thread HTTPS (TLS) file server — prints user/sys split per transfer
// Modes (compile-time): exactly one of
//   -DTLS_MODE_OPENSSL
//   -DTLS_MODE_KTLS_WRITE      (requires OPENSSL_KTLS)
//   -DTLS_MODE_KTLS_SENDFILE   (requires OPENSSL_KTLS)
// Build examples:
//   gcc -O2 -Wall -Wextra -DTLS_MODE_OPENSSL           -o https_server single_thread_https_server.c -lssl -lcrypto
//   gcc -O2 -Wall -Wextra -DTLS_MODE_KTLS_WRITE  -DOPENSSL_KTLS=1 -o https_server single_thread_https_server.c -lssl -lcrypto
//   gcc -O2 -Wall -Wextra -DTLS_MODE_KTLS_SENDFILE -DOPENSSL_KTLS=1 -o https_server single_thread_https_server.c -lssl -lcrypto

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/sysinfo.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef HAVE_TCP_INFO_BYTES
#define HAVE_TCP_INFO_BYTES 0
#endif

#if (defined(TLS_MODE_OPENSSL) + defined(TLS_MODE_KTLS_WRITE) + defined(TLS_MODE_KTLS_SENDFILE)) != 1
# error "Define exactly one of TLS_MODE_OPENSSL, TLS_MODE_KTLS_WRITE, TLS_MODE_KTLS_SENDFILE"
#endif

#ifdef TLS_MODE_OPENSSL
# define MODE_NAME "OpenSSL(SSL_write)"
#endif
#ifdef TLS_MODE_KTLS_WRITE
# define MODE_NAME "kTLS(write)"
#endif
#ifdef TLS_MODE_KTLS_SENDFILE
# define MODE_NAME "kTLS(sendfile)"
#endif

#define REQ_BUFSZ 8192
#define CHUNK_SZ  (512 * 1024)
#ifndef ONE_SHOT
#define ONE_SHOT 1
#endif

static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;

static void on_sigint(int sig){(void)sig; g_stop = 1; if (g_listen_fd >= 0) close(g_listen_fd);} 
static void die_perror(const char *m){perror(m); exit(EXIT_FAILURE);} 
static void die_ssl(const char *w){fprintf(stderr,"[SSL] %s failed\n",w); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);} 

static void now_hms(char *b,size_t l){struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); struct tm tm; localtime_r(&ts.tv_sec,&tm);
    snprintf(b,l,"%02d:%02d:%02d.%03ld",tm.tm_hour,tm.tm_min,tm.tm_sec,ts.tv_nsec/1000000);} 

static int get_current_cpu(void){int c=sched_getcpu(); return (c<0)?-1:c;} 
static void log_affinity_startup(void){
    cpu_set_t set; CPU_ZERO(&set);
    if (sched_getaffinity(0,sizeof(set),&set)==0){
        char buf[512]; buf[0]='\0'; size_t left=sizeof(buf); char *p=buf; int first=1;
        for(int i=0;i<CPU_SETSIZE;++i) if(CPU_ISSET(i,&set)){int n=snprintf(p,left,first?"%d":",%d",i); if(n<=0||(size_t)n>=left)break; p+=n; left-=(size_t)n; first=0;}
        fprintf(stderr,"[CPU] affinity={%s} | online=%d conf=%d | running_on=%d\n",
            buf[0]?buf:"?", get_nprocs(), get_nprocs_conf(), get_current_cpu());
    } else fprintf(stderr,"[CPU] sched_getaffinity() failed\n");
}

static int make_listen_sock(uint16_t port){
    int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0)die_perror("socket");
    int one=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(port);
    if(bind(fd,(struct sockaddr*)&a,sizeof(a))<0)die_perror("bind");
    if(listen(fd,16)<0)die_perror("listen");
    return fd;
}

static ssize_t ssl_write_all(SSL *ssl,const void *buf,size_t len){
    const uint8_t *p=(const uint8_t*)buf; size_t left=len;
    while(left>0){ if(g_stop) return -1;
        int n=SSL_write(ssl,p,(int)left);
        if(n>0){p+=n; left-=(size_t)n; continue;}
        int e=SSL_get_error(ssl,n);
        if(e==SSL_ERROR_WANT_WRITE||e==SSL_ERROR_WANT_READ){usleep(1000); continue;}
        return -1;
    }
    return (ssize_t)len;
}

static ssize_t tls_write_all(SSL *ssl,const void *buf,size_t len){
#if defined(TLS_MODE_OPENSSL)
    return ssl_write_all(ssl,buf,len);
#else
#ifdef OPENSSL_KTLS
    BIO *wbio=SSL_get_wbio(ssl);
    int ktls=(wbio && BIO_get_ktls_send(wbio));
#else
    int ktls=0;
#endif
    if(ktls){
        int fd=SSL_get_fd(ssl);
        const uint8_t *p=(const uint8_t*)buf; size_t left=len;
        while(left>0){ if(g_stop) return -1;
            ssize_t n=send(fd,p,left,MSG_NOSIGNAL);
            if(n>0){p+=n; left-=(size_t)n; continue;}
            if(n<0){ if(errno==EINTR) continue; if(errno==EAGAIN||errno==EWOULDBLOCK){usleep(1000); continue;} return -1; }
        }
        return (ssize_t)len;
    }else{
# ifdef KTLS_STRICT
        fprintf(stderr,"[ERR] kTLS not active (KTLS_STRICT)\n"); return -1;
# else
        return ssl_write_all(ssl,buf,len);
# endif
    }
#endif
}

static int send_http_404(SSL *ssl){
    const char *body="<html><body><h1>404 Not Found</h1></body></html>\n";
    char hdr[256];
    int hdrlen=snprintf(hdr,sizeof(hdr),
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        strlen(body));
    if(tls_write_all(ssl,hdr,(size_t)hdrlen)<0) return -1;
    if(tls_write_all(ssl,body,strlen(body))<0) return -1;
    return 0;
}

static size_t url_decode(char *s){
    char *src=s,*dst=s;
    while(*src){
        if(src[0]=='%'&&isxdigit((unsigned char)src[1])&&isxdigit((unsigned char)src[2])){
            char h[3]={src[1],src[2],0}; *dst++=(char)strtol(h,NULL,16); src+=3;
        }else if(src[0]=='+'){*dst++=' '; src++;}
        else *dst++=*src++;
    }
    *dst='\0'; return (size_t)(dst-s);
}

static int safe_join_under_base(const char *base,const char *name,char out[PATH_MAX]){
    char base_real[PATH_MAX]; if(!realpath(base,base_real)) return -1;
    char cand[PATH_MAX]; if(snprintf(cand,sizeof(cand),"%s/%s",base,name)>=(int)sizeof(cand)) return -1;
    char *cand_real=realpath(cand,NULL); if(!cand_real) return -1;
    size_t blen=strlen(base_real);
    int ok=(strncmp(base_real,cand_real,blen)==0)&&(cand_real[blen]=='/'||cand_real[blen]=='\0');
    if(ok){strncpy(out,cand_real,PATH_MAX-1); out[PATH_MAX-1]='\0';}
    free(cand_real); return ok?0:-1;
}

struct perf_ctx{
    struct rusage ru0,ru1;        // user/sys split
#if defined(__linux__) && HAVE_TCP_INFO_BYTES
    struct tcp_info ti0,ti1; int have_tcpinfo; int sfd;
#endif
    struct timespec t0,t1,tb,te;  // total/body windows
    int cpu_start,cpu_end;
};

static void perf_begin(struct perf_ctx *pc, SSL *ssl){
    memset(pc,0,sizeof(*pc));
    getrusage(RUSAGE_SELF,&pc->ru0);
    clock_gettime(CLOCK_MONOTONIC,&pc->t0);
    clock_gettime(CLOCK_MONOTONIC,&pc->tb);
#if defined(__linux__) && HAVE_TCP_INFO_BYTES
    pc->sfd=SSL_get_fd(ssl); socklen_t tilen=sizeof(struct tcp_info);
    memset(&pc->ti0,0,sizeof(pc->ti0));
    pc->have_tcpinfo=(getsockopt(pc->sfd,IPPROTO_TCP,TCP_INFO,&pc->ti0,&tilen)==0);
#else
    (void)ssl; // TCP_INFO 안쓰는 빌드에서 경고 제거
#endif
    pc->cpu_start=get_current_cpu();
}

static void perf_end_and_log(struct perf_ctx *pc,const char *filepath,off_t sent_total,const char *mode_name){
    getrusage(RUSAGE_SELF,&pc->ru1);
    clock_gettime(CLOCK_MONOTONIC,&pc->t1);
    clock_gettime(CLOCK_MONOTONIC,&pc->te);

    double dt=(pc->t1.tv_sec-pc->t0.tv_sec)+(pc->t1.tv_nsec-pc->t0.tv_nsec)/1e9;
    double user_s=(pc->ru1.ru_utime.tv_sec-pc->ru0.ru_utime.tv_sec)+
                   (pc->ru1.ru_utime.tv_usec-pc->ru0.ru_utime.tv_usec)/1e6;
    double sys_s =(pc->ru1.ru_stime.tv_sec-pc->ru0.ru_stime.tv_sec)+
                   (pc->ru1.ru_stime.tv_usec-pc->ru0.ru_stime.tv_usec)/1e6;
    double thr_mb_s=(sent_total/(1024.0*1024.0))/(dt>0?dt:1);
    double cpu_user_pct=(dt>0)?(user_s/dt*100.0):0.0;
    double cpu_sys_pct =(dt>0)?(sys_s /dt*100.0):0.0;
    double cpu_sum_pct = cpu_user_pct + cpu_sys_pct;

    pc->cpu_end=get_current_cpu();

    char ts[32]; now_hms(ts,sizeof(ts));
    fprintf(stderr,
        "\n========== XFER RESULT (%s) ==========\n"
        "mode            : %s\n"
        "file            : %s\n"
        "size            : %jd bytes\n"
        "time(App->Ker)  : %.3f s\n"
        "throughput      : %.2f MB/s\n"
        "cpu_user        : %.1f %%\n"
        "cpu_sys         : %.1f %%\n"
        "cpu (user+sys)  : %.1f %%\n"
        "proc_user_s     : %.3f s\n"
        "proc_sys_s      : %.3f s\n"
        "cpu (start->end): %d -> %d\n"
        "body window     : start=%.6f end=%.6f (wall)\n",
        ts, mode_name, filepath, (intmax_t)sent_total, dt, thr_mb_s,
        cpu_user_pct, cpu_sys_pct, cpu_sum_pct,
        user_s, sys_s,
        pc->cpu_start, pc->cpu_end,
        pc->tb.tv_sec + pc->tb.tv_nsec/1e9, pc->te.tv_sec + pc->te.tv_nsec/1e9
    );

#if defined(__linux__) && HAVE_TCP_INFO_BYTES
    if(pc->have_tcpinfo){
        socklen_t tilen2=sizeof(struct tcp_info);
        memset(&pc->ti1,0,sizeof(pc->ti1));
        if(getsockopt(pc->sfd,IPPROTO_TCP,TCP_INFO,&pc->ti1,&tilen2)==0){
# if HAVE_TCP_INFO_BYTES
            double acked=(double)pc->ti1.tcpi_bytes_acked-(double)pc->ti0.tcpi_bytes_acked;
            double thr_ack=(acked/(1024.0*1024.0))/(dt>0?dt:1);
            fprintf(stderr,"net (ACK-base)  : acked=%.0f bytes, thr_ack=%.2f MB/s\n",acked,thr_ack);
# else
            fprintf(stderr,"net (ACK-base)  : tcpi_bytes_* unavailable\n");
# endif
        }
    } else fprintf(stderr,"net (ACK-base)  : N/A (rebuild with -DHAVE_TCP_INFO_BYTES=1)\n");
#else
    fprintf(stderr,"net (ACK-base)  : N/A (rebuild with -HAVE_TCP_INFO_BYTES=1)\n");
#endif
    fprintf(stderr,"======================================\n\n");
}


static int send_file_over_ssl(SSL *ssl,const char *filepath,const char *disp_name){
    struct perf_ctx pc; perf_begin(&pc,ssl);
    int fd=open(filepath,O_RDONLY|O_CLOEXEC); if(fd<0){perror("open(file)"); return send_http_404(ssl);} 
    posix_fadvise(fd,0,0,POSIX_FADV_SEQUENTIAL);
    posix_fadvise(fd,0,0,POSIX_FADV_NOREUSE);
    struct stat st; if(fstat(fd,&st)<0){perror("fstat"); close(fd); return send_http_404(ssl);} 
    if(!S_ISREG(st.st_mode)){close(fd); return send_http_404(ssl);} 
    off_t fsize=st.st_size;

    char hdr[512];
    int hdrlen=snprintf(hdr,sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %jd\r\nContent-Disposition: attachment; filename=\"%s\"\r\nConnection: close\r\n\r\n",
        (intmax_t)fsize,disp_name);
    if(tls_write_all(ssl,hdr,(size_t)hdrlen)<0){close(fd); return -1;}

    off_t sent_total=0;

#if defined(TLS_MODE_KTLS_SENDFILE)
#ifdef OPENSSL_KTLS
    BIO *wbio=SSL_get_wbio(ssl);
    int ktls_sf=(wbio && BIO_get_ktls_send(wbio));
#else
    int ktls_sf=0;
#endif
    if(ktls_sf){
        int sfd=SSL_get_fd(ssl);
        int cork=1; setsockopt(sfd,IPPROTO_TCP,TCP_CORK,&cork,sizeof(cork));
        off_t off=0;
        while(off<fsize){
            if(g_stop){cork=0; setsockopt(sfd,IPPROTO_TCP,TCP_CORK,&cork,sizeof(cork)); close(fd); return -1;}
            ssize_t sn=sendfile(sfd,fd,&off,(size_t)(fsize-off));
            if(sn<0){ if(errno==EINTR) continue; perror("sendfile"); break; }
            if(sn==0) break;
        }
        cork=0; setsockopt(sfd,IPPROTO_TCP,TCP_CORK,&cork,sizeof(cork));
        sent_total=off;
        if(off==fsize){ close(fd); perf_end_and_log(&pc,filepath,sent_total,MODE_NAME); return 0; }
        lseek(fd,off,SEEK_SET);
    }
#endif

    long pg=sysconf(_SC_PAGESIZE);
    size_t bufsz=(size_t)CHUNK_SZ; if(bufsz%(size_t)pg) bufsz+=(size_t)pg-(bufsz%(size_t)pg);
    void *buf=NULL; if(posix_memalign(&buf,(size_t)pg,bufsz)!=0) buf=malloc(bufsz);
    if(!buf){close(fd); return -1;}

    int sfd=SSL_get_fd(ssl);
    int sndbuf=1<<20; setsockopt(sfd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
    int cork=1; setsockopt(sfd,IPPROTO_TCP,TCP_CORK,&cork,sizeof(cork));

    ssize_t r=0;
    while(!g_stop){
        do{ r=read(fd,buf,bufsz);}while(r<0 && errno==EINTR);
        if(r<0){perror("read(file)"); break;}
        if(r==0) break;
        if(tls_write_all(ssl,buf,(size_t)r)<0){ r=-1; break; }
        sent_total+=r;
    }

    cork=0; setsockopt(sfd,IPPROTO_TCP,TCP_CORK,&cork,sizeof(cork));
    free(buf); close(fd);
    perf_end_and_log(&pc,filepath,sent_total,MODE_NAME);
    return (r<0||g_stop)?-1:0;
}

static int handle_client(SSL *ssl,const char *base_dir){
    char req[REQ_BUFSZ];
    int n=SSL_read(ssl,req,sizeof(req)-1); if(n<=0) return -1; req[n]='\0';

    int sfd=SSL_get_fd(ssl);
    struct sockaddr_in peer; socklen_t plen=sizeof(peer);
    char ip[INET_ADDRSTRLEN]="0.0.0.0"; int port=0;
    if(getpeername(sfd,(struct sockaddr*)&peer,&plen)==0){ inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip)); port=ntohs(peer.sin_port); }

    char method[8]={0},path[1024]={0},proto[16]={0};
    if(sscanf(req,"%7s %1023s %15s",method,path,proto)<2) return -1;
    if(strcmp(method,"GET")!=0) return send_http_404(ssl);

    if(strcmp(path,"/")==0){
        const char *body="<html><body><h1>OK</h1><p>GET /filename</p></body></html>\n";
        char hdr[256]; int hdrlen=snprintf(hdr,sizeof(hdr),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",strlen(body));
        tls_write_all(ssl,hdr,(size_t)hdrlen); tls_write_all(ssl,body,strlen(body));
        fprintf(stderr,"[REQ] %s:%d GET / -> 200 (info)\n",ip,port); return 0;
    }

    struct timespec t_req_start,t_req_end; clock_gettime(CLOCK_MONOTONIC,&t_req_start);

    char filename[NAME_MAX];
    const char *p=(path[0]=='/')?(path+1):path;
    strncpy(filename,p,sizeof(filename)-1); filename[sizeof(filename)-1]='\0';
    char *q=strchr(filename,'?'); if(q)*q='\0'; url_decode(filename);

    if(strchr(filename,'\\')||strstr(filename,"../")||strcmp(filename,"..")==0){
        fprintf(stderr,"[REQ] %s:%d %s -> 400 (bad path)\n",ip,port,path);
        return send_http_404(ssl);
    }

    char fullpath[PATH_MAX];
    if(safe_join_under_base(base_dir,filename,fullpath)<0){
        fprintf(stderr,"[REQ] %s:%d %s -> 404 (outside base)\n",ip,port,path);
        return send_http_404(ssl);
    }

    char ts[32]; now_hms(ts,sizeof(ts));
    fprintf(stderr,
        "----- REQUEST (%s) ---------------------------------\n"
        "client          : %s:%d\n"
        "method/path     : %s %s\n"
        "resolved file   : %s\n"
        "mode            : %s\n"
        "running_on_cpu  : %d\n"
        "----------------------------------------------------\n",
        ts,ip,port,method,path,fullpath,MODE_NAME,get_current_cpu());

    int rc=send_file_over_ssl(ssl,fullpath,filename);

    clock_gettime(CLOCK_MONOTONIC,&t_req_end);
    double req_dt=(t_req_end.tv_sec-t_req_start.tv_sec)+(t_req_end.tv_nsec-t_req_start.tv_nsec)/1e9;
    fprintf(stderr," [APP] REQ_WINDOW: %.3f s (req->body->done)\n\n",req_dt);
    return rc;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <port> <cert.pem> <key.pem> <base-dir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint16_t port     = (uint16_t)atoi(argv[1]);
    const char *cert_path = argv[2];
    const char *key_path  = argv[3];
    const char *base_dir  = argv[4];

    struct sigaction sa = {0};
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) die_ssl("SSL_CTX_new");

#ifdef TLS_MODE_OPENSSL
# ifdef SSL_OP_ENABLE_KTLS
    SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_KTLS);
# endif
#elif defined(TLS_MODE_KTLS_WRITE) || defined(TLS_MODE_KTLS_SENDFILE)
# ifdef SSL_OP_ENABLE_KTLS
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
# endif
#endif

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) die_ssl("set_min_proto TLS1.3");
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) die_ssl("set_max_proto TLS1.3");

    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1)
        die_ssl("SSL_CTX_set_ciphersuites TLS_AES_256_GCM_SHA384");

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0)
        die_ssl("SSL_CTX_use_certificate_file");
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
        die_ssl("SSL_CTX_use_PrivateKey_file");
    if (!SSL_CTX_check_private_key(ctx))
        die_ssl("SSL_CTX_check_private_key");

    int lfd = make_listen_sock(port);
    g_listen_fd = lfd;

    char ts[32]; now_hms(ts, sizeof(ts));
    printf("[INFO] %s | 모드=%s, https://0.0.0.0:%u 대기 (Ctrl-C 종료)\n",
           ts, MODE_NAME, port);
    if (ONE_SHOT)
        printf("[INFO] ONE_SHOT=%d | 첫 요청 처리 후 종료\n", ONE_SHOT);
    log_affinity_startup();

    int served = 0;
    while (!g_stop) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) { if (g_stop) break; else continue; }
            if (errno == EBADF && g_stop) break;
            perror("accept"); break;
        }

        struct timespec t_conn_start, t_conn_end;
        clock_gettime(CLOCK_MONOTONIC, &t_conn_start);

        SSL *ssl = SSL_new(ctx);
        if (!ssl) { perror("SSL_new"); close(cfd); continue; }
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); close(cfd); continue;
        }

        {
            const SSL_CIPHER *sc = SSL_get_current_cipher(ssl);
            const char *ver   = SSL_get_version(ssl);
            const char *cname = sc ? SSL_CIPHER_get_name(sc) : "?";
#ifdef OPENSSL_KTLS
            BIO *wbio = SSL_get_wbio(ssl);
            int ktls_on = (wbio && BIO_get_ktls_send(wbio));
#else
            int ktls_on = 0;
#endif
            fprintf(stderr, "[KTLS] ver=%s cipher=%s ktls_send=%d\n", ver, cname, ktls_on);
        }

        (void)handle_client(ssl, base_dir);

        SSL_shutdown(ssl);
        clock_gettime(CLOCK_MONOTONIC, &t_conn_end);
        double conn_dt = (t_conn_end.tv_sec - t_conn_start.tv_sec) +
                         (t_conn_end.tv_nsec - t_conn_start.tv_nsec) / 1e9;
        fprintf(stderr, " [APP] CONN_WINDOW: %.3f s (accept->shutdown)\n\n", conn_dt);

        SSL_free(ssl);
        close(cfd);

        served++;
        if (ONE_SHOT && served >= 1) {
            char tss[32]; now_hms(tss, sizeof(tss));
            fprintf(stderr, "[INFO] %s | ONE_SHOT: %d건 처리 완료 → 종료\n", tss, served);
            break;
        }
    }

    close(lfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
