// multi_thread_server.c
#define _GNU_SOURCE
/**
 * Multithreaded, non-blocking HTTPS file server (HTTP/1.1 close)
 *
 * 설계 개요
 *  - 단일 acceptor 스레드가 신규 연결을 받고 라운드로빈으로 워커 큐에 전달
 *  - 각 워커는 EPOLLET 기반 상태머신(핸드셰이크→요청읽기→헤더→파일→종료)
 *  - 전송 모드는 컴파일 타임에 하나만 선택
 *      TLS_MODE_OPENSSL / TLS_MODE_KTLS_WRITE / TLS_MODE_KTLS_SENDFILE
 *
 * 빌드:
 *  gcc -O2 -pthread -Wall -Wextra -DTLS_MODE_OPENSSL -o multi_thread_server multi_thread_server.c -lssl -lcrypto
 *  gcc -O2 -pthread -Wall -Wextra -DTLS_MODE_KTLS_WRITE -DOPENSSL_KTLS=1 -o multi_thread_server multi_thread_server.c -lssl -lcrypto
 *  gcc -O2 -pthread -Wall -Wextra -DTLS_MODE_KTLS_SENDFILE -DOPENSSL_KTLS=1 -o multi_thread_server multi_thread_server.c -lssl -lcrypto
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

/** 단 하나의 모드만 허용 **/
#if (defined(TLS_MODE_OPENSSL) + defined(TLS_MODE_KTLS_WRITE) + defined(TLS_MODE_KTLS_SENDFILE)) != 1
#  error "Define exactly one TLS_MODE_*"
#endif

#ifdef TLS_MODE_OPENSSL
#  define MODE_NAME "OpenSSL(SSL_write)"
#endif
#ifdef TLS_MODE_KTLS_WRITE
#  define MODE_NAME "kTLS(write)"
#endif
#ifdef TLS_MODE_KTLS_SENDFILE
#  define MODE_NAME "kTLS(sendfile)"
#endif

/** 상수/전역 **/
#define MAX_WORKERS   128
#define MAX_EVENTS    256
#define REQ_BUFSZ     8192
#define IO_BUFSZ      (512*1024)

static volatile sig_atomic_t g_stop = 0;

/** 시그널 **/
static void on_sigint(int sig){ (void)sig; g_stop = 1; }

/** 논블로킹 */
static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/** die */
static void die(const char* m){ perror(m); exit(1); }
static void die_ssl(const char* m){ fprintf(stderr, "[SSL] %s\n", m); ERR_print_errors_fp(stderr); exit(1);}

/** URL 디코드 */
static size_t url_decode(char *s){
    char *src=s, *dst=s;
    while(*src){
        if (src[0]=='%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])){
            char h[3] = {src[1], src[2], 0};
            *dst++ = (char)strtol(h, NULL, 16); src+=3;
        }else if(src[0]=='+'){ *dst++=' '; src++; }
        else { *dst++=*src++; }
    }
    *dst='\0';
    return (size_t)(dst-s);
}

/** 안전한 경로 결합 */
static int safe_join_under_base(const char *base, const char *name, char out[PATH_MAX]){
    char realb[PATH_MAX];
    if (!realpath(base, realb)) return -1;
    char cand[PATH_MAX];
    if (snprintf(cand, sizeof(cand), "%s/%s", base, name) >= (int)sizeof(cand)) return -1;
    char *realc = realpath(cand, NULL);
    if (!realc) return -1;
    size_t bl = strlen(realb);
    int ok = (strncmp(realb, realc, bl)==0) && (realc[bl]=='/' || realc[bl]=='\0');
    if (ok){ strncpy(out, realc, PATH_MAX-1); out[PATH_MAX-1]='\0'; }
    free(realc);
    return ok?0:-1;
}

/** 상태 */
typedef enum { S_HANDSHAKE=0, S_READ_REQ, S_SEND_HDR, S_SEND_FILE, S_CLOSING } conn_state_t;

/** 연결 컨텍스트 */
typedef struct conn {
    int              fd;
    SSL             *ssl;
    conn_state_t     st;
    bool             ktls_on;
    /* 요청 버퍼 */
    char             req[REQ_BUFSZ];
    size_t           rq_len;
    /* 응답 헤더 버퍼 */
    char             hdr[512];
    size_t           hdr_len;
    size_t           hdr_off;
    /* 파일 송신 */
    int              ffd;
    off_t            fsize;
    off_t            foff;
    char             disp[NAME_MAX];
    /* OpenSSL 경로용 송신 버퍼 */
    unsigned char   *buf;
    size_t           bufsz;
} conn_t;

/** 워커 컨텍스트 */
typedef struct {
    pthread_t  th;
    int        ep;
    int        qcap;
    int       *q;
    int        qh, qt;
    pthread_mutex_t qmtx;
    pthread_cond_t  qcv;
    SSL_CTX   *ctx;
    const char* base_dir;
    int        id;
    int        cpu;
} worker_t;

/** 연결 정리 */
static void conn_free(conn_t *c){
    if (!c) return;
    if (c->ffd >= 0) close(c->ffd);
    if (c->ssl){ SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->fd>=0) close(c->fd);
    free(c->buf);
    free(c);
}

/** CPU 핀ning(테스트 실패시 경고만) */
static void pin_self_to_cpu(int cpu){
    cpu_set_t set; CPU_ZERO(&set);
    if (cpu >= 0 && cpu < CPU_SETSIZE){
        CPU_SET(cpu, &set);
        int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
        if (rc != 0){
            fprintf(stderr, "[WARN] pthread_setaffinity_np(cpu=%d) failed: %s\n", cpu, strerror(errno));
        }
    }
}

/** 허용된 CPU 마스크에서 n번째 세트 비트 */
static int pick_nth_allowed_cpu(int n){
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0){
        long c = sysconf(_SC_NPROCESSORS_ONLN);
        if (c <= 0) return 0;
        return n % (int)c;
    }
    int list[CPU_SETSIZE], cnt = 0;
    for (int i=0; i<CPU_SETSIZE; ++i) if (CPU_ISSET(i, &allowed)) list[cnt++] = i;
    if (cnt == 0) return 0;
    return list[n % cnt];
}

/** 비동기 재시도 시 epoll 관심 이벤트 */
static void want_events_from_ssl(conn_t *c, uint32_t *events){
    *events = EPOLLET;
    if (c->st == S_HANDSHAKE) { *events |= (EPOLLIN | EPOLLOUT); return; }
    if (c->st == S_READ_REQ)  *events |= EPOLLIN; else *events |= EPOLLOUT;
}

/** kTLS 활성 여부 체크 */
static int ssl_is_ktls_on(SSL *ssl){
#ifdef OPENSSL_KTLS
    BIO *wbio = SSL_get_wbio(ssl);
    return (wbio && BIO_get_ktls_send(wbio));
#else
    (void)ssl; return 0;
#endif
}

/** epoll add/mod (EPOLLET 고정) */
static int add_fd_et(int ep, int fd, uint32_t ev, void *ptr){
    struct epoll_event e = { .events = ev | EPOLLET, .data.ptr = ptr };
    return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
}
static int mod_fd_et(int ep, int fd, uint32_t ev, void *ptr){
    struct epoll_event e = { .events = ev | EPOLLET, .data.ptr = ptr };
    return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e);
}

/** 비동기 TLS 송신 */
static int send_nonblock_tls(conn_t *c, const void *buf, size_t len){
#if defined(TLS_MODE_OPENSSL)
    int n = SSL_write(c->ssl, buf, (int)len);
    if (n > 0) return n;
    int e = SSL_get_error(c->ssl, n);
    if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) return 0;
    return -1;
#else
# ifdef OPENSSL_KTLS
    if (c->ktls_on){
        ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
        if (n > 0) return (int)n;
        if (n < 0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return 0;
        return -1;
    }
# endif
    int n = SSL_write(c->ssl, buf, (int)len);
    if (n > 0) return n;
    int e = SSL_get_error(c->ssl, n);
    if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) return 0;
    return -1;
#endif
}

/** 응답 헤더 플러시 */
static int flush_hdr(conn_t *c){
    while (c->hdr_off < c->hdr_len){
        int n = send_nonblock_tls(c, c->hdr + c->hdr_off, c->hdr_len - c->hdr_off);
        if (n > 0) c->hdr_off += (size_t)n;
        else if (n == 0) return 0;
        else return -1;
    }
    return 1;
}

/** ex_data 인덱스: base_dir 전달 */
static int g_ssl_ex_base_dir_idx = -1;

/** 파일 오픈 + 헤더 준비 + TCP_CORK=1 */
static int build_and_open_file(conn_t *c){
    const char *base_dir = SSL_get_ex_data(c->ssl, g_ssl_ex_base_dir_idx);
    char full[PATH_MAX];
    if (safe_join_under_base(base_dir, c->disp, full) < 0) return -1;
    c->ffd = open(full, O_RDONLY | O_CLOEXEC);
    if (c->ffd < 0) return -1;
    struct stat st; if (fstat(c->ffd, &st) < 0 || !S_ISREG(st.st_mode)) return -1;
    c->fsize = st.st_size; c->foff = 0;
    int cork = 1; setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
    c->hdr_len = (size_t)snprintf(c->hdr, sizeof(c->hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %jd\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Connection: close\r\n\r\n",
        (intmax_t)c->fsize, c->disp);
    c->hdr_off = 0;
    return 0;
}

/** 파일 본문 전송(모드별) */
static int send_file_chunk(conn_t *c){
#if defined(TLS_MODE_KTLS_SENDFILE)
# ifdef OPENSSL_KTLS
    if (c->ktls_on){
        while (c->foff < c->fsize){
            ssize_t n = sendfile(c->fd, c->ffd, &c->foff, (size_t)(c->fsize - c->foff));
            if (n > 0) continue;
            if (n == 0) break;
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return 0;
            return -1;
        }
        return 1;
    }
# endif
#endif
    if (!c->buf){
        long pg = sysconf(_SC_PAGESIZE);
        size_t need = IO_BUFSZ; if (need % (size_t)pg) need += (size_t)pg - (need % (size_t)pg);
        if (posix_memalign((void**)&c->buf, (size_t)pg, need)!=0) c->buf = malloc(need);
        c->bufsz = need;
    }
    for(;;){
        ssize_t r = read(c->ffd, c->buf, c->bufsz);
        if (r > 0){
            size_t off=0;
            while(off < (size_t)r){
                int n = send_nonblock_tls(c, c->buf + off, (size_t)r - off);
                if (n > 0) off += (size_t)n;
                else if (n == 0) {
                    /* would block: 파일 오프셋 되돌리기 */
                    lseek(c->ffd, (off - (size_t)r), SEEK_CUR);
                    return 0;
                } else return -1;
            }
            c->foff += r;
        } else if (r == 0) {
            return 1;
        } else {
            if (errno==EINTR) continue;
            if (errno==EAGAIN || errno==EWOULDBLOCK) return 0;
            return -1;
        }
        /* 공정성: 웨이크마다 한 덩어리 */
        //break;
    }
    return 0;
}

/** 404 */
static void send_404(conn_t *c){
    const char *body = "<html><body><h1>404 Not Found</h1></body></html>\n";
    char hdr[256];
    int  len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", strlen(body));
    (void)send_nonblock_tls(c, hdr, (size_t)len);
    (void)send_nonblock_tls(c, body, strlen(body));
}

/** 이벤트 핸들러: 상태머신 전진 + would-block 재무장 */
static void handle_conn_event(worker_t *w, conn_t *c, uint32_t ev){
    if (ev & (EPOLLHUP | EPOLLERR)) { c->st = S_CLOSING; }

    for(;;){
        if (c->st == S_HANDSHAKE){
            int r = SSL_accept(c->ssl);
            if (r == 1){
                c->ktls_on = ssl_is_ktls_on(c->ssl);
                /* 핸드셰이크 완료: kTLS 여부 로그 */
                fprintf(stdout, "KTLS=%d fd=%d\n", c->ktls_on?1:0, c->fd); fflush(stdout);
                c->st = S_READ_REQ;
            } else {
                int e = SSL_get_error(c->ssl, r);
                if (e==SSL_ERROR_WANT_READ || e==SSL_ERROR_WANT_WRITE) {
                    uint32_t ne; want_events_from_ssl(c, &ne); mod_fd_et(w->ep, c->fd, ne, c); return;
                }
                fprintf(stdout, "ERROR handshake fd=%d\n", c->fd); fflush(stdout);
                c->st = S_CLOSING;
            }
        }

        if (c->st == S_READ_REQ){
            for(;;){
                ssize_t n = SSL_read(c->ssl, c->req + c->rq_len, sizeof(c->req) - 1 - c->rq_len);
                if (n > 0){ c->rq_len += (size_t)n; c->req[c->rq_len] = '\0'; }
                else {
                    int e = SSL_get_error(c->ssl, (int)n);
                    if (e==SSL_ERROR_WANT_READ){ mod_fd_et(w->ep, c->fd, EPOLLIN, c); return; }
                    if (e==SSL_ERROR_WANT_WRITE){ mod_fd_et(w->ep, c->fd, EPOLLOUT, c); return; }
                    if (n==0) { c->st = S_CLOSING; break; }
                    fprintf(stdout, "ERROR read fd=%d\n", c->fd); fflush(stdout);
                    c->st = S_CLOSING; break;
                }
                /* 간단 파싱 */
                char method[8]={0}, path[1024]={0}, proto[16]={0};
                if (sscanf(c->req, "%7s %1023s %15s", method, path, proto) >= 2){
                    if (strcmp(method, "GET")!=0){ send_404(c); c->st = S_CLOSING; break; }
                    const char *p = (path[0]=='/') ? path+1 : path;
                    strncpy(c->disp, p, sizeof(c->disp)-1); c->disp[sizeof(c->disp)-1]='\0';
                    char *q = strchr(c->disp, '?'); if (q) *q='\0';
                    url_decode(c->disp);
                    if (strstr(c->disp, "../") || strchr(c->disp,'\\')){ send_404(c); c->st = S_CLOSING; break; }
                    if (build_and_open_file(c) < 0){ send_404(c); c->st = S_CLOSING; break; }
                    /* 어떤 파일을 보낼지 로그 */
                    fprintf(stdout, "REQUEST fd=%d path=\"%s\" size=%jd\n", c->fd, c->disp, (intmax_t)c->fsize); fflush(stdout);
                    c->st = S_SEND_HDR; break;
                }
                if (c->rq_len == sizeof(c->req)-1){ send_404(c); c->st = S_CLOSING; break; }
            }
        }

        if (c->st == S_SEND_HDR){
            int r = flush_hdr(c);
            if (r < 0){ fprintf(stdout, "ERROR hdr fd=%d\n", c->fd); fflush(stdout); c->st = S_CLOSING; }
            else if (r == 0){ mod_fd_et(w->ep, c->fd, EPOLLOUT, c); return; }
            else { c->st = S_SEND_FILE; }
        }

        if (c->st == S_SEND_FILE){
            int r = send_file_chunk(c);
            if (r < 0){ fprintf(stdout, "ERROR body fd=%d\n", c->fd); fflush(stdout); c->st = S_CLOSING; }
            else if (r == 0){ mod_fd_et(w->ep, c->fd, EPOLLOUT, c); return; }
            else {
                int cork=0; setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                /* 전송 완료 시점: 정확한 바이트 = 파일 크기 */
                fprintf(stdout, "COMPLETE fd=%d path=\"%s\" bytes=%jd\n", c->fd, c->disp, (intmax_t)c->fsize);
                fflush(stdout);
                c->st = S_CLOSING;
            }
        }

        if (c->st == S_CLOSING){
            conn_free(c); return;
        }
    }
}

/** 워커 스레드 */
static void* worker_main(void *arg){
    worker_t *w = (worker_t*)arg;

    pin_self_to_cpu(w->cpu);
    fprintf(stderr, "[INFO] worker#%d pinned to CPU %d\n", w->id, w->cpu);

    struct epoll_event evs[MAX_EVENTS];

    while(!g_stop){
        /* 1) acceptor → worker 큐 수신 */
        pthread_mutex_lock(&w->qmtx);
        while (w->qh != w->qt){
            int cfd = w->q[w->qh]; w->qh = (w->qh + 1) % w->qcap;
            pthread_mutex_unlock(&w->qmtx);

            set_nonblock(cfd);

            /* [SOCKET TUNING — 큰 덩어리 배출 강제] */
            int cork = 1;
            (void)setsockopt(cfd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

            int sndbuf = 4 * 1024 * 1024;   // 1~4MB 권장, 우선 4MB로 시작
            (void)setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

            #ifdef TCP_NOTSENT_LOWAT
                int lowat = 512 * 1024;         // 512KB~1MB 권장
                (void)setsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat));
            #endif
            /* [END SOCKET TUNING] */

            
            /* [VERIFY — 실제 적용된 값 로깅] */
            int v; socklen_t l = sizeof(v);
            if (getsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &v, &l) == 0)
                    fprintf(stdout, "SNDBUF=%d\n", v);
            #ifdef TCP_NOTSENT_LOWAT
                if (getsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &v, &l) == 0)
                    fprintf(stdout, "NOTSENT_LOWAT=%d\n", v);
            #endif
                fflush(stdout);

            conn_t *c = (conn_t*)calloc(1, sizeof(*c));
            c->fd = cfd; c->ffd = -1; c->st = S_HANDSHAKE;
            c->ssl = SSL_new(w->ctx); if (!c->ssl){ close(cfd); free(c); goto next_ingest; }
            SSL_set_fd(c->ssl, cfd);
            SSL_set_ex_data(c->ssl, g_ssl_ex_base_dir_idx, (void*)w->base_dir);
            uint32_t ev = EPOLLIN | EPOLLOUT; /* 핸드셰이크 IN/OUT 모두 */
            if (add_fd_et(w->ep, cfd, ev, c) < 0){ conn_free(c); goto next_ingest; }

            next_ingest:
            pthread_mutex_lock(&w->qmtx);
        }
        pthread_mutex_unlock(&w->qmtx);

        /* 2) 이벤트 처리 */
        int n = epoll_wait(w->ep, evs, MAX_EVENTS, 200);
        if (n < 0){ if (errno==EINTR) continue; else break; }
        for (int i=0; i<n; ++i){
            conn_t *c = (conn_t*)evs[i].data.ptr;
            if (!c) continue;
            handle_conn_event(w, c, evs[i].events);
        }
    }
    return NULL;
}

/** 큐 삽입 */
static void q_push(worker_t *w, int fd){
    pthread_mutex_lock(&w->qmtx);
    int nxt = (w->qt + 1) % w->qcap;
    if (nxt == w->qh){ w->qh = (w->qh + 1) % w->qcap; } /* 가득차면 drop oldest */
    w->q[w->qt] = fd; w->qt = nxt;
    pthread_mutex_unlock(&w->qmtx);
    pthread_cond_signal(&w->qcv);
}

/** 리스너 */
static int make_listen(uint16_t port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&a, sizeof(a))<0) die("bind");
    if (listen(fd, 1024)<0) die("listen");
    set_nonblock(fd);
    return fd;
}

/** main */
int main(int argc, char **argv){
    /* stdout: line-buffered → tail -f 로 바로 보이게 */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 5){
        fprintf(stderr, "Usage: %s <port> <cert.pem> <key.pem> <base-dir> [workers]\n", argv[0]);
        return 1;
    }
    uint16_t port = (uint16_t)atoi(argv[1]);
    const char *cert = argv[2];
    const char *key  = argv[3];
    const char *base_dir = argv[4];
    int workers = (argc >= 6) ? atoi(argv[5]) : (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (workers <= 0) workers = 1;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;

    struct sigaction sa = {0}; sa.sa_handler = on_sigint; sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL);

    SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
    const SSL_METHOD *m = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(m); if (!ctx) die_ssl("SSL_CTX_new");
#ifdef SSL_OP_ENABLE_KTLS
# if defined(TLS_MODE_OPENSSL)
    SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_KTLS);
# else
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
# endif
#endif
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) die_ssl("min TLS1.3");
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) die_ssl("max TLS1.3");
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1) die_ssl("set ciphersuite");
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) die_ssl("use cert");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) die_ssl("use key");
    if (!SSL_CTX_check_private_key(ctx)) die_ssl("check key");

    g_ssl_ex_base_dir_idx = SSL_get_ex_new_index(0, (void*)"base_dir", NULL, NULL, NULL);

    int lfd = make_listen(port);

    worker_t *ws = calloc((size_t)workers, sizeof(worker_t));

    for (int i=0; i<workers; ++i) ws[i].cpu = pick_nth_allowed_cpu(i);

    for (int i=0;i<workers;i++){
        ws[i].ep = epoll_create1(EPOLL_CLOEXEC); if (ws[i].ep<0) die("epoll_create1");
        ws[i].qcap = 4096; ws[i].q = calloc((size_t)ws[i].qcap, sizeof(int)); ws[i].qh=ws[i].qt=0;
        pthread_mutex_init(&ws[i].qmtx, NULL); pthread_cond_init(&ws[i].qcv, NULL);
        ws[i].ctx = ctx; ws[i].base_dir = base_dir; ws[i].id = i;
        if (pthread_create(&ws[i].th, NULL, worker_main, &ws[i]) != 0) die("pthread_create");
    }

    fprintf(stderr, "[INFO] mode=%s listen=https://0.0.0.0:%u workers=%d (Ctrl-C to stop)\n", MODE_NAME, port, workers);

    int rr = 0; /* 라운드로빈 */
    while(!g_stop){
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int cfd = accept4(lfd, (struct sockaddr*)&addr, &alen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0){
            if (errno==EAGAIN || errno==EWOULDBLOCK){ usleep(1000); continue; }
            if (errno==EINTR) continue; else break;
        }
        q_push(&ws[rr], cfd); rr++; if (rr==workers) rr=0;
    }

    close(lfd);
    g_stop = 1;
    for (int i=0;i<workers;i++){ pthread_join(ws[i].th, NULL); close(ws[i].ep); free(ws[i].q); }
    free(ws);
    SSL_CTX_free(ctx); EVP_cleanup();
    return 0;
}
