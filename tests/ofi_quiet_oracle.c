/* Observe target bytes after quiet using TCP control only.
 *
 * Between the setup barrier and each observation/acknowledgment, PE 1 makes
 * no SHMEM calls. PE 0 posts no further fabric operations after the quiet
 * under test until that acknowledgment. The check is one pass, never a
 * poll-until-correct loop. Volatile loads plus a CPU/compiler fence assume
 * coherent NIC DMA on the target platform; validate that assumption there.
 *
 * TCP transit creates an observation delay: this is not an instantaneous
 * visibility proof. Combine the runtime result with delivery/accounting
 * analysis and the independently run delayed-delivery model negative control.
 */
#define _POSIX_C_SOURCE 200809L
#include <shmem.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define WRITES 17
#define EPOCHS 4
#define HOST_BYTES 256
#define MAGIC UINT32_C(0x534f5351)
#define QUIET_RETURNED 1
#define ACK_GOOD 2
#define ACK_BAD 3

struct peer_info {
    char host[HOST_BYTES];
    char control_host[HOST_BYTES];
    uint32_t port;
};

static int timeout_seconds = 30;

static void
fail(const char *message)
{
    fprintf(stderr, "PE %d: OFI quiet oracle: %s\n", shmem_my_pe(), message);
    shmem_global_exit(1);
    exit(1);
}

static void
fail_system(const char *message)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "%s: %s", message, strerror(errno));
    fail(detail);
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        fail_system("clock_gettime failed");
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + (uint64_t) ts.tv_nsec;
}

static void
wait_fd(int fd, short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = now_ns();
        if (now >= deadline)
            fail("TCP control timeout");
        int milliseconds = (int) ((deadline - now + 999999) / 1000000);
        struct pollfd p = { .fd = fd, .events = events };
        int ret = poll(&p, 1, milliseconds);
        if (ret < 0 && errno == EINTR)
            continue;
        if (ret < 0)
            fail_system("TCP control poll failed");
        if (!ret)
            continue;
        if (p.revents & events)
            return;
        fail("TCP control connection failed");
    }
}

static uint64_t
deadline_ns(void)
{
    return now_ns() + (uint64_t) timeout_seconds * UINT64_C(1000000000);
}

static void
nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        fail_system("cannot set TCP socket nonblocking");
}

static void
transfer(int fd, void *buffer, size_t bytes, int writing)
{
    unsigned char *p = buffer;
    uint64_t deadline = deadline_ns();
    while (bytes) {
        wait_fd(fd, writing ? POLLOUT : POLLIN, deadline);
        ssize_t n = writing ? send(fd, p, bytes, 0) : recv(fd, p, bytes, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n < 0)
            fail_system("TCP control send/receive failed");
        if (n == 0)
            fail("TCP control connection closed");
        p += n;
        bytes -= (size_t) n;
    }
}

static void
send_frame(int fd, int epoch, int operation)
{
    uint32_t frame[3] = { htonl(MAGIC), htonl((uint32_t) epoch),
                          htonl((uint32_t) operation) };
    transfer(fd, frame, sizeof(frame), 1);
}

static int
receive_frame(int fd, int epoch)
{
    uint32_t frame[3];
    transfer(fd, frame, sizeof(frame), 0);
    if (ntohl(frame[0]) != MAGIC || ntohl(frame[1]) != (uint32_t) epoch)
        fail("invalid TCP control frame");
    return (int) ntohl(frame[2]);
}

static int
listen_control(uint32_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail_system("TCP control socket failed");
    nonblocking(fd);
    struct sockaddr_in addr = { .sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) || listen(fd, 1))
        fail_system("TCP control bind/listen failed");
    socklen_t bytes = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &bytes))
        fail_system("TCP control port query failed");
    *port = ntohs(addr.sin_port);
    return fd;
}

static int
connect_control(const struct peer_info *peer)
{
    char service[16];
    snprintf(service, sizeof(service), "%u", (unsigned int) peer->port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(peer->control_host, service, &hints, &addresses))
        fail("TCP control hostname resolution failed; set SOS_OFI_CONTROL_HOST");
    int connected = -1;
    uint64_t deadline = deadline_ns();
    for (struct addrinfo *a = addresses; a; a = a->ai_next) {
        int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0)
            continue;
        nonblocking(fd);
        int ret = connect(fd, a->ai_addr, a->ai_addrlen);
        if (ret < 0 && errno == EINPROGRESS) {
            wait_fd(fd, POLLOUT, deadline);
            int error = 0;
            socklen_t bytes = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &bytes))
                error = errno;
            ret = error ? -1 : 0;
        }
        if (ret == 0) {
            connected = fd;
            break;
        }
        close(fd);
    }
    freeaddrinfo(addresses);
    if (connected < 0)
        fail("TCP control connect failed");
    return connected;
}

static unsigned char
pattern(int epoch, int slot, size_t byte)
{
    return (unsigned char) (1 + (epoch * 31 + slot * 7 + byte % 251) % 253);
}

static int
observe(const volatile unsigned char *target, size_t bytes, int epoch)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    for (int slot = 0; slot < WRITES; slot++)
        for (size_t byte = 0; byte < bytes; byte++) {
            unsigned char actual = target[(size_t) slot * bytes + byte];
            if (actual != pattern(epoch, slot, byte)) {
                fprintf(stderr, "PE 1: quiet-at-return mismatch: epoch=%d "
                        "slot=%d byte=%zu got=%u expected=%u\n",
                        epoch, slot, byte, (unsigned int) actual,
                        (unsigned int) pattern(epoch, slot, byte));
                return 0;
            }
        }
    return 1;
}

int
main(int argc, char **argv)
{
    size_t bytes = 1024;
    const char *mode = argc >= 3 ? argv[2] : "blocking";
    if (argc > 3 || (strcmp(mode, "blocking") && strcmp(mode, "nbi")))
        return 1;
    if (argc >= 2) {
        char *end;
        unsigned long n = strtoul(argv[1], &end, 10);
        if (!*argv[1] || *end || n == 0 || n > 8192)
            return 1;
        bytes = (size_t) n;
    }
    const char *timeout = getenv("SOS_OFI_CONTROL_TIMEOUT");
    if (timeout) {
        char *end;
        long n = strtol(timeout, &end, 10);
        if (!*timeout || *end || n < 1 || n > 600)
            return 1;
        timeout_seconds = (int) n;
    }
    signal(SIGPIPE, SIG_IGN);
    int provided;
    if (shmem_init_thread(SHMEM_THREAD_SINGLE, &provided))
        return 1;
    if (provided != SHMEM_THREAD_SINGLE || shmem_n_pes() != 2) {
        shmem_finalize();
        return 77;
    }
    int me = shmem_my_pe();
    int nbi = !strcmp(mode, "nbi");
    struct peer_info *local = shmem_malloc(sizeof(*local));
    unsigned char *target = shmem_malloc(EPOCHS * WRITES * bytes);
    unsigned char *source = malloc(WRITES * bytes);
    if (!local || !target || !source)
        fail("allocation failed");
    memset(local, 0, sizeof(*local));
    memset(target, 0, EPOCHS * WRITES * bytes);
    if (gethostname(local->host, HOST_BYTES - 1))
        fail("gethostname failed");
    const char *control_host = getenv("SOS_OFI_CONTROL_HOST");
    if (!control_host)
        control_host = local->host;
    if (strlen(control_host) >= HOST_BYTES)
        fail("control hostname too long");
    strcpy(local->control_host, control_host);
    int listener = me == 1 ? listen_control(&local->port) : -1;
    shmem_barrier_all();
    struct peer_info peer;
    shmem_getmem(&peer, local, sizeof(peer), 1 - me);
    if (!strcmp(local->host, peer.host)) {
        if (me == 0)
            fprintf(stderr, "SKIP: quiet oracle requires two different hosts\n");
        if (listener >= 0)
            close(listener);
        shmem_free(target);
        shmem_free(local);
        free(source);
        shmem_finalize();
        return 77;
    }
    /* All OFI setup/control operations finish before the measured protocol. */
    shmem_barrier_all();
    int control;
    if (me == 0) {
        control = connect_control(&peer);
    } else {
        wait_fd(listener, POLLIN, deadline_ns());
        control = accept(listener, NULL, NULL);
        if (control < 0)
            fail_system("TCP control accept failed");
        nonblocking(control);
        close(listener);
    }
    for (int epoch = 0; epoch < EPOCHS; epoch++) {
        if (me == 0) {
            for (int i = 0; i < WRITES; i++) {
                int slot = epoch % 2 ? WRITES - i - 1 : i;
                unsigned char *s = source + (nbi ? (size_t) slot * bytes : 0);
                for (size_t byte = 0; byte < bytes; byte++)
                    s[byte] = pattern(epoch, slot, byte);
                unsigned char *t = target + ((size_t) epoch * WRITES + slot) * bytes;
                if (nbi)
                    shmem_putmem_nbi(t, s, bytes, 1);
                else {
                    shmem_ctx_putmem(SHMEM_CTX_DEFAULT, t, s, bytes, 1);
                    memset(s, 0xee, bytes);
                }
            }
            shmem_quiet();
            uint64_t returned = now_ns();
            if (nbi)
                memset(source, 0xee, WRITES * bytes);
            send_frame(control, epoch, QUIET_RETURNED);
            if (receive_frame(control, epoch) != ACK_GOOD)
                fail("receiver rejected data after quiet");
            printf("OFI quiet observation: epoch=%d mode=%s "
                   "return_to_ack_ns=%llu\n", epoch, mode,
                   (unsigned long long) (now_ns() - returned));
        } else {
            if (receive_frame(control, epoch) != QUIET_RETURNED)
                fail("missing quiet-return announcement");
            int good = observe(target + (size_t) epoch * WRITES * bytes, bytes, epoch);
            send_frame(control, epoch, good ? ACK_GOOD : ACK_BAD);
            if (!good)
                fail("target visibility check failed");
        }
    }
    close(control);
    /* These completion operations occur only after all observations and ACKs. */
    shmem_barrier_all();
    shmem_free(target);
    shmem_free(local);
    free(source);
    if (me == 0)
        printf("OFI quiet oracle completed: mode=%s bytes=%zu epochs=%d "
               "writes=%d control=tcp receiver_shmem_calls=0\n",
               mode, bytes, EPOCHS, WRITES);
    shmem_finalize();
    return 0;
}
