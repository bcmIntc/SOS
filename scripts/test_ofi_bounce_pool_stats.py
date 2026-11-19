#!/usr/bin/env python3
"""Exercise actual allocation-probe code against CPU-only progress mocks."""
from pathlib import Path
import shlex
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def block(text, start):
    opening = text.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#define RAISE_ERROR_MSG(...) do { fprintf(stderr, __VA_ARGS__); exit(43); } while (0)
#define RAISE_ERROR_STR(msg) RAISE_ERROR_MSG("%s\n", msg)
#define shmem_internal_assert assert
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx) ((void)0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx) ((void)0)
#define SHMEM_TRANSPORT_OFI_TYPE_BOUNCE 1
#define OFI_MORE_POOL 1
typedef struct { uint64_t nalloc; } shmem_free_list_t;
typedef struct { struct { int mytype; } frag; char data[32]; } shmem_transport_ofi_bounce_buffer_t;
typedef struct {
    int id;
    shmem_free_list_t *bounce_buffers;
    struct { int count; } put_more;
    struct { int active; } node_quota;
    void *bounce_counter_head;
    uint64_t pending_bb_cntr;
    bool bounce_pool_stats;
    uint64_t bounce_pool_allocations, bounce_pool_waits, bounce_pool_limit_waits;
    uint64_t bounce_pool_quota_waits, bounce_pool_drain_calls, bounce_pool_high_water;
    double bounce_pool_wait_seconds, bounce_pool_max_wait_seconds;
} shmem_transport_ctx_t;
static size_t shmem_transport_ofi_max_bounce_buffers = 3;
static int shmem_internal_my_pe = 75;
static int timer_error, backwards, clocks, drains, admissions, flushes;
static shmem_transport_ofi_bounce_buffer_t buffer;
static int mock_clock(clockid_t clock, struct timespec *now) {
    assert(clock == CLOCK_MONOTONIC);
    if (timer_error) { errno=EIO; return -1; }
    now->tv_sec=1; now->tv_nsec=25000000; return 0;
}
static int mock_wall(struct timeval *now, void *zone) {
    if (timer_error) { errno=EIO; return -1; }
    now->tv_sec=1; now->tv_usec=25000; return 0;
}
#define clock_gettime mock_clock
#define gettimeofday mock_wall
"""

MOCKS = r"""
#undef clock_gettime
#undef gettimeofday
static double shmem_transport_ofi_bounce_pool_now(void) {
    clocks++;
    return 1.0 + (backwards ? -1.0 : 1.0) * (clocks - 1) * 0.005;
}
static bool shmem_transport_ofi_node_admit(void *quota, uint64_t in_use) {
    admissions++;
    return !((typeof(((shmem_transport_ctx_t *)0)->node_quota) *)quota)->active || admissions >= 3;
}
static void shmem_transport_ofi_drain_cq(shmem_transport_ctx_t *ctx) {
    drains++;
    if (ctx->bounce_buffers->nalloc >= 3 && drains >= 2) ctx->bounce_buffers->nalloc--;
}
static void shmem_transport_ofi_more_flush(shmem_transport_ctx_t *ctx, int reason) {
    assert(reason==OFI_MORE_POOL); flushes++; ctx->put_more.count=0;
}
static void shmem_transport_ofi_wait_counter_sources(shmem_transport_ctx_t *ctx) {
    ctx->bounce_counter_head=NULL; ctx->bounce_buffers->nalloc--;
}
static void *shmem_free_list_alloc(shmem_free_list_t *pool) {
    pool->nalloc++; buffer.frag.mytype=1; return &buffer;
}
"""

MAIN = r"""
int main(int argc, char **argv) {
    if (argc > 1) {
        timer_error=!strcmp(argv[1],"timer-error");
        if (!strcmp(argv[1],"backwards")) {
            shmem_free_list_t pool={3};
            shmem_transport_ctx_t ctx={.bounce_buffers=&pool,.bounce_pool_stats=true};
            backwards=1;
            create_bounce_buffer(&ctx,"abc",4);
        } else {
            assert(actual_now()==1.025);
        }
        return 0;
    }
    for (int enabled=0; enabled<=1; enabled++) {
        for (int mode=0; mode<4; mode++) {
            shmem_free_list_t pool={mode==1 || mode==3 ? 3 : mode==2 ? 1 : 0};
            shmem_transport_ctx_t ctx={.id=2,.bounce_buffers=&pool,.bounce_pool_stats=enabled};
            ctx.node_quota.active=mode==2;
            ctx.put_more.count=mode==1 || mode==3;
            ctx.bounce_counter_head=mode==3 ? &buffer : NULL;
            clocks=drains=admissions=flushes=0;
            assert(create_bounce_buffer(&ctx,"abc",4)==&buffer);
            assert(!memcmp(buffer.data,"abc",4));
            assert(drains==(mode==3 ? 1 : mode ? 2 : 0));
            assert(admissions==(mode==2 ? 3 : 1));
            assert(flushes==(mode==1 || mode==3 ? 1 : 0));
            assert(ctx.pending_bb_cntr==1);
            assert(clocks==(enabled && mode ? 2 : 0));
            assert(ctx.bounce_pool_allocations==(enabled ? 1 : 0));
            assert(ctx.bounce_pool_waits==(enabled && mode ? 1 : 0));
            assert(ctx.bounce_pool_limit_waits==(enabled && (mode==1 || mode==3) ? 1 : 0));
            assert(ctx.bounce_pool_quota_waits==(enabled && mode==2 ? 1 : 0));
            assert(ctx.bounce_pool_drain_calls==(enabled ? drains : 0));
            assert(ctx.bounce_pool_high_water==(enabled ? pool.nalloc : 0));
            if (enabled && mode) {
                assert(ctx.bounce_pool_wait_seconds > 0.0049 && ctx.bounce_pool_wait_seconds < 0.0051);
                assert(ctx.bounce_pool_max_wait_seconds==ctx.bounce_pool_wait_seconds);
            } else assert(ctx.bounce_pool_wait_seconds==0 && ctx.bounce_pool_max_wait_seconds==0);
            report(&ctx);
        }
    }
    return 0;
}
"""


class BouncePoolStatsTests(unittest.TestCase):
    def test_allocation_waits_timing_and_per_pe_reporting(self):
        header = (ROOT / "src/transport_ofi.h").read_text()
        timer = block(header, header.index("double shmem_transport_ofi_bounce_pool_now")).replace(
            "shmem_transport_ofi_bounce_pool_now", "actual_now", 1)
        allocate = block(header, header.index("shmem_transport_ofi_bounce_buffer_t * create_bounce_buffer"))
        source = (ROOT / "src/transport_ofi.c").read_text()
        start = source.index("void shmem_transport_ctx_destroy")
        report = block(source, source.index("if (ctx->bounce_pool_stats)", start))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for monotonic in (False, True):
                with self.subTest(monotonic=monotonic):
                    program = root / "probe.c"
                    program.write_text(PREFIX + timer + MOCKS + allocate
                                       + "\nstatic void report(shmem_transport_ctx_t *ctx) {\n"
                                       + report + "\n}\n" + MAIN)
                    command = shlex.split(os.environ.get("CC", "cc")) + [
                        "-std=gnu11", "-Wall", "-Werror", "-Wno-unused-function",
                        str(program), "-o", str(root / "probe")]
                    if monotonic:
                        command += ["-DHAVE_CLOCK_GETTIME"]
                    result = subprocess.run(command, capture_output=True, text=True, cwd=root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(root / "probe")], capture_output=True, text=True, cwd=root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    lines = result.stderr.splitlines()
                    self.assertEqual(len(lines), 4)
                    self.assertTrue(all(line.startswith("[0075] OFI bounce pool: ctx=2 has_pool=1") for line in lines))
                    self.assertIn("waits=0", lines[0])
                    for mode in ("timer-error", "backwards"):
                        result = subprocess.run([str(root / "probe"), mode], capture_output=True, text=True, cwd=root)
                        self.assertEqual(result.returncode, 43)
                        self.assertIn("Bounce-pool timer", result.stderr)


if __name__ == "__main__":
    unittest.main()
