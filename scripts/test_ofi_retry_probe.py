#!/usr/bin/env python3
"""Exercise production retry diagnostics with CPU-only provider mocks."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from test_ofi_bounce_pool_stats import block

ROOT = Path(__file__).resolve().parents[1]

PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <sys/uio.h>
#define FI_MORE UINT64_C(1)
#define FI_DELIVERY_COMPLETE UINT64_C(2)
#define FI_COMPLETION UINT64_C(4)
#define FI_FENCE UINT64_C(8)
#define FI_EAGAIN 11
#include "transport_ofi_more_state.h"
struct counter { uint64_t success, errors; };
struct fi_cq_entry { void *op_context; };
struct fi_rma_iov { uint64_t addr; size_t len; uint64_t key; };
struct fi_msg_rma {
    const struct iovec *msg_iov; void **desc; size_t iov_count;
    uint64_t addr; const struct fi_rma_iov *rma_iov; size_t rma_iov_count;
};
typedef struct { uint64_t nalloc; } shmem_free_list_t;
typedef struct { int mytype; } shmem_transport_ofi_frag_t;
typedef shmem_transport_ofi_frag_t shmem_transport_ofi_bounce_buffer_t;
typedef struct {
    int id, stx_idx, put_epoch_context;
    bool retry_probe, put_epoch_complete;
    uint64_t retry_probe_reports, retry_probe_cq_reads, retry_probe_cq_events;
    uint64_t put_cntr_pending, put_cntr_limit, pending_get_cntr;
    uint64_t pending_bb_cntr, completed_bb_cntr;
    unsigned int put_epoch_puts;
    size_t put_epoch_npes;
    shmem_free_list_t *bounce_buffers;
    shmem_transport_ofi_more_state_t put_more;
    struct counter *put_cntr, *get_cntr;
    void *ep, *cq;
    int node_quota;
    struct { int context; bool outstanding, complete; } bounce_tx_marker;
} shmem_transport_ctx_t;
static size_t shmem_transport_ofi_max_bounce_buffers = 128;
static uint64_t shmem_transport_ofi_max_poll = 1000;
static int shmem_internal_my_pe = 7, shmem_transport_ofi_single_ep;
static unsigned int counter_reads, cq_reads, posts, event;
static unsigned char data;
static void *shmem_internal_data_base = &data;
static struct { size_t OFI_CQ_BATCH_SIZE; } shmem_internal_params = {1};
#define SHMEM_TRANSPORT_OFI_TYPE_BOUNCE 1
#define SHMEM_TRANSPORT_OFI_TYPE_BOUNCE_TX 3
#define SHMEM_TRANSPORT_OFI_CNTR_READ(p) (*(p))
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx) ((void)0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx) ((void)0)
#define shmem_internal_assert assert
#define GET_MR_DESC_ADDR(index) ((void)(index), (void **)0)
static int shmem_transport_ofi_get_mr_desc_index(void *p) { (void)p; return 0; }
static void fail(const char *format, ...) {
    va_list args; va_start(args,format); vfprintf(stderr,format,args); va_end(args);
    printf("counter_reads=%u cq_reads=%u posts=%u\n",counter_reads,cq_reads,posts);
    exit(43);
}
#define RAISE_ERROR_MSG(...) fail(__VA_ARGS__)
#define RAISE_ERROR_STR(msg) fail("%s\n",msg)
#define OFI_CTX_CHECK_ERROR(ctx,ret) do { (void)(ctx); if(ret) fail("provider error %d\n",(int)(ret)); } while(0)
static uint64_t fi_cntr_read(struct counter *c) { counter_reads++; return c->success; }
static uint64_t fi_cntr_readerr(struct counter *c) { counter_reads++; return c->errors; }
static shmem_transport_ofi_frag_t fragment = {1};
static int fi_cq_read(void *cq, struct fi_cq_entry *buf, size_t count) {
    (void)cq; assert(count==1); cq_reads++;
    if(event) { event=0; buf->op_context=&fragment; return 1; }
    return -FI_EAGAIN;
}
static void shmem_free_list_free(shmem_free_list_t *pool, void *buffer) {
    assert(buffer==&fragment); assert(pool->nalloc); pool->nalloc--;
}
static void shmem_transport_ofi_node_release(int *quota, uint64_t count) {
    (void)quota; (void)count;
}
static int fi_writemsg(void *ep, const struct fi_msg_rma *msg, uint64_t flags) {
    (void)ep; assert(msg->msg_iov->iov_len==0);
    assert(flags==FI_DELIVERY_COMPLETE); posts++; return -FI_EAGAIN;
}
static void shmem_transport_probe(void) {}
"""

MAIN = r"""
int main(int argc, char **argv) {
    assert(argc==2);
    struct counter put={100,0}, get={20,0};
    shmem_free_list_t pool={2};
    shmem_transport_ctx_t ctx={
        .id=-1,.stx_idx=-1,.retry_probe=strcmp(argv[1],"off")!=0,
        .put_cntr=&put,.get_cntr=&get,.bounce_buffers=&pool,
        .put_cntr_pending=103,.put_cntr_limit=1000,.pending_get_cntr=21,
        .pending_bb_cntr=2,.put_more={.limit=1,.budget=128}
    };
    uint64_t polled=0;
    if(!strcmp(argv[1],"success")) {
        ctx.put_more.bounce_post=true;ctx.put_more.bounce_flags=FI_MORE;
        assert(!try_again(&ctx,0,&polled,"accepted",42,9,4096,FI_MORE));
        assert(counter_reads==0 && cq_reads==0 && !ctx.put_more.bounce_post);
        assert(ctx.put_more.bounce_flags==0 && ctx.put_more.count==1);
        return 0;
    }
    if(!strcmp(argv[1],"error")) {
        try_again(&ctx,-5,&polled,"failed",42,9,4096,0);
        assert(0);
    }
    if(!strcmp(argv[1],"flush")) {
        ctx.put_more.count=1;
        shmem_transport_ofi_more_flush(&ctx,OFI_MORE_RETRY);
        assert(0);
    }
    if(!strcmp(argv[1],"cap")) {
        for(int i=0;i<20;i++) {
            uint64_t once=0;
            assert(try_again(&ctx,-FI_EAGAIN,&once,"earlier",42,9,4096,0));
        }
        assert(ctx.retry_probe_reports==8 && counter_reads==32);
    }
    if(!strcmp(argv[1],"global")) {
        ctx.put_more.limit=0;shmem_transport_ofi_max_poll=3;
    }
    event=1;
    bool more=!strcmp(argv[1],"more");
    ctx.put_more.bounce_flags=more ? FI_MORE : 0;
    uint64_t flags=more ? ctx.put_more.bounce_flags : FI_FENCE|FI_COMPLETION|FI_DELIVERY_COMPLETE;
    while(try_again(&ctx,-FI_EAGAIN,&polled,"test-post",42,9,4096,flags)) {
        if(more) flags=ctx.put_more.bounce_flags;
    }
    assert(0);
}
"""


class RetryProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix=".ofi-retry-test-", dir=ROOT)
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        header = (ROOT / "src/transport_ofi.h").read_text()
        drain = block(header, header.index("void shmem_transport_ofi_drain_cq("))
        probe = block(header, header.index("\nvoid shmem_transport_ofi_retry_probe(") + 1)
        retry = block(header, header.index("\nint try_again(") + 1)
        more = (ROOT / "src/transport_ofi_more.h").read_text()
        flush = block(more, more.index("shmem_transport_ofi_more_flush("))
        program = root / "probe.c"
        program.write_text(PREFIX + "\nstatic inline\n" + drain + "\nstatic inline\n"
                           + probe + "\nstatic inline void\n" + flush
                           + "\nstatic inline\n" + retry + MAIN)
        cls.binary = root / "probe"
        result = subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src"),
            str(program), "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True)
        lines = [line for line in result.stderr.splitlines() if "OFI retry probe:" in line]
        return result, lines

    def test_disabled_probe_and_success_do_not_read_counters_or_log(self):
        result, lines = self.run_mode("off")
        self.assertEqual(result.returncode, 43)
        self.assertFalse(lines)
        self.assertIn("counter_reads=0", result.stdout)
        self.assertIn("FI_MORE operation retry exceeded 64 attempts", result.stderr)
        result, lines = self.run_mode("success")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(lines)

    def test_exhaustion_reports_actual_flags_and_completion_progress(self):
        for mode, more in (("on", 0), ("more", 1)):
            result, lines = self.run_mode(mode)
            self.assertEqual(result.returncode, 43)
            self.assertEqual(len(lines), 3)
            for line, attempt in zip(lines, (1, 16, 64)):
                self.assertIn(f"attempt={attempt} ", line)
                self.assertIn("operation=test-post line=42 pe=9 bytes=4096", line)
                self.assertIn(f"fi_more={more if attempt == 1 else 0} ", line)
                self.assertIn("put_issued=103 put_done=100 put_errors=0", line)
                self.assertIn("get_issued=21 get_done=20 get_errors=0", line)
                self.assertIn("bb_pending=2 bb_done=1 pool_used=1", line)
            self.assertIn("exhausted=1", lines[-1])
            self.assertIn("counter_reads=12 cq_reads=65", result.stdout)

    def test_context_report_cap_cannot_suppress_final_failure(self):
        result, lines = self.run_mode("cap")
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(lines), 9)
        self.assertIn("attempt=64 exhausted=1", lines[-1])
        self.assertIn("counter_reads=36", result.stdout)

    def test_global_retry_limit_is_unchanged_and_has_a_final_snapshot(self):
        result, lines = self.run_mode("global")
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(lines), 2)
        self.assertIn("attempt=4 exhausted=1", lines[-1])
        self.assertIn("Operation retry limit exceeded (3)", result.stderr)

    def test_flush_and_nonretry_errors_keep_existing_failure_behavior(self):
        result, lines = self.run_mode("flush")
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(lines), 3)
        self.assertIn("operation=shmem_transport_ofi_more_flush", lines[-1])
        self.assertIn("pe=-1 bytes=0", lines[-1])
        self.assertIn("posts=64", result.stdout)
        self.assertIn("deferred source buffers remain owned", result.stderr)
        result, lines = self.run_mode("error")
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(lines), 1)
        self.assertIn("ret=-5 attempt=0 exhausted=1", lines[0])
        self.assertIn("provider error -5", result.stderr)


if __name__ == "__main__":
    unittest.main()
