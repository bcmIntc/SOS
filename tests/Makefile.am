# Standalone public-API regressions, independent of the tests-sos submodule.
if USE_OFI
# Build the matrix binaries with ordinary make, without installing them.
noinst_PROGRAMS = ofi_immediate ofi_counter_init ofi_quiet_oracle
check_PROGRAMS = ofi_quiet_model ofi_counter_wait_model
TESTS = ofi_immediate
ofi_immediate_SOURCES = ofi_immediate.c
ofi_counter_init_SOURCES = ofi_counter_init.c
ofi_quiet_oracle_SOURCES = ofi_quiet_oracle.c
# Explicit local model target; never linked to libsma or launched by TEST_RUNNER.
ofi_quiet_model_SOURCES = ofi_quiet_oracle.c quiet-model/shmem.c
ofi_quiet_model_CPPFLAGS = -I$(srcdir)/quiet-model
ofi_quiet_model_LDADD =
# Explicit counter-helper model; run directly, without MPI or TEST_RUNNER.
ofi_counter_wait_model_SOURCES = ofi_counter_wait_model.c
ofi_counter_wait_model_LDADD =

AM_CPPFLAGS = -I$(top_builddir)/mpp -I$(top_srcdir)/mpp
AM_LDFLAGS = $(LIBTOOL_WRAPPER_LDFLAGS)
LDADD = $(top_builddir)/src/libsma.la
if USE_PMI_SIMPLE
LDADD += $(top_builddir)/pmi-simple/libpmi_simple.la
endif
NPROCS ?= 2
LOG_COMPILER = $(TEST_RUNNER)
endif

EXTRA_DIST = run-ofi-immediate-matrix.sh test_ofi_immediate_matrix.py \
             run-ofi-quiet-matrix.sh test_ofi_quiet_oracle.py quiet-model/shmem.h
