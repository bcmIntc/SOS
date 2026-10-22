# Standalone public-API regressions, independent of the tests-sos submodule.
if USE_OFI
# Build the matrix binaries with ordinary make, without installing them.
noinst_PROGRAMS = ofi_immediate ofi_counter_init
TESTS = ofi_immediate
ofi_immediate_SOURCES = ofi_immediate.c
ofi_counter_init_SOURCES = ofi_counter_init.c

AM_CPPFLAGS = -I$(top_builddir)/mpp -I$(top_srcdir)/mpp
AM_LDFLAGS = $(LIBTOOL_WRAPPER_LDFLAGS)
LDADD = $(top_builddir)/src/libsma.la
if USE_PMI_SIMPLE
LDADD += $(top_builddir)/pmi-simple/libpmi_simple.la
endif
NPROCS ?= 2
LOG_COMPILER = $(TEST_RUNNER)
endif

EXTRA_DIST = run-ofi-immediate-matrix.sh test_ofi_immediate_matrix.py
