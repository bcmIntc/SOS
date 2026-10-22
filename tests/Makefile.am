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
ofi_counter_wait_model_CPPFLAGS = -I$(top_srcdir)/src
ofi_counter_wait_model_LDADD =
$(ofi_counter_wait_model_OBJECTS): $(top_srcdir)/src/transport_ofi_counter.h

# config.status generates runners in builddir from the distributed .in files.
# The configured quiet runner reads its Python driver directly from srcdir.
nodist_noinst_SCRIPTS = run-ofi-immediate-matrix.sh run-ofi-quiet-matrix.sh
OFI_TEST_BYTES ?= all
OFI_TEST_LAUNCHER ?= mpirun -n 2 -ppn 1 -no-vni
.PHONY: ofi-regressions check-ofi-quiet check-ofi-immediate
ofi-regressions: $(noinst_PROGRAMS) $(check_PROGRAMS) $(nodist_noinst_SCRIPTS)

check-ofi-quiet: ofi-regressions
	SOS_OFI_LOG_DIR="$${SOS_OFI_LOG_DIR:-$(abs_top_builddir)/logs/quiet-suite-$$(date +%Y%m%d-%H%M%S)}" \
	    $(SHELL) "$(abs_builddir)/run-ofi-quiet-matrix.sh" \
	    "$(abs_builddir)/ofi_quiet_oracle" "$(OFI_TEST_BYTES)" $(OFI_TEST_LAUNCHER)

check-ofi-immediate: ofi-regressions
	@set -e; \
	case "$(OFI_TEST_BYTES)" in \
	    all) sizes="1024 4096 8192" ;; \
	    ''|*[!0-9]*) echo "OFI_TEST_BYTES must be all or an integer in 1-8192" >&2; exit 2 ;; \
	    *) sizes="$(OFI_TEST_BYTES)" ;; \
	esac; \
	log_root="$${SOS_OFI_LOG_DIR:-$(abs_top_builddir)/logs/immediate-suite-$$(date +%Y%m%d-%H%M%S)}"; \
	if test -e "$$log_root"; then \
	    echo "use a new log directory; $$log_root already exists" >&2; exit 2; \
	fi; \
	for bytes in $$sizes; do \
	    SOS_OFI_LOG_DIR="$$log_root/matrix-$$bytes" \
	        $(SHELL) "$(abs_builddir)/run-ofi-immediate-matrix.sh" \
	        "$(abs_builddir)/ofi_immediate" "$$bytes" $(OFI_TEST_LAUNCHER); \
	done

AM_CPPFLAGS = -I$(top_builddir)/mpp -I$(top_srcdir)/mpp
AM_LDFLAGS = $(LIBTOOL_WRAPPER_LDFLAGS)
LDADD = $(top_builddir)/src/libsma.la
if USE_PMI_SIMPLE
LDADD += $(top_builddir)/pmi-simple/libpmi_simple.la
endif
NPROCS ?= 2
LOG_COMPILER = $(TEST_RUNNER)
endif

EXTRA_DIST = run-ofi-immediate-matrix.sh.in test_ofi_immediate_matrix.py \
             run-ofi-quiet-matrix.sh.in test_ofi_quiet_oracle.py quiet-model/shmem.h \
             test_ofi_vpath_workflow.py
