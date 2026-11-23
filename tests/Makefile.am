# Standalone public-API regressions, independent of the tests-sos submodule.
if USE_OFI
# Build the matrix binaries with ordinary make, without installing them.
noinst_PROGRAMS = ofi_immediate ofi_counter_init ofi_quiet_oracle ofi_more ofi_node_budget
if USE_PMI_MPI
# MPI supplies only bootstrap/control; the data plane is standalone libfabric.
noinst_PROGRAMS += ofi_counter_hardware
ofi_counter_hardware_SOURCES = ofi_counter_hardware.c
ofi_counter_hardware_CPPFLAGS = -I$(top_srcdir)/src
ofi_counter_hardware_LDADD =
$(ofi_counter_hardware_OBJECTS): $(top_srcdir)/src/transport_ofi_counter.h
endif
check_PROGRAMS = ofi_quiet_model ofi_counter_wait_model ofi_more_state_model ofi_more_retry_model ofi_node_budget_model
TESTS = ofi_immediate
ofi_immediate_SOURCES = ofi_immediate.c
ofi_counter_init_SOURCES = ofi_counter_init.c
ofi_quiet_oracle_SOURCES = ofi_quiet_oracle.c
ofi_more_SOURCES = ofi_more.c
ofi_node_budget_SOURCES = ofi_node_budget.c
ofi_node_budget_model_SOURCES = ofi_node_budget_model.c
ofi_node_budget_model_CPPFLAGS = -I$(top_srcdir)/src
ofi_node_budget_model_LDADD =
$(ofi_node_budget_model_OBJECTS): $(top_srcdir)/src/transport_ofi_node_budget.h
# Explicit local model target; never linked to libsma or launched by TEST_RUNNER.
ofi_quiet_model_SOURCES = ofi_quiet_oracle.c quiet-model/shmem.c
ofi_quiet_model_CPPFLAGS = -I$(srcdir)/quiet-model
ofi_quiet_model_LDADD =
# Explicit counter-helper model; run directly, without MPI or TEST_RUNNER.
ofi_counter_wait_model_SOURCES = ofi_counter_wait_model.c
ofi_counter_wait_model_CPPFLAGS = -I$(top_srcdir)/src
ofi_counter_wait_model_LDADD =
$(ofi_counter_wait_model_OBJECTS): $(top_srcdir)/src/transport_ofi_counter.h
ofi_more_state_model_SOURCES = ofi_more_state_model.c
ofi_more_state_model_CPPFLAGS = -I$(top_srcdir)/src
ofi_more_state_model_LDADD =
$(ofi_more_state_model_OBJECTS): $(top_srcdir)/src/transport_ofi_more_state.h
ofi_more_retry_model_SOURCES = ofi_more_retry_model.c
ofi_more_retry_model_CPPFLAGS = -I$(top_srcdir)/src
ofi_more_retry_model_LDADD =
$(ofi_more_retry_model_OBJECTS): $(top_srcdir)/src/transport_ofi_more_state.h \
	$(top_srcdir)/src/transport_ofi_more.h

# config.status generates runners in builddir from the distributed .in files.
# The configured quiet runner reads its Python driver directly from srcdir.
nodist_noinst_SCRIPTS = run-ofi-immediate-matrix.sh run-ofi-quiet-matrix.sh \
                       run-ofi-counter-hardware.sh run-ofi-more.sh run-ofi-node-budget.sh
OFI_TEST_BYTES ?= all
OFI_TEST_LAUNCHER ?= mpirun -n 2 -ppn 1 -no-vni
OFI_NODE_LOCAL_PES ?= 4
OFI_NODE_LAUNCHER ?= mpirun -n 8 -ppn 4 -no-vni
.PHONY: check-ofi-node-budget ofi-regressions check-ofi-quiet check-ofi-immediate \
        check-ofi-counter-hardware check-ofi-bounce-tx-model
check-ofi-node-budget: ofi-regressions
	$(SHELL) "$(abs_builddir)/run-ofi-node-budget.sh" \
	    "$(OFI_NODE_LOCAL_PES)" $(OFI_NODE_LAUNCHER)
ofi-regressions: $(noinst_PROGRAMS) $(check_PROGRAMS) $(nodist_noinst_SCRIPTS)

check-ofi-counter-hardware: ofi-regressions
if USE_PMI_MPI
	SOS_OFI_LOG_DIR="$${SOS_OFI_LOG_DIR:-$(abs_top_builddir)/logs/counter-hardware-$$(date +%Y%m%d-%H%M%S)}" \
	    $(SHELL) "$(abs_builddir)/run-ofi-counter-hardware.sh" \
	    "$(abs_builddir)/ofi_counter_hardware" $(OFI_TEST_LAUNCHER)
else
	@echo "counter hardware tests require --enable-pmi-mpi and an MPI C compiler" >&2; exit 2
endif

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
else
.PHONY: check-ofi-bounce-tx-model
endif

# Source-extracted CPU model: no libsma, configure/build of production, launcher
# or allocation is required. Override PYTHON when python3 predates Python 3.8.
PYTHON ?= python3
check-ofi-bounce-tx-model:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(top_srcdir)/scripts/test_ofi_bounce_tx_complete.py"

EXTRA_DIST = run-ofi-immediate-matrix.sh.in test_ofi_immediate_matrix.py \
             run-ofi-node-budget.sh.in \
             run-ofi-more.sh.in \
             run-ofi-quiet-matrix.sh.in test_ofi_quiet_oracle.py quiet-model/shmem.h \
             test_ofi_vpath_workflow.py run-ofi-counter-hardware.sh.in \
             test_ofi_counter_hardware_runner.py test_osu_shmem_runner.py \
             ofi_bounce_tx_model.c ofi_bounce_tx_complete.md
