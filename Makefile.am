# -*- Makefile -*-
#
# Copyright 2011 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S.  Government
# retains certain rights in this software.
#
# Copyright (c) 2017 Intel Corporation. All rights reserved.
# This software is available to you under the BSD license.
#
# This file is part of the Sandia OpenSHMEM software package. For license
# information, see the LICENSE file in the top level directory of the
# distribution.

ACLOCAL_AMFLAGS = -I config

EXTRA_DIST = sandia-openshmem.spec autogen.sh pmi-simple \
	scripts/build-ofi-immediate.sh scripts/rebuild-ofi.sh.in \
	scripts/run-osu-shmem.sh.in

if ENABLE_MANPAGES
EXTRA_DIST += man
endif

dist_doc_DATA = README NEWS LICENSE

SUBDIRS = bindings mpp pmi-simple src modules tests

if USE_OFI
nodist_noinst_SCRIPTS = scripts/rebuild-ofi.sh scripts/run-osu-shmem.sh
# Invoke these from the configured build root, including a VPATH build.
# "all" generates headers and rebuilds libsma before linking the regressions.
.PHONY: ofi-regressions check-ofi-quiet check-ofi-immediate check-ofi-counter-hardware
ofi-regressions: all
	$(MAKE) -C tests ofi-regressions

check-ofi-quiet: ofi-regressions
	$(MAKE) -C tests check-ofi-quiet

check-ofi-immediate: ofi-regressions
	$(MAKE) -C tests check-ofi-immediate

check-ofi-counter-hardware: ofi-regressions
	$(MAKE) -C tests check-ofi-counter-hardware
endif

if ENABLE_MANPAGES
SUBDIRS += man
endif
