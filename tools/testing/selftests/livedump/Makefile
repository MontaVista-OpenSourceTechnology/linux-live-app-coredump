# SPDX-License-Identifier: GPL-2.0
# Makefile for livedump selftests.
CFLAGS = -Wall -O2

TEST_GEN_PROGS := lacdtest

include ../lib.mk

override RUN_TESTS := if [ -f /proc/self/livedump ] ; \
		      then	\
				./lacdtest ; \
		      else	\
				echo "WARN: No /proc/self/livedump exists, test skipped." ; \
		      fi
override EMIT_TESTS := echo "$(RUN_TESTS)"
