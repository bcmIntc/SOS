CC = oshcc

.PHONY: all
all:
	${CC} hello.c -o hello
	${CC} pi.c -o pi
	${CC} pi_reduce.c -o pi_reduce
	${CC} ofi_epoch_quiet.c -o ofi_epoch_quiet

hello: hello.c
	${CC} hello.c -o $@

pi: pi.c
	${CC} pi.c -o $@

pi_reduce: pi_reduce.c
	${CC} pi_reduce.c -o $@

ofi_epoch_quiet: ofi_epoch_quiet.c
	${CC} ofi_epoch_quiet.c -o $@

.PHONY: clean
clean:
	${RM} *.o hello pi pi_reduce ofi_epoch_quiet
