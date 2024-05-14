CC=gcc
VULN1FLAGS=-fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0

# -fno-stack-protector = canary protection
#  -z execstack = disable NX flag in stack pages
#  -D_FORTIFY_SOURCE=0 = disable BoF detection in vulnerable functions
#  to disable ASLR -> set /proc/sys/kernel/randomize_va_space to 0

#set owner to root and change suid = chown root vuln; chmod +s vuln

vuln1: vuln1.c
	$(CC) $(VULN1FLAGS) -o vuln1 vuln1.c

