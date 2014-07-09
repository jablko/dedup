all:
	tsxs -o metalink.so metalink.cc

check:
	for script in test/*; do $$script; done | sed ' #\
	  s/^ok [0-9]\+/\x1b[1;32m\0\x1b[0m/ #\
	  s/^not ok [0-9]\+\|Bail out!/\x1b[1;37;41m\0\x1b[0m/ #\
	  s/#.*/\x1b[33m\0\x1b[0m/'
