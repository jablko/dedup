all:
	tsxs -C metalink.cc -o metalink.so

check:
	for e in test/*; do $$e; done
