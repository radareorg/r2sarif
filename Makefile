all:
	r2 -i sarif.r2.js /bin/ls

test:
	R2R_OFFLINE=1 r2r -i test/db

install:
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	ln -fs $(shell pwd)/sarif.r2.js $(shell r2 -H R2_USER_PLUGINS)/sarif.r2.js

user-install:
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	cp -f sarif.r2.js $(shell r2 -H R2_USER_PLUGINS)

symstall:
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	ln -fs $(shell pwd)/sarif.r2.js $(shell r2 -H R2_USER_PLUGINS)

uninstall user-uninstall:
	rm -f $(shell r2 -H R2_USER_PLUGINS)/sarif.r2.js

indent:
	cat sarif.r2.js | sed -e 's/\t/ /g' > tmp.r2.js
	mv tmp.r2.js sarif.r2.js
	semistandard --global r2 --fix sarif.r2.js

.PHONY: all test install user-install symstall uninstall user-uninstall indent
