PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
SYS_PLUGDIR=$(shell r2 -H R2_LIBR_PLUGINS)

all: sarif.r2.js

r2: sarif.r2.js
	@echo "sarif load test/bins/files/sarif.driver.ns.json"
	@echo "sarif addw"
	r2 -i sarif.r2.js /bin/ls

clean:
	rm -f sarif.r2.js src/types.js

vs:
	open -a "Visual Studio Code" .

sarif.r2.js: src/plugin.r2.ts
	cd src/sarif && R2PM_OFFLINE=1 r2pm -r r2frida-compile -o types.js types.ts
	cd src && R2PM_OFFLINE=1 r2pm -r r2frida-compile -o ../sarif.r2.js plugin.r2.ts

test:
	cd test && R2R_OFFLINE=1 r2r -i db

citest:
	R2R_OFFLINE=1 r2r test/db

user-install: sarif.r2.js
	mkdir -p $(PLUGDIR)
	rm -f $(PLUGDIR)/sarif.r2.js
	cp -f sarif.r2.js $(PLUGDIR)/sarif.r2.js

user-symstall:
	mkdir -p $(PLUGDIR)
	rm -f $(PLUGDIR)/sarif.r2.js
	ln -fs $(shell pwd)/sarif.r2.js $(PLUGDIR)/sarif.r2.js

user-uninstall:
	rm -f $(shell r2 -H R2_USER_PLUGINS)/sarif.r2.js

install:
	$(MAKE) user-install PLUGDIR=$(SYS_PLUGDIR)

symstall:
	$(MAKE) user-symstall PLUGDIR=$(SYS_PLUGDIR)

uninstall:
	$(MAKE) user-uninstall PLUGDIR=$(SYS_PLUGDIR)

purge: user-uninstall uninstall

.PHONY: all test
.PHONY: user-install user-symstall user-uninstall
.PHONY: install symstall uninstall purge
