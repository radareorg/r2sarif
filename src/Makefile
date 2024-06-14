all:
	tsc

vs vsc:
	open -a "Visual Studio Code" .

test:
	$(MAKE) -C .. test

xxtest:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix sarif/*.ts

r2: plugin.r2.js
	r2 -i plugin.r2.js -c sarif /bin/ls

plugin.r2.js: plugin.r2.ts
	rm -f sarif/*.js
	cd sarif && r2pm -r r2frida-compile -o types.js types.ts
	r2pm -r r2frida-compile -o plugin.r2.js plugin.r2.ts

pub:
	npm pub

.PHONY: pub r2 lint test vs vsc all
