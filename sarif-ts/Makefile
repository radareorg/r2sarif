all:
	tsc

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix sarif/*.ts

r2: plugin.r2.js
	r2 -i plugin.r2.js -c sarif /bin/ls

plugin.r2.js: plugin.r2.ts
	r2pm -r r2frida-compile -o plugin.r2.js plugin.r2.ts

pub:
	npm pub
