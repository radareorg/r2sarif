all:
	tsc

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix sarif/*.ts

pub:
	npm pub
