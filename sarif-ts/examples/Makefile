all:
	tsc verify.ts
	node verify.js

sync21:
	wget -O tmp http://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json
	# turns out "pattern": "^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$" is invalid for ajv xD
	cat tmp | grep -v zA | sed -e 's/en-US",/en-US"/' > sarif-schema-2.1.0.json
	rm -f tmp

sync22:
	# not standard?
	wget -O tmp https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.2/schema/sarif-2-2.schema.json
	mv tmp sarif-schema-2.2.0.json

sync: sync21 sync22
