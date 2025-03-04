.PHONY: clean
clean:
	rm -rf {root,intermediate,ca-bundle,ca-chain}.{crl,crt,key} leaf.{crt,key} with-idp without-idp

.PHONY: with-idp
with-idp: venv
	./venv/bin/python3 make-artifacts 1
	mkdir -p with-idp
	mv *.crt *.key *.crl with-idp

.PHONY: without-idp
without-idp: venv
	./venv/bin/python3 make-artifacts 0
	mkdir -p without-idp
	mv *.crt *.key *.crl without-idp

venv:
	(python3 -m venv venv && ./venv/bin/pip install -U pip && ./venv/bin/pip install cryptography) || (rm -rf venv; exit 1)
