.PHONY: docs-install docs-serve docs-build

docs-install:
	python3 -m pip install -r requirements-docs.txt

docs-serve: docs-install
	python3 -m mkdocs serve

docs-build: docs-install
	python3 -m mkdocs build --strict
