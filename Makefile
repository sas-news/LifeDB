.PHONY: init validate rebuild docs-smoke docs-smoke-docker test ci-local ci-python ci-opencode ci-hermes ci-package-smoke ci-docker up down runtime-reset recovery-drill

docs-smoke:
	PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py

docs-smoke-docker:
	PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --with-docker

init:
	python scripts/lifedb-compose.py run --rm lifedb init

validate:
	python scripts/lifedb-compose.py run --rm lifedb validate

rebuild:
	python scripts/lifedb-compose.py run --rm lifedb rebuild

test:
	PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v

ci-local:
	./scripts/ci-equivalent.sh all

ci-python:
	./scripts/ci-equivalent.sh python

ci-opencode:
	./scripts/ci-equivalent.sh opencode

ci-hermes:
	./scripts/ci-equivalent.sh hermes

ci-package-smoke:
	./scripts/ci-equivalent.sh package-smoke

ci-docker:
	./scripts/ci-equivalent.sh docker

up:
	python scripts/lifedb-compose.py up -d --build

down:
	python scripts/lifedb-compose.py down

runtime-reset:
	# Runtime reset is safe only while the server is stopped.
	python scripts/lifedb-compose.py stop lifedb
	python scripts/lifedb-compose.py run --rm lifedb runtime reset --confirm DELETE-RUNTIME

recovery-drill:
	# Runtime reset is safe only while the server is stopped.
	python scripts/lifedb-compose.py stop lifedb
	python scripts/lifedb-compose.py run --rm lifedb validate
	python scripts/lifedb-compose.py run --rm lifedb runtime reset --confirm DELETE-RUNTIME
	python scripts/lifedb-compose.py run --rm lifedb rebuild
	python scripts/lifedb-compose.py run --rm lifedb validate
	python scripts/lifedb-compose.py run --rm lifedb search recoverable
