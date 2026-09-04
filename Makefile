.PHONY: init validate rebuild test up down runtime-reset recovery-drill

init:
	docker compose run --rm lifedb init

validate:
	docker compose run --rm lifedb validate

rebuild:
	docker compose run --rm lifedb rebuild

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

up:
	docker compose up -d --build

down:
	docker compose down

runtime-reset:
	# Runtime reset is safe only while the server is stopped.
	@test -n "$(LIFEDB_VAULT)" || (echo "Set LIFEDB_VAULT explicitly"; exit 1)
	docker compose stop lifedb
	docker compose run --rm lifedb runtime reset --confirm DELETE-RUNTIME

recovery-drill:
	# Runtime reset is safe only while the server is stopped.
	@test -n "$(LIFEDB_VAULT)" || (echo "Set LIFEDB_VAULT explicitly"; exit 1)
	docker compose stop lifedb
	docker compose run --rm lifedb validate
	docker compose run --rm lifedb runtime reset --confirm DELETE-RUNTIME
	docker compose run --rm lifedb rebuild
	docker compose run --rm lifedb validate
	docker compose run --rm lifedb search recoverable
