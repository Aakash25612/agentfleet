COMPOSE ?= docker compose

.PHONY: demo test bench build up down logs audit clean

## make demo  — build, start the stack, run the scripted agents (one command)
demo: up
	$(COMPOSE) --profile tools run --rm demo

## make test  — unit tests (inside the image build) + end-to-end safety suite
test: up
	$(COMPOSE) --profile tools run --rm e2e -test.v -test.skip 'TestBench'

## make bench — cold start and proxy overhead numbers (BENCH_SANDBOXES=20 by default)
bench: up
	$(COMPOSE) --profile tools run --rm e2e -test.v -test.run 'TestBench'

build:
	$(COMPOSE) --profile build --profile tools build

up: build
	$(COMPOSE) up -d --wait

## make audit TENANT=acme AGENT=repo-triager — the auditor's query
audit:
	$(COMPOSE) --profile tools run --rm --entrypoint /bin/auditq demo -dir /audit -tenant $(TENANT) -agent $(AGENT)

logs:
	$(COMPOSE) logs -f egressproxy executor

down:
	$(COMPOSE) --profile tools down --remove-orphans
	@ids=$$(docker ps -aq --filter label=agentfleet.session); [ -z "$$ids" ] || docker rm -f $$ids
	@nets=$$(docker network ls -q --filter label=agentfleet.session); [ -z "$$nets" ] || docker network rm $$nets

clean: down
	$(COMPOSE) down -v
