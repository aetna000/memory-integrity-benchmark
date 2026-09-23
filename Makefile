PYTHON ?= python3
SEED ?= 20260922
RUN_ID ?= llmbasedos-v0.4-rc1-seed-$(SEED)
COMPETITOR_RUN_ID ?= competitor-smoke-seed-$(SEED)
ATMEM_VERSION ?= 2.3.6
ATMEM_RUN_ID ?= atmem-v$(ATMEM_VERSION)-seed-$(SEED)

.PHONY: bootstrap test credentials competitor-smoke atmem-smoke benchmark-atmem benchmark-llmbasedos benchmark-all verify

bootstrap:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -r requirements-all.lock

test:
	$(PYTHON) -m unittest discover -v

credentials:
	.venv/bin/python -m runner.check_credentials

competitor-smoke: credentials
	.venv/bin/python -m runner.run --systems mem0,zep,letta --attacks C,F --trials 1 --seed $(SEED) --run-id $(COMPETITOR_RUN_ID)
	.venv/bin/python -m runner.report results/$(COMPETITOR_RUN_ID)
	cd results/$(COMPETITOR_RUN_ID) && sha256sum --check SHA256SUMS

benchmark-llmbasedos: test
	$(PYTHON) -m runner.run --systems llmbasedos --attacks all --trials-from-yaml --seed $(SEED) --run-id $(RUN_ID)

atmem-smoke: test
	$(PYTHON) -m runner.run --systems atmem --attacks all --trials 1 --seed $(SEED) --run-id atmem-v$(ATMEM_VERSION)-smoke-s$(SEED)

benchmark-atmem: test
	$(PYTHON) -m runner.run --systems atmem --attacks all --trials-from-yaml --seed $(SEED) --run-id $(ATMEM_RUN_ID)
	$(PYTHON) -m runner.report results/$(ATMEM_RUN_ID)
	cd results/$(ATMEM_RUN_ID) && sha256sum --check SHA256SUMS

benchmark-all: credentials test
	.venv/bin/python -m runner.run --systems all --attacks all --trials-from-yaml --seed $(SEED) --run-id $(RUN_ID)
	.venv/bin/python -m runner.report results/$(RUN_ID)
	cd results/$(RUN_ID) && sha256sum --check SHA256SUMS

verify:
	$(PYTHON) -m runner.report results/$(RUN_ID)
	cd results/$(RUN_ID) && sha256sum --check SHA256SUMS
