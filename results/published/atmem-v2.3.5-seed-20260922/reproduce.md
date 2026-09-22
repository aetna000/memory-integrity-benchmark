# Reproduce AtMem 2.3.5 qualification

Tested on CPython 3.11.16, macOS arm64, benchmark commit
`18d8d2fe232f8c2fccfa5334886a761b1356b2da`.

```bash
git clone https://github.com/aetna000/memory-integrity-benchmark.git
cd memory-integrity-benchmark
git checkout 18d8d2fe232f8c2fccfa5334886a761b1356b2da
python3.11 -m venv .venv-atmem
. .venv-atmem/bin/activate
python -m pip install -r requirements.lock -r requirements-atmem.lock
python -m unittest tests.test_atmem_adapter tests.test_contract tests.test_publication
python -m runner.run \
  --systems atmem \
  --attacks all \
  --trials-from-yaml \
  --seed 20260922 \
  --run-id atmem-v2.3.5-seed-20260922 \
  --output-dir ./atmem-evidence-output
python -m runner.report ./atmem-evidence-output
python -m runner.publication ./atmem-evidence-output
```

The run refuses to overwrite an existing evidence directory. Use a fresh output
path. The expected validation result is 700 trials: 200 `PASS`, 400
`NOT_REPRESENTABLE`, and 100 `FAIL`.
