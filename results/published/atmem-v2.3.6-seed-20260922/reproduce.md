# Reproduce AtMem 2.3.6 qualification

Tested on CPython 3.11.16, macOS arm64, benchmark commit
`07585b6615d640f93fe49854b4da3d5e97358af0`.

```bash
git clone https://github.com/aetna000/memory-integrity-benchmark.git
cd memory-integrity-benchmark
git checkout 07585b6615d640f93fe49854b4da3d5e97358af0
python3.11 -m venv .venv-atmem
. .venv-atmem/bin/activate
python -m pip install -r requirements.lock -r requirements-atmem.lock
python -m unittest \
  tests.test_atmem_adapter \
  tests.test_combined_report \
  tests.test_contract \
  tests.test_publication \
  tests.test_secret_scans
python -m runner.run \
  --systems atmem \
  --attacks all \
  --trials-from-yaml \
  --seed 20260922 \
  --run-id atmem-v2.3.6-seed-20260922 \
  --output-dir ./atmem-evidence-output
python -m runner.report ./atmem-evidence-output
python -m runner.publication ./atmem-evidence-output
```

The run refuses to overwrite an existing evidence directory. Use a fresh output
path. The expected validation result is 700 trials: 400 `PASS`, 300
`NOT_REPRESENTABLE`, zero `FAIL`, and zero `ERROR`.
