## Starting from a fresh clone

The repository contains code only: captures, models and alert logs are gitignored
(the captures hold real home traffic). To get a working system:

1. `venv/bin/python setup_check.py` - lists what is missing and which script builds it
2. Record captures on your own network (see `capture_run.py` and `scenarios.py`)
3. `venv/bin/python build_dataset_v2.py && venv/bin/python train_v2.py D`
4. `sudo venv/bin/python live_ids.py`

Steps 2-3 take about an hour. Without them, the unit tests still run (N of 158);
the replay tests skip, because they need captures.

## Starting from a fresh clone

The repository contains code only: captures, models and alert logs are gitignored
(the captures hold real home traffic, and .pcap files are large). A fresh clone is
8 MB and every entry point explains what is missing rather than crashing:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python setup_check.py      # lists what is missing and which script builds it
venv/bin/python -m pytest tests/ -q # 116 of 158 pass with no data at all
```

`setup_check.py` then walks through capturing your own traffic, building the
dataset and training the model (about an hour). The 42 skipped tests are the ones
that replay captures.