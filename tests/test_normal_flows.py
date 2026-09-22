import pandas as pd
from build_normal_flows import split_by_time, SPLIT_FRACTION
from live_ids import load_extra_normal_flows, FLOW_METADATA_COLUMNS


FLOW_COUNT = 10
FIRST_TIME = 1000.0
STEP = 5.0

def build_frame():
    rows = []
    for index in range(FLOW_COUNT):
        rows.append({"window_time": FIRST_TIME + index * STEP, "packet_count": index})
    return pd.DataFrame(rows)

def test_split_by_time_keeps_order_and_splits_in_two():
    frame = build_frame()
    train, holdout, split_time = split_by_time(frame, SPLIT_FRACTION)
    assert len(train) == FLOW_COUNT / 2
    assert len(holdout) == FLOW_COUNT / 2
    assert train["window_time"].max() < holdout["window_time"].min()
    assert split_time == holdout["window_time"].iloc[0]

def test_metadata_columns_are_not_used_as_features(tmp_path):
    csv_path = tmp_path / "flows.csv"
    build_frame().assign(is_ipv6=1).to_csv(csv_path, index=False)
    frame = load_extra_normal_flows(str(csv_path))
    for column in FLOW_METADATA_COLUMNS:
        assert column not in frame.columns
    assert "packet_count" in frame.columns    