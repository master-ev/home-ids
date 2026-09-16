import sys
from collections import Counter
import joblib
import pandas as pd
import feature_sets as fs
from build_dataset_v2 import featurize_pcap
from context import flow_endpoints

MODEL_PATH = "my_model_v2.joblib"

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python classify_v2.py file.pcap")
        return
    path = sys.argv[1]
    saved = joblib.load(MODEL_PATH)
    model = saved["model"]
    features = saved["features"]
    base_features = fs.load_base_features()
    rows, flow_list = featurize_pcap(path, base_features)
    frame = pd.DataFrame(rows)
    predictions = model.predict(fs.clean_features(frame[features]))
    total = Counter()
    per_source = {}
    for index in range(len(flow_list)):
        source, destination, port = flow_endpoints(flow_list[index])
        prediction = str(predictions[index])
        total[prediction] = total[prediction] + 1
        if source not in per_source:
            per_source[source] = Counter()
        per_source[source][prediction] = per_source[source][prediction] + 1
    print(f"{path}: {len(flow_list)} flows, model set {saved['feature_set']}")
    print(f"Total: {dict(total)}")
    for source in sorted(per_source.keys()):
        print(f"  {source:<16} {dict(per_source[source])}")

if __name__ == "__main__":
    main()