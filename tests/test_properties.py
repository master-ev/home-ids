from hypothesis import given, strategies as st
from alert_policy import (family_of, specificity_of, cooldown_allows, episode_starts, SPECIFICITY_GENERIC, SPECIFICITY_SPECIFIC, KIND_FAMILY)
from labels import choose_campaign_label, flows_per_port, DOS_VERDICT, SCAN_VERDICT
from trackers import held_open_connections, persistent_connections

MAX_FLOWS = 5000
MAX_PORTS = 65535
MAX_TIME = 10 ** 9
KNOWN_KINDS = sorted(KIND_FAMILY.keys())
KNOWN_VERDICTS = ["scan", "udp_scan", "dos", "syn_flood", "bruteforce", "anomaly", "normal"]

TIME_TOLERANCE = 0.001

@given(
    last=st.floats(min_value=0, max_value=MAX_TIME),
    elapsed=st.floats(min_value=0, max_value=MAX_TIME),
    cooldown=st.floats(min_value=1, max_value=3600),
)
def test_cooldown_allows_exactly_after_the_gap(last, elapsed, cooldown):
    now = last + elapsed
    measured = now - last
    if abs(measured - cooldown) < TIME_TOLERANCE:
        return
    assert cooldown_allows(last, now, cooldown) == (measured >= cooldown)

@given(
    last=st.floats(min_value=0, max_value=MAX_TIME),
    pause=st.floats(min_value=0, max_value=MAX_TIME),
    gap=st.floats(min_value=1, max_value=3600),
)
def test_episode_starts_exactly_after_the_gap(last, pause, gap):
    now = last + pause
    measured = now - last
    if abs(measured - gap) < TIME_TOLERANCE:
        return
    assert episode_starts(last, now, gap) == (measured > gap)

@given(st.text())
def test_family_is_never_empty(kind):
    family = family_of(kind)
    assert isinstance(family, str)
    assert family == KIND_FAMILY.get(kind, kind)

@given(st.text())
def test_specificity_is_always_one_of_two_levels(kind):
    assert specificity_of(kind) in (SPECIFICITY_GENERIC, SPECIFICITY_SPECIFIC)

@given(
    verdict=st.sampled_from(KNOWN_VERDICTS),
    flows=st.integers(min_value=0, max_value=MAX_FLOWS),
    ports=st.integers(min_value=0, max_value=MAX_PORTS),
)
def test_labelling_never_crashes_and_returns_a_pair(verdict, flows, ports):
    kind, desc = choose_campaign_label(verdict, flows, ports)
    if kind is None:
        assert desc is None
    else:
        assert isinstance(kind, str)
        assert isinstance(desc, str)
        assert len(desc) > 0

@given(
    flows=st.integers(min_value=1, max_value=MAX_FLOWS),
    ports=st.integers(min_value=1, max_value=MAX_PORTS),
)
def test_scan_shaped_campaigns_are_never_labelled_dos(flows, ports):
    scan_shaped_flows = ports
    kind, desc = choose_campaign_label(DOS_VERDICT, scan_shaped_flows, ports)
    if ports > 3:
        assert kind != "dos"

@given(
    flows=st.integers(min_value=0, max_value=MAX_FLOWS),
    ports=st.integers(min_value=0, max_value=MAX_PORTS),
)
def test_flows_per_port_never_divides_by_zero(flows, ports):
    ratio = flows_per_port(flows, ports)
    assert ratio >= 0.0

connection_summaries = st.lists(
    st.fixed_dictionaries({
        "triple": st.sampled_from([("a", "b", 80), ("a", "b", 443), ("c", "d", 80)]),
        "conn": st.text(min_size=1, max_size=5),
        "packets": st.integers(min_value=0, max_value=100),
        "initiator_ack": st.booleans(),
        "closed": st.booleans(),
    }),
    max_size=30,
)

@given(summaries=connection_summaries)
def test_held_open_is_a_subset_of_the_input(summaries):
    held = held_open_connections(summaries)
    all_conns = set()
    for summary in summaries:
        all_conns.add(summary["conn"])
    for triple in held:
        assert held[triple] <= all_conns

@given(
    current=st.sets(st.text(min_size=1, max_size=4), max_size=20),
    previous=st.sets(st.text(min_size=1, max_size=4), max_size=20),
)
def test_persistent_connections_is_symmetric_and_a_subset(current, previous):
    shared = persistent_connections(current, previous)
    assert shared == persistent_connections(previous, current)
    assert shared <= current
    assert shared <= previous