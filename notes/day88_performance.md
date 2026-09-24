# Day 88 - How fast is the pipeline?

Never measured. A 5-second window that takes longer than 5 seconds to process does
not slow the IDS down - the kernel drops the packets it cannot buffer, silently.

## Measurements (benchmark.py)
<FILL IN table per capture: components, slowest window, throughput, margin>

Real home traffic from the day 76 soak: 810224 packets in 0.54 h = ~420 packets/s.

## Conclusion
<FILL IN: enough margin / optimised the model call / documented limit>

