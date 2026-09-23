
def pytest_report_header(config):
    return ("home-ids: tests that replay captures skip on a fresh clone - " "captures are gitignored (real home traffic). See setup_check.py.")