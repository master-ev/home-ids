import cProfile
import pstats
import runpy
import sys

PROFILE_FILE = "profile_run.out"
TOP_ROWS = 30

def run_target_under_profiler(target_script, target_argv):
    saved_argv = sys.argv
    sys.argv = target_argv
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        runpy.run_path(target_script, run_name="__main__")
    finally:
        profiler.disable()
        sys.argv = saved_argv
    return profiler

def print_report(profile_file):
    print("")
    print("top by CUMULATIVE time (who owns the total)")
    stats = pstats.Stats(profile_file)
    stats.sort_stats("cumulative")
    stats.print_stats(TOP_ROWS)
    print("")
    print("top by OWN time (where the CPU burns)")
    stats = pstats.Stats(profile_file)
    stats.sort_stats("tottime")
    stats.print_stats(TOP_ROWS)

def main():
    if len(sys.argv) < 2:
        print("usage: python diagnose_profile_run.py <script.py> [script args...]")
        return
    target_script = sys.argv[1]
    target_argv = sys.argv[1:]
    profiler = run_target_under_profiler(target_script, target_argv)
    profiler.dump_stats(PROFILE_FILE)
    print_report(PROFILE_FILE)
    print("")
    print("profile saved to " + PROFILE_FILE)

main()