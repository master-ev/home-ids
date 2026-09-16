import sys
import incidents as inc

def main():
    path = inc.DEFAULT_ALERTS_PATH
    if len(sys.argv) > 1:
        path = sys.argv[1]
    inc.print_report(path)

if __name__ == "__main__":
    main()