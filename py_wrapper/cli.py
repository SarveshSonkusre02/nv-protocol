import os
import sys

def main():
    # Add the current directory containing all backend modules to sys.path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    import nv
    nv.main()

if __name__ == "__main__":
    main()