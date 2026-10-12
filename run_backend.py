"""Run the unmodified upstream Python backend with a prepared asyncio loop."""
import asyncio
import runpy
import sys
from pathlib import Path


def main():
    source, config = (Path(p).resolve() for p in sys.argv[1:3])
    sys.path.insert(0, str(source.parent))
    sys.argv = [str(source), str(config)]
    asyncio.set_event_loop(asyncio.new_event_loop())
    runpy.run_path(str(source), run_name="__main__")


if __name__ == "__main__":
    main()
