#!/usr/bin/env python3
"""Launch Ryu manager with an eventlet compatibility patch.

Ryu 4.34 expects eventlet.wsgi.ALREADY_HANDLED, which is missing in newer
Eventlet releases. This launcher inserts the symbol before importing
ryu.cmd.manager so the controller can run on modern Eventlet versions.
"""

import runpy
import sys
import os
from pathlib import Path


def patch_eventlet_already_handled():
    # Avoid greendns import path issues with older dnspython builds.
    os.environ.setdefault("EVENTLET_NO_GREENDNS", "yes")

    import eventlet.wsgi

    if not hasattr(eventlet.wsgi, "ALREADY_HANDLED"):
        eventlet.wsgi.ALREADY_HANDLED = object()


def main():
    patch_eventlet_already_handled()

    default_app = str(Path(__file__).resolve().with_name("dynamic_host_blocking.py"))
    app_args = sys.argv[1:] if len(sys.argv) > 1 else [default_app]

    sys.argv = ["ryu-manager", *app_args]
    runpy.run_module("ryu.cmd.manager", run_name="__main__")


if __name__ == "__main__":
    main()
