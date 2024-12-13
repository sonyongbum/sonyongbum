#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import volatility3.cli
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
if __name__ == "__main__":
    volatility3.cli.main()
