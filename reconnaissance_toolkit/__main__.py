#!/usr/bin/env python3
import logging

from reconnaissance_toolkit.main import main

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log = logging.getLogger(__name__)
        log.fatal(e)
        raise
