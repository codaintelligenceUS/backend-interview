#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""

import os
import sys


def main() -> None:
    """Run administrative tasks."""
    # Set (not setdefault) so a DJANGO_SETTINGS_MODULE left over in your shell
    # from another project cannot hijack this one.
    os.environ['DJANGO_SETTINGS_MODULE'] = 'interview_api.settings'

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
