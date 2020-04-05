#   Copyright 2020 Yan Fitterer
#
#   Copying and distribution of this file, with or without modification,
#   are permitted in any medium without royalty provided the copyright
#   notice and this notice are preserved.  This file is offered as-is,
#   without any warranty.

# "Local delivery agent" for DMARC aggregate reports
# This utility is suitable for use as an "external command" for postfix
# local delivery. In particular, it attempts to catch all errors
# and always exits 0, since we do not want to be sending back
# delivery failure reports back to the DMARC report sender.

import sys
import subprocess

def main():
    try:
        if not len(sys.argv) > 1:
            raise Exception('no launch command')
        cproc = subprocess.run(sys.argv[1:], stdin=sys.stdin)
        if cproc.returncode != 0:
            print('ERROR: command exited ' + str(cproc.returncode),
                  file=sys.stderr)

    except Exception as e:
        print('FATAL: ' + str(e), file=sys.stderr)
    finally:
        sys.exit(0)

if __name__ == '__main__':
    main()
