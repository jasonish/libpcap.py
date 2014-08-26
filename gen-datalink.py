#! /usr/bin/env python
#
# Script to generate a file containing datalink values.

import sys
import re

header = """# Automatically generated.
"""

def main():
    linktypes = []
    with open("/usr/include/pcap/bpf.h") as fileobj:
        print(header)
        for line in fileobj:
            m = re.search("^#define (DLT_[A-Z0-9]+)\s+(\d+)", line)
            if m:
                linktypes.append((m.group(1), m.group(2)))
    
    for linktype in linktypes:
        print("%s = %s" % (linktype[0], linktype[1]))

    print("\n# Lookup by value.")
    print("LINKTYPE = {}")
    for name, value in linktypes:
        print("LINKTYPE[%s] = '%s'" % (value, name))

sys.exit(main())