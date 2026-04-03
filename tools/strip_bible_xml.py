#!/usr/bin/env python3
"""Strip XML from Bible AKJV and produce plain text.

Usage: python3 strip_bible_xml.py <input.xml> <output.txt>
"""
import xml.etree.ElementTree as ET
import sys

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input.xml> <output.txt>", file=sys.stderr)
    sys.exit(1)

tree = ET.parse(sys.argv[1])
root = tree.getroot()

text = []
for verse in root.iter('{http://www.bibletechnologies.net/2003/OSIS/namespace}verse'):
    ref = verse.get('osisID', '')
    content = ''.join(verse.itertext()).strip()
    if content:
        text.append(f'{ref} {content}')

output = '\n'.join(text)
with open(sys.argv[2], 'w') as f:
    f.write(output)

print(f"Wrote {sys.argv[2]}: {len(text)} verses, {len(output)} bytes ({len(output)/1024/1024:.2f} MiB)", file=sys.stderr)
