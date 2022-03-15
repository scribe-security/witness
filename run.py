#!/usr/bin/env python3
from sys import stdout, argv
import json
import yaml
from base64 import b64decode
from subprocess import check_call, DEVNULL
from tempfile import NamedTemporaryFile

if len(argv) == 1:
	print('Usage: {} command [args...]'.format(argv[0]))
	exit(0)

check_call('make', stdout=DEVNULL)
with NamedTemporaryFile() as f:
	check_call( ['bin/witness', 'run', '--trace', '-k', 'examples/log4shell/demokey.pem', '-s', 'STEP_NAME', '-o', f.name, '--', *argv[1:]] )
	data = json.load(f)
payload = b64decode( data['payload'] )
intoto = json.loads(payload)
att = intoto['predicate']['attestations']
for a in att:
	if a['type'].startswith('https://witness.dev/attestations/command-run/'):
		for p in a['attestation']['processes']:
			print('Process #{} {}:'.format(p['processid'], p['program']))
			def printFiles(name, key):
				if key in p:
					print('  {}:'.format(name))
					for path, digests in p[key].items():
						print('    {} {}'.format(digests['sha256'], path))
			printFiles('Read', 'openedfiles')
			printFiles('Write', 'writtenfiles')