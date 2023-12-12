#!/usr/bin/env python
import sys,json
try:
	import yaml
except:
	print('Require yaml module !')
	print('pip install pyyaml')
	exit(1)

gpoYamlRules = ''
with open("src/GPO-rules.yaml", "r") as fp:
	try:
		gpoYamlRules = yaml.safe_load(fp)
	except yaml.YAMLError as exc:
		print(exc)
		sys.stdin.readline()
		exit(1)


ui    = open('src/UI.html','r').read()
ui = ui.replace('{GPO-rules.yaml}', json.dumps(gpoYamlRules,indent=4))
open('bin/GPO-Generator.html','w').write(ui)