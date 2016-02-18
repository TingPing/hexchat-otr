#!/usr/bin/python
#
# Uli Meis <a.sporto+bee@gmail.com>
#
# Just a short script to generate our FORMAT_REC
#

import sys,os,re

lines = map(lambda x: x.strip(),open(sys.argv[1],"r").readlines())

if len(sys.argv) > 2:
	out_dir = sys.argv[2]
else:
	out_dir = "."
hdr = open(os.path.join(out_dir, "otr-formats.h"), "w")
srcx = open(os.path.join(out_dir, "hexchat-formats.c"), "w")

srcx.write('#include "otr.h"\n');
srcx.write('FORMAT_REC formats[] = {\n\t')
srcx.write('{ MODULE_NAME, "otr" }')

hdr.write("enum\n{\n\t")
hdr.write("TXT_OTR_MODULE_NAME")

fills = 0

section = None

for line in lines:
	srcx.write(",\n\t")

	e = line.split("\t")

	if len(e)==1:
		# Section name
		section = e[0]
		srcx.write("""{ NULL, "%s" }""" % (e[0]))

		hdr.write(",\n\tTXT_OTR_FILL_%d" % fills)
		
		fills += 1

		continue

	params = []
	fo = e[1]
	new = ""
	last=0
	i=0
	srcx.write("""{ "%s", "%s" """ % (e[0],fo.replace("%%9","").replace("%9","").replace("%g","").replace("%n","")))
	for m in re.finditer("(^|[^%])%([0-9]*)[ds]",fo):
		if m.group()[-1]=='d':
			params += ['1']
		else:
			params += ['0']
		new += fo[last:m.start()+len(m.group(1))].replace('%%','%')+"$"
		if m.group(2): new+= "[%s]" % m.group(2)
		new += "%d" % i
		last = m.end()
		i += 1

	new += fo[last:].replace('%%','%')

	e[1] = new
	e += [len(params)] + params

	#print "Handling line %s with elen %d" % (line,len(e))

	premsg = ""
	if e[1][0] != "{" and section!="Nickignore" and section!="Contexts":
		premsg = "%9OTR%9: "

	srcx.write("}")

	hdr.write(",\n\t")

	hdr.write("TXT_%s" % e[0].upper())

hdr.write("""
};

extern FORMAT_REC formats[];
""")

srcx.write(""",
\t{ NULL, NULL }
};

G_STATIC_ASSERT (G_N_ELEMENTS(formats) - 1 == TXT_ST_UNKNOWN + 1);
""")

hdr.close()
srcx.close()
