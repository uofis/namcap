# 
# namcap rules - depends
# Copyright (C) 2003-2007 Jason Chu <jason@archlinux.org>
# 
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 

import re, os, os.path, pacman

pkgcache = {}

def load(name, path=None):
	if not pkgcache.has_key(name):
		pkgcache[name] = pacman.load(name)
	return pkgcache[name]

libcache = {}

def getcovered(current, dependlist, covereddepend):
	if current == None:
		for i in dependlist:
			pac = load(i)
			if pac != None and pac.depends != None:
				for j in pac.depends:
					if j != None and not j in covereddepend.keys():
						covereddepend[j] = 1
						getcovered(j, dependlist, covereddepend)
	else:
		pac = load(current)
		if pac != None and pac.depends != None:
			for i in pac.depends:
				if i != None and not i in covereddepend.keys():
					covereddepend[i] = 1
					getcovered(i, dependlist, covereddepend)

def walkfunc(arg, dirname, names):
	for i in names:
		if os.path.isfile(dirname+'/'+i):
			var = os.popen3('readelf -d ' + dirname+'/'+i)
			for j in var[1].readlines():
				if re.search('Shared library',j) != None:
					n = re.search('Shared library: \[(.*)\]', j)
					if n != None:
						try:
							if not arg[0].has_key(os.path.abspath(libcache[n.group(1)])[1:]):
								arg[0][os.path.abspath(libcache[n.group(1)])[1:]] = {}
							arg[0][os.path.abspath(libcache[n.group(1)])[1:]][dirname+'/'+i] = 1
						except KeyError:
							# Ignore that library if we can't find it
							# TODO: review it
							pass
				# But we can check to see if it's a script we know about
				else:
					fd = open(dirname+'/'+i)
					firstline = fd.readline()
					if re.match('#!.*python',firstline) != None:
						if not arg[1].has_key('python'):
							arg[1]['python'] = {}
						arg[1]['python'][dirname+'/'+i] = 1
					elif re.match('#!.*perl',firstline) != None:
						if not arg[1].has_key('perl'):
							arg[1]['perl'] = {}
						arg[1]['perl'][dirname+'/'+i] = 1
					elif re.match('#!.*ruby',firstline) != None:
						if not arg[1].has_key('ruby'):
							arg[1]['ruby'] = {}
						arg[1]['ruby'][dirname+'/'+i] = 1
					elif re.match('#!.*bash',firstline) != None or re.match('#!.*sh',firstline) != None:
						if not arg[1].has_key('bash'):
							arg[1]['bash'] = {}
						arg[1]['bash'][dirname+'/'+i] = 1
					elif re.match('#!.*wish',firstline) != None:
						if not arg[1].has_key('tk'):
							arg[1]['tk'] = {}
						arg[1]['tk'][dirname+'/'+i] = 1
					elif re.match('#!.*expect',firstline) != None:
						if not arg[1].has_key('expect'):
							arg[1]['expect'] = {}
						arg[1]['expect'][dirname+'/'+i] = 1
					fd.close()
			var[0].close()
			var[1].close()
			var[2].close()
	return
			
def finddepends(liblist):
	dependlist = {}
	foundlist = []

	somatches = {}
	actualpath = {}

	for j in liblist.keys():
		actualpath[j] = os.path.realpath('/'+j)[1:]

	# Sometimes packages don't include all so .so, .so.1, .so.1.13, .so.1.13.19 files
	# They rely on ldconfig to create all the symlinks
	# So we will strip off the matching part of the files and use this regexp to match the rest
	so_end = re.compile('(\.\d+)*')

	pacmandb = '/var/lib/pacman/local'
	for i in os.listdir(pacmandb):
		if os.path.isfile(pacmandb+'/'+i+'/files'):
			file = open(pacmandb+'/'+i+'/files')
			for j in file.readlines():
				if j[len(j)-1:]=='\n':
					j = j[:len(j)-1]

				for k in liblist.keys():
					# If the file is an exact match, so it's a match up to a point and everything after that point matches a the regexp
					# i.e. gpm includes libgpm.so and libgpm.so.1.19.0, but everything links to libgpm.so.1
					# We compare find libgpm.so.1.19.0 startswith libgpm.so.1 and .19.0 matches the regexp
					if j == actualpath[k] or (j.startswith(actualpath[k]) and so_end.match(j[len(actualpath[k]):])):
						n = re.match('(.*)-([^-]*)-([^-]*)', i)
						if not dependlist.has_key(n.group(1)):
							dependlist[n.group(1)] = {}
						for x in liblist[k]:
							dependlist[n.group(1)][x] = 1
						foundlist.append(k)
			file.close()

	ret = []
	for i in liblist.keys():
		if i not in foundlist:
			ret.append('Library ' + i + ' has no package associated')
	return dependlist, ret

def getprovides(depends, provides):
	for i in depends.keys():
		pac = load(i)

		if pac != None and pac.provides != None:
			provides[i] = pac.provides

def filllibcache():
	var = os.popen3('ldconfig -p')
	for j in var[1].readlines():
		g = re.match('\s*(.*) \(.*\) => (.*)',j)
		if g != None:
			libcache[g.group(1)] = g.group(2)


class package:
	def short_name(self):
		return "depends"
	def long_name(self):
		return "Checks dependencies semi-smartly."
	def prereq(self):
		return "extract"
	def analyze(self, pkginfo, data):
		liblist = [{},{}]
		dependlist = {}
		smartdepend = {}
		smartprovides = {}
		covereddepend = {}
		pkgcovered = {}
		ret = [[],[],[]]
		filllibcache()
		os.environ['LC_ALL'] = 'C'
		os.path.walk(data, walkfunc, liblist)

		# Ldd all the files and find all the link and script dependencies
		dependlist, tmpret = finddepends(liblist[0])

		# Handle "no package associated" errors
		for i in tmpret:
			ret[1].append(i)

		# Do the script handling stuff
		for i, v in liblist[1].iteritems():
			if not dependlist.has_key(i):
				dependlist[i] = {}
			for j in v.keys():
				dependlist[i][j] = 1
			files = [x[len(data)+1:] for x in v.keys()]
			ret[2].append('Script link detected (' + i + ') in file ' + str(files))

		# Remove the package name from that list, we can't depend on ourselves.
		if dependlist.has_key(pkginfo.name):
			del dependlist[pkginfo.name]

		# Do the info stuff
		for i, v in dependlist.iteritems():
			if type(v) == dict:
				files = [x[len(data)+1:] for x in v.keys()]
				ret[2].append('File '+ str(files) +' link-level dependence on ' + i)

		# Check for packages in testing
		if os.path.isdir('/var/lib/pacman/testing'):
			for i in dependlist.keys():
				p = pacman.load(i, '/var/lib/pacman/testing/')
				q = load(i)
				if p != None and q != None and p.release == q.release and p.version == q.version:
					ret[1].append('Dependency ' + i + ' on your system is a testing release')

		# Find all the covered dependencies from the PKGBUILD
		pkgdepend = {}
		if pkginfo.depends != None:
			for i in pkginfo.depends:
				pkgdepend[i] = 1
		getcovered(None, pkgdepend, pkgcovered)

		# Do tree walking to find all the non-leaves (branches?)
		getcovered(None, dependlist, covereddepend)
		for i in covereddepend.keys():
			ret[2].append('Dependency covered by dependences from link dependence (' + i + ')')
		# Set difference them to find the leaves
		for i in dependlist.keys():
			if not i in covereddepend.keys():
				smartdepend[i] = 1

		# Get the provides so we can reference them later
		getprovides(dependlist, smartprovides)

		# Do the actual message outputting stuff
		for i in smartdepend.keys():
			# If (the PKGBUILD has dependencies 
			# and i isn't in them
			# and i isn't the package name
			# and ((there are provides for i
			# and those provides aren't included in the package's dependencies)
			# or there are no provides for i))
			# or the PKGBUILD has no dependencies
			if (pkginfo.depends != None and i not in pkginfo.depends and i != pkginfo.name and ((smartprovides.has_key(i) and len([c for c in smartprovides[i] if c in pkgcovered.keys()]) == 0) or not smartprovides.has_key(i))) or pkginfo.depends == None:
					if type(dependlist[i]) == dict:
						ret[0].append('Dependency detected and not included ('+i+') from files '+str([x[len(data)+1:] for x in dependlist[i].keys()]))
					else:
						ret[0].append('Dependency detected and not included ('+i+')')
		if pkginfo.depends != None:
			for i in pkginfo.depends:
				if covereddepend.has_key(i) and dependlist.has_key(i):
					ret[1].append('Dependency included but already satisfied ('+i+')')
				# if i is not in the depends as we see them and it's not in any of the provides from said depends
				elif not smartdepend.has_key(i) and i not in [y for x in smartprovides.values() for y in x]:
					ret[1].append('Dependency included and not needed ('+i+')')
		ret[2].append('Depends as namcap sees them: depends=('+ ' '.join(smartdepend.keys())+')')
		return ret
	def type(self):
		return "tarball"