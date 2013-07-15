# 
# namcap rules - blackarchgroups
# Copyright (C) 2013 Evan Teitelman <teitelmanevan@gmail.com>
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

"""Verifies that a package is in the 'blackarch' group and one secondary group."""

import re
from Namcap.ruleclass import *

class BlackarchGroupsRule(PkgbuildRule):
	name = "blackarchgroups"
	description = "Verifies that a package is in the 'blackarch' group and one secondary group."
	def analyze(self, pkginfo, tar):
		primary_group = 'blackarch'
		secondary_groups = ['blackarch-analysis', 'blackarch-exploitation',
		      'blackarch-forensics', 'blackarch-intel', 'blackarch-defensive',
		      'blackarch-threat-model', 'blackarch-web-apps', 'blackarch-password-attacks',
		      'blackarch-wireless', 'blackarch-stress-testing', 'blackarch-reversing']
		nsecondary_needed = 1

		has_groups = False
		nsecondary = 0
		for i in pkginfo.pkgbuild:
			m = re.match(r'groups=\((.*)\)', i)

			# No match.
			if m == None:
				continue

			has_groups=True
			# Split array, remove quotation marks and whitespace.
			items = [re.sub("['\"\s]", '', i) for i in m.group(1).split(' ')]

			# Check for primary group.
			if primary_group not in items:
				self.warnings.append(("not-in-primary-group (%s)", primary_group))
			else:
				items.pop(items.index(primary_group))

			# Check for items.
			for j in items:
				if j not in secondary_groups:
					self.warnings.append(("group-invalid %s", j))
				else:
					nsecondary += 1
			# One check is enough.
			break
		if not has_groups:
			self.warnings.append(("no-groups", ()))
		elif nsecondary < nsecondary_needed:
			self.warnings.append(("not-enough-secondary-groups %s", nsecondary_needed))

# vim: set ts=4 sw=4 noet:
