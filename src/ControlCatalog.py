#!/usr/bin/python
# -*- coding: utf-8 -*- 

# RMT - Risk Management Tool
# Copyright (C) 2014  Stjepan Groš <stjepan.gros@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys

import xmltodict

class ControlCatalogException(Exception): pass
class ControlCatalogDuplicateIDException(ControlCatalogException): pass

class Control:
	"""
	Class that represents a single control.
	"""

	def __init__(self, data):
		"""
		Initialize class from XML data read by xmltodict parser
		"""
		self.controlClass = data['control-class']
		self.family = data['family']
		self.number = data['number']
		self.title = data['title']
		try:
			self.priority = data['priority']
		except KeyError:
			self.priority = None

		self.description = data['description']
		try:
			self.supplementalGuidance = data['supplemental-guidance']
		except KeyError:
			self.supplementalGuidance = None
		try:
			self.controlEnhancements = data['control-enhancements']
		except KeyError:
			self.controlEnhancements = None
			
		try:
			self.objectives = data['objectives']
		except KeyError:
			self.objectives = None

		self.references = {}
		if not data.has_key('references'):
			return

		if isinstance(data[u'references'][u'reference'], list):
			for reference in data[u'references'][u'reference']:
				self.references[reference[u'@href']] = reference[u'#text']
		else:
			self.references[data[u'references'][u'reference'][u'@href']] = data[u'references'][u'reference'][u'#text']
#                        self.threatDescription[data['name']['@lang']] = data['name']['#text']

#			for reference in data['references']['reference']:
#				self.references[reference[u'@href']] = reference[u'#text']
#				print reference
#		except KeyError:
#			pass

	def __str__(self):
		return self.getName(lang='hr')

	def getId(self):
		return self.number

	def getTitle(self):
		return unicode(self.title)

	def getDescription(self, lang="hr"):
		try:
			return unicode(self.threatDescription[lang])
		except KeyError:
			return unicode(self.threatDescription['en'])

class ControlCatalog:
	"""
	Class holding all the threats from the catalog.
	"""

	def __init__(self):
		self.controls = []

	def loadFromXMLFile(self, xmlFile):
		self.controls = []
		self.addFromXMLFile(xmlFile)

	def addFromXMLFile(self, xmlFile):

		data = xmltodict.parse(open(xmlFile))

		for controlData in data[u'ns3:controls'][u'ns3:control']:
			c = Control(controlData)
			self.controls.append(c)

	def getControls(self):
		return self.controls

def main(xmlFile):
	controlCatalog = ControlCatalog()
	controlCatalog.loadFromXMLFile(xmlFile)

	for control in controlCatalog.getControls():
		print(u"{} {}".format(control.getId(), control.getTitle()))

if __name__ == '__main__':
	main(sys.argv[1])
