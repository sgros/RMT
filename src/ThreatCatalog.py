#!/usr/bin/python
# -*- coding: utf-8 -*- 

import sys

import xmltodict

class ThreatCatalogException(Exception): pass
class ThreatCatalogDuplicateIDException(ThreatCatalogException): pass

class Threat:
	"""
	Class that represents a single threat.
	"""

	def __init__(self, threatGroup, data):
		"""
		Initialize class from XML data read by xmltodict parser
		"""
		self.threatId = data['@id']
		self.threatGroup = threatGroup

		self.threatName = {}
		if isinstance(data['name'], list):
			for name in data['name']:
				self.threatName[name['@lang']] = name['#text']
		else:
			self.threatName[data['name']['@lang']] = data['name']['#text']

		self.threatDescription = {}
		if data.has_key('description'):
			if isinstance(data['description'], list):
				for name in data['description']:
					self.threatDescription[name['@lang']] = name['#text']
			else:
				self.threatDescription[data['name']['@lang']] = data['name']['#text']
	def __str__(self):
		return self.getName(lang='hr')

	def getId(self):
		return self.threatId

	def getName(self, lang="hr"):
		try:
			return unicode(self.threatName[lang])
		except KeyError:
			return unicode(self.threatName['en'])

	def getDescription(self, lang="hr"):
		try:
			return unicode(self.threatDescription[lang])
		except KeyError:
			return unicode(self.threatDescription['en'])

class ThreatGroup:
	"""
	Class that represents a single threat group.
	"""

	def __init__(self, data):
		"""
		Initialize threat group from data. This data is XML fragment from
		XML file converted using xmltodict 
		"""

		self.threatGroupId = data['@id']
		self.isAdversarial = data['@adversary']

		self.threatGroupName = {}
		if isinstance(data['name'], list):

			for name in data['name']:
				self.threatGroupName[name['@lang']] = name['#text']

		else:
			self.threatGroupName[data['name']['@lang']] = data['name']['#text']

		self.threats = []
		for threat in data[u'threat']:
			self.threats.append(Threat(self, threat))

	def getId(self):
		return self.threatGroupId

	def getName(self, lang="hr"):
		try:
			return unicode(self.threatGroupName[lang])
		except KeyError:
			return unicode(self.threatGroupName['en'])

	def getThreats(self):
		return self.threats

class ThreatCatalog:
	"""
	Class holding all the threats from the catalog.
	"""

	def __init__(self):
		self.threatGroups = []
		self.threatGroupsById = {}

		self.threats = []
		self.threatsById = {}

	def loadFromXMLFile(self, xmlFile):
		self.threatGroups = []
		self.threatGroupsById = {}
		self.threats = []
		self.threatsById = {}
		self.addFromXMLFile(xmlFile)

	def addFromXMLFile(self, xmlFile):

		def _parseThreatGroup(threatGroupData):

			t = ThreatGroup(threatGroupData)
			self.threatGroups.append(t)
			self.threatGroupsById[t.getId()] = t

			for threat in t.getThreats():
				self.threats.append(threat)
				self.threatsById[threat.getId()] = threat

		data = xmltodict.parse(open(xmlFile))

		if isinstance(data[u'threat-catalog'][u'threat-group'], list):
			for threatGroup in data[u'threat-catalog'][u'threat-group']:
				_parseThreatGroup(threatGroup)

		else:
			_parseThreatGroup(data[u'threat-catalog'][u'threat-group'])

	def getThreatGroups(self):
		return self.threatGroups

	def getThreats(self):
		return self.threats

	def getThreatGroupById(self, threatGroupId):
		return self.threatGroupsById[threatGroupId]

	def getThreatById(self, threatId):
		return self.threatsById[threatId]

def main(xmlFile):
	threatCatalog = ThreatCatalog()
	threatCatalog.loadFromXMLFile(xmlFile)

	for threatGroup in threatCatalog.getThreatGroups():
		print(u"{} {}".format(threatGroup.getId(), threatGroup.getName()))

		for threat in threatGroup.getThreats():
			print(u"\t{} {}".format(threat.getId(), threat.getName()))

if __name__ == '__main__':
	main(sys.argv[1])
