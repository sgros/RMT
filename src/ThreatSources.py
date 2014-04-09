#!/usr/bin/python
# -*- coding: utf-8 -*- 

import sys, traceback

import xmltodict

class ThreatSourcesException(Exception): pass
class ThreatSourcesDuplicateIDException(ThreatSourcesException): pass
class ThreatSourcesNoIDException(ThreatSourcesException): pass

class ThreatSource:
	"""
	Class that represents a single threat source.
	"""

	def __init__(self, data):
		"""
		Initialize class from XML data read by xmltodict parser
		"""
		self.threatSourcesById = {}
		self.threatSources = []

		self.threatSourceId = data['@id']
		if data.has_key('@adversarial'):
			self.isAdversarial = data['@adversarial']

		self.threatSourceName = {}
		if isinstance(data['name'], list):
			for name in data['name']:
				self.threatSourceName[name['@lang']] = name['#text']
		else:
			self.threatSourceName[data['name']['@lang']] = data['name']['#text']

		self.threatSourceDescription = {}
		if data.has_key('description'):
			if isinstance(data['description'], list):
				for name in data['description']:
					self.threatSourceDescription[name['@lang']] = name['#text']
			else:
				self.threatSourceDescription[data['name']['@lang']] = data['name']['#text']

		# Recursively descent and parse all subsources...
		if data.has_key('threat-source'):

			if isinstance(data[u'threat-source'], list):
				for threatSource in data[u'threat-source']:
					ts = ThreatSource(threatSource)

					tsid = ts.getId()
					if self.threatSourcesById.has_key(tsid):
						raise ThreatSourcesDuplicateIDException(tsid)
					self.threatSourcesById[tsid] = ts

					self.threatSources.append(ts)
			else:
				ts = ThreatSource(data[u'threat-source'])

				tsid = ts.getId()
				if self.threatSourcesById.has_key(tsid):
					raise ThreatSourcesDuplicateIDException(tsid)
				self.threatSourcesById[tsid] = ts

				self.threatSources.append(ts)

	def __str__(self):
		return self.getName(lang='hr')

	def getId(self):
		return self.threatSourceId

	def getName(self, lang="hr"):
		try:
			return unicode(self.threatSourceName[lang])
		except KeyError:
			return unicode(self.threatSourceName['en'])

	def getDescription(self, lang="hr"):
		try:
			return unicode(self.threatSourceDescription[lang])
		except KeyError:
			return unicode(self.threatSourceDescription['en'])

	def getThreatSources(self):
		return self.threatSources

	def getThreatSourceById(self, threatSourceId):

		if self.threatSourcesById.has_key(threatSourceId):
			return self.threatSourcesById[threatSourceId]

		for threatSource in self.threatSources:
			try:
				return threatSource.getThreatSourceById(threatSourceId)
			except ThreatSourcesNoIDException:
				# We don't print trace here because there is still
				# possibility that the given source will be found
				# in some other data structures...
				pass

		# But, now we are certain there is not requested threat source and we
		# raise exception
		raise ThreatSourcesNoIDException(threatSourceId)

	def hasSubthreats(self):
		return len(self.threatSources) > 0

class ThreatSources:
	"""
	This class holds information about all known sources of threats.

	The idea is to preinitialize it with the sources from catalog when
	the risk management system is established. Those threat sources are
	in reality types, not specific threats.

	Then, as the system is used/evolved, specific instances of threat
	source are added.
	"""

	def __init__(self):
		self.threatSources = []
		self.threatSourcesById = {}


	def addXMLFragment(self, xmlFragment):
		self.addParsedXMLFragment(xmltodict.parse(xmlFragment))

	def addParsedXMLFragment(self, parsedXMLFragment):

		def _parseSingleThreatSource(threatSource):

			ts = ThreatSource(threatSource)

			tsid = ts.getId()
			if self.threatSourcesById.has_key(tsid):
				raise ThreatSourcesDuplicateIDException(tsid)
			self.threatSourcesById[tsid] = ts

			self.threatSources.append(ts)

		if isinstance(parsedXMLFragment[u'threat-sources'][u'threat-source'], list):

			for threatSource in parsedXMLFragment[u'threat-sources'][u'threat-source']:
				_parseSingleThreatSource(threatSource)
		else:
			_parseSingleThreatSource(parsedXMLFragment[u'threat-sources'][u'threat-source'])

	def loadFromXMLFile(self, xmlFile):
		self.threatSources = []
		self.threatSourcesById = {}
		self.addFromXMLFile(xmlFile)

	def addFromXMLFile(self, xmlFile):
		self.addXMLFragment(open(xmlFile))

	def getThreatSources(self):
		return self.threatSources

	def getThreatSourceById(self, threatSourceId):

		if self.threatSourcesById.has_key(threatSourceId):
			return self.threatSourcesById[threatSourceId]

		for threatSource in self.threatSources:
			try:
				return threatSource.getThreatSourceById(threatSourceId)
			except ThreatSourcesNoIDException:
				# We don't print trace here because there is still
				# possibility that the given source will be found
				# in some other data structures...
				pass

		# But, now we are certain there is not requested threat source and we
		raise ThreatSourcesNoIDException(threatSourceId)

def dumpThreatSources(prefix, threatSources):

	for threatSource in threatSources:
		print(prefix + u"{} {}".format(threatSource.getId(), threatSource.getName()))

		if threatSource.getThreatSources() != []:
			dumpThreatSources(prefix + "\t", threatSource.getThreatSources())

def main(xmlFile):
	threatSource = ThreatSources()
	threatSource.loadFromXMLFile(xmlFile)

	dumpThreatSources(u"", threatSource.getThreatSources())

if __name__ == '__main__':
	main(sys.argv[1])
