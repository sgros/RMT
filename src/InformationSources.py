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

import sys, traceback

import xmltodict

from ThreatSources import ThreatSources

class NotImplemented(Exception): pass

class InformationSourcesException(Exception): pass
class UnknownInformationSourceType(InformationSourcesException): pass
class InformationSourcesDuplicateIDException(InformationSourcesException): pass

class IdentifiedThreatSource:
	"""
	Class that holds a single identified threat
	"""

	def __init__(self, data):
		"""
		Initialize class from XML data read by xmltodict parser
		"""
		self.threatSourceId = data['@id']

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

	def getID(self):
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

class IdentifiedThreat:
	"""
	Class that holds a single identified threat
	"""
	def __init__(self, data, informationSource, resource):
		self.informationSource = informationSource
		self.resource = resource
		self.threat = self.informationSource.getThreatById(data['@threat-id'])
		try:
			self.threatSource = self.informationSource.getResourceById(data['@threat-source-id'])
		except KeyError:
			self.threatSource = self.informationSource.getThreatSourceById(data['@threat-source-id'])

		try:
			self.threatSourceRelevance = int(data['@threat-source-relevance'])
		except KeyError:
			self.threatSourceRelevance = 0
		try:
			self.probability = int(data['@probability'])
		except KeyError:
			self.probability = 0
		try:
			self.impact = int(data['@impact'])
		except KeyError:
			self.impact = 0

	def getInformationSourceId(self):
		return self.informationSourceId

	def getThreat(self):
		return self.threat

	def getThreatSource(self):
		return self.threatSource

	def getResource(self):
		return self.resource

	def setInformationSource(self, informationSource):
		self.informationSource = informationSource

	def getInformationSource(self):
		return self.informationSource

	def getId(self):
		return self.id

	# These are proxie methods to embedded objects
	def getThreatName(self, lang = "hr"):
		if self.threat is None:
			threatCatalog = self.informationSource.getThreatCatalog()
			self.threat = threatCatalog.getThreatById(self.threatId)

		return self.threat.getName(lang)

	def getThreatSourceName(self, lang):
		return self.threatSource.getName(lang)

	def getThreatSourceRelevance(self):
		return self.threatSourceRelevance

	def getResourceName(self, lang):
		return self.resource.getName(lang)

	def getProbability(self):
		return self.probability

	def getImpact(self):
		return self.impact

class IdentifiedVulnerability:
	"""
	Class with all identified vulnerabilities.
	"""
	def __init__(self, data, informationSource, resource):
		self.vulnerability = informationSource.getVulnerabilityById(data['@vulnerability-id'])
		self.informationSource = informationSource
		self.severity = int(data['@severity'])
		self.resource = resource

	def getResource(self):
		return self.resource

	def getVulnerability(self):
		return self.vulnerability

	def getSeverity(self):
		return self.severity

	def getSource(self):
		return self.source

	def getId(self):
		return self.id

	def getDate(self):
		return self.date

	# These are proxie methods to embedded objects
	def getVulnerabilityName(self, lang = "hr"):
		return self.vulnerability.getName(lang)

	def getResourceName(self, lang = "hr"):
		return self.resource.getName(lang)

class IdentifiedRisk():

	def __init__(self, identifiedVulnerability, identifiedThreat, resource):
		self.identifiedVulnerability = identifiedVulnerability
		self.identifiedThreat = identifiedThreat
		self.resource = resource

	def getIdentifiedVulnerability(self):
		return self.identifiedVulnerability

	def getIdentifiedThreat(self):
		return self.identifiedThreat

	def getResource(self):
		return self.resource

	def _getValue(self):
		"""
		Return quantitative risk value
		"""
		return (self.identifiedVulnerability.getSeverity() *
				self.identifiedThreat.getThreatSourceRelevance() *
				self.identifiedThreat.getProbability() *
				self.identifiedThreat.getImpact() / 1000.0)

	def getValue(self):
		"""
		Return quantitative risk value
		"""
		return int(round(self._getValue()))

	def getValueNormalizedToResource(self, normalizationResource):
		"""
		Return quantitative risk value
		"""
		return int(round(self._getValue() * self.resource.getBasicValue() / normalizationResource.getBasicValue))

	########################################################################
	# Proxy methods
	########################################################################

	def getResourceName(self):
		return self.resource.getName()

	def getVulnerabilityName(self):
		return self.identifiedVulnerability.getVulnerabilityName()

	def getVulnerabilitySeverity(self):
		return self.identifiedVulnerability.getSeverity()

	def getThreatName(self):
		return self.identifiedThreat.getThreatName()

	def getThreatProbability(self):
		return self.identifiedThreat.getProbability()

	def getThreatImpact(self):
		return self.identifiedThreat.getImpact()

	def getThreatSourceName(self, lang):
		return self.identifiedThreat.getThreatSourceName(lang)

	def getThreatSourceRelevance(self, lang):
		return self.identifiedThreat.getThreatSourceRelevance(lang)

class InformationSource():
	"""
	This class holds information about a single information source that
	is used to identify threat sources, threats and/or vulnerabilities.
	"""

	def __parseNewThreatSource(self, data, identifiedThreatSourcesByID):
		if isinstance(data, list):
			for xmlFragment in data:
				its = IdentifiedThreatSource(xmlFragment)
				identifiedThreatSourcesByID[its.getID()] = its
		else:
			its = IdentifiedThreatSource(data['threat-source'])
			identifiedThreatSourcesByID[its.getID()] = its

	def __parseNewThreats(self, data, identifiedThreatsByID):
		if isinstance(data, list):
			for xmlFragment in data:
				it = IdentifiedThreat(xmlFragment)
				identifiedThreatsByID[it.getID()] = it
		else:
			it = IdentifiedThreat(data['threat-source'])
			identifiedThreatsByID[it.getID()] = it

	def __parseNewVulnerabilities(self, data, identifiedVulnerabilitiesByID):
		if isinstance(data, list):
			for xmlFragment in data:
				iv = IdentifiedVulnerability(xmlFragment)
				identifiedVulnerabilitiesByID[iv.getID()] = iv
		else:
			iv = IdentifiedVulnerability(data['threat-source'])
			identifiedVulnerabilitiesByID[iv.getID()] = iv

	def __parseIdentifiedThreats(self, data, threats, threatSources, informationSource, resource):

		localyIdentifiedThreats = []

		if isinstance(data['threat'], list):
			for threat in data['threat']:
				it = IdentifiedThreat(threat, informationSource, resource)
				localyIdentifiedThreats.append(it)
				threats.add(it.getThreat())
				threatSource = it.getThreatSource()
				if threatSource:
					threatSources.add(threatSource)

				resource.addThreat(it.getThreat())

		else:
			it = IdentifiedThreat(data['threat'], informationSource, resource)
			localyIdentifiedThreats.append(it)
			threats.add(it.getThreat())
			threatSource = it.getThreatSource()
			if threatSource:
				threatSources.add(threatSource)
			resource.addThreat(it.getThreat())

		return localyIdentifiedThreats

	def __parseIdentifiedVulnerabilities(self, data, vulnerabilities, informationSource, resource):

		localyIdentifiedVulnerabilities = []

		if isinstance(data['vulnerability'], list):
			for vulnerability in data['vulnerability']:
				iv = IdentifiedVulnerability(vulnerability, informationSource, resource)
				localyIdentifiedVulnerabilities.append(iv)
				vulnerabilities.add(iv.getVulnerability())

				resource.addVulnerability(iv.getVulnerability())

		else:
			iv = IdentifiedVulnerability(data['vulnerability'], informationSource, resource)
			localyIdentifiedVulnerabilities.append(iv)
			vulnerabilities.add(iv.getVulnerability())

			resource.addVulnerability(iv.getVulnerability())

		return localyIdentifiedVulnerabilities

	def __parseRiskElement(self, data, identifiedThreats, threats, threatSources, identifiedVulnerabilities, vulnerabilities, resources, identifiedRisks, informationSource):

		resourceId = data['@resource-id']
		resource = self.getResourceById(resourceId)
		self.resources.add(resource)

		localyIdentifiedThreats = []
		localyIdentifiedVulnerabilities = []

		if data.has_key('threats'):
			localyIdentifiedThreats = self.__parseIdentifiedThreats(data['threats'], threats, threatSources, informationSource, resource)
			identifiedThreats.extend(localyIdentifiedThreats)

		if data.has_key('vulnerabilities'):
			localyIdentifiedVulnerabilities = self.__parseIdentifiedVulnerabilities(data['vulnerabilities'], vulnerabilities, informationSource, resource)
			identifiedVulnerabilities.extend(localyIdentifiedVulnerabilities)

		for vuln in localyIdentifiedVulnerabilities:
			for threat in localyIdentifiedThreats:
				identifiedRisks.append(IdentifiedRisk(vuln, threat, resource))

	def __parseChangeLogs(self, data, changeLogs):

		if isinstance(data['changelog'], list):
			for changelog in data['changelog']:
				changeLogs.append({'date': changelog['@date'], 'user': changelog['@user'], 'logEntry': changelog['#text']})

		else:
			changeLogs.append({'date': data['changelog']['@date'], 'user': data['changelog']['@user'], 'logEntry': data['changelog']['#text']})

	def __init__(self, informationSourcesCollection, data):
		"""
		Initialize class from XML data read by xmltodict parser
		"""

		# This is a collection class, that holds all Information sources. The important
		# point is that it has access to catalogs and threat sources that are necessary
		# to obtain information.
		self.informationSourcesCollection = informationSourcesCollection

		# All identified threats, vulnerabilities and risks
		self.identifiedThreats = []
		self.identifiedVulnerabilities = []
		self.identifiedRisks = []

		# Threats, vulnerabilities, and risks indexed by resource
		self.identifiedThreatsByResource = {}
		self.identifiedVulnerabilitiesByResource = {}
		self.identifiedRisksByResource = {}

		# Sets of all identified vulnerabilities, threats, threat sources, and resources from the catalogs
		self.vulnerabilities = set()
		self.threats = set()
		self.threatSources = set()
		self.resources = set()

		self.sourceId = data['@id']
		self.sourceType = data['@type']
		self.sourceDate = data['@date']
		try:
			self.relevanceType = data['@relevance-type']
		except KeyError:
			self.relevanceType = "constant"
		try:
			self.relevanceInitialValue = data['@initial-relevance']
		except KeyError:
			self.relevanceInitialValue = 0

		self.propertiesList = ['ID', 'Type', 'Date']

		self.sourceName = {}
		if isinstance(data['title'], list):

			for title in data['title']:
				self.sourceName[title['@lang']] = title['#text']

		else:
			self.sourceName[data['title']['@lang']] = data['title']['#text']

		self.propertiesList.append("Title")

		self.description = {}
		if data.has_key('description'):

			if isinstance(data['description'], list):

				for description in data['description']:
					self.description[title['@lang']] = description['#text']

			else:
					self.description[data['description']['@lang']] = data['description']['#text']

			self.propertiesList.append("Description")

		# Type specific processing
		if self.sourceType == "internal_report":

			try:
				self.author = data['author']
			except KeyError:
				self.author = "UNKNOWN"

			self.propertiesList.append("Type")

		elif self.sourceType == "sysaid":
			pass

		elif self.sourceType == "microsoft_advisory":
			self.propertiesList.append("Microsoft ID")

		elif self.sourceType == "adobe_advisory":

			self.propertiesList.append("Adobe ID")

			self.url = []
			if isinstance(data['url'], list):
				for url in data['url']: self.url.append(url)
			else:
				self.url.append(data['url'])

			if len(self.url): self.propertiesList.append("URL")

			try:
				self.cve = data['@cveid']
				self.propertiesList.append("CVE")
			except KeyError:
				self.cve = "UNKNOWN"

		elif self.sourceType == "personal_correspodence":
			pass

		elif self.sourceType == "webpage":

			self.url = []
			if isinstance(data['url'], list):
				for url in data['url']: self.url.append(url)
			else:
				self.url.append(data['url'])

			if len(self.url): self.propertiesList.append("URL")

		else:
			raise UnknownInformationSourceType(self.sourceType)

		################################################################
		# Parse identified threat sources
		################################################################
		if data.has_key('threat-sources'):
			self.__parseNewThreatSource(data['threat-sources'], self.informationSourcesCollection.identifiedThreatSourcesByID)

		################################################################
		# Parse identified threats
		################################################################
		if data.has_key('threats'):
			self.__parseNewThreats(data['threats'], self.informationSourcesCollection.identifiedThreatsByID)

		################################################################
		# Parse identified vulnerabilities
		################################################################
		if data.has_key('vulnerabilities'):
			self.__parseNewVulnerabilities(data['threat-sources'], self.informationSourcesCollection.identifiedVulnerabilitiesByID)

		################################################################
		# Parse identified risks
		################################################################
		if data.has_key('risks'):

			if data['risks'].has_key('risk'):
				if isinstance(data['risks']['risk'], list):
					for risk in data['risks']['risk']:
						self.__parseRiskElement(risk, self.identifiedThreats,
							self.threats, self.threatSources,
							self.identifiedVulnerabilities,
							self.vulnerabilities, self.resources,
							self.identifiedRisks, self)

				else:
					self.__parseRiskElement(data['risks']['risk'],
							self.identifiedThreats,
							self.threats,
							self.threatSources,
							self.identifiedVulnerabilities,
							self.vulnerabilities,
							self.resources,
							self.identifiedRisks,
							self)

			if data['risks'].has_key('threats'):
				resource = self.getResourceById(data['risks']['threats']['@resource-id'])
				localyIdentifiedThreats = self.__parseIdentifiedThreats(data['risks']['threats'],
									self.threats, self.threatSources, self, resource)
				self.identifiedThreats.extend(localyIdentifiedThreats)

			if data['risks'].has_key('vulnerabilities'):
				resource = self.getResourceById(data['risks']['vulnerabilities']['@resource-id'])
				localyIdentifiedVulnerabilities = self.__parseIdentifiedVulnerabilities(data['risks']['vulnerabilities'],
									self.vulnerabilities, self, resource)
				self.identifiedVulnerabilities.extend(localyIdentifiedVulnerabilities)

		################################################################
		# Parse changelog entries
		################################################################
		self.changeLogs = []
		if data.has_key('changelogs'):
			self.__parseChangeLogs(data['changelogs'], self.changeLogs)

		################################################################
		# Index identified risks by resource
		################################################################
		for risk in self.identifiedRisks:
			resource = risk.getResource()

			if not self.identifiedRisksByResource.has_key(resource):
				self.identifiedRisksByResource[resource] = []

			self.identifiedRisksByResource[resource].append(risk)

	########################################################################
	##
	## Different getter/setter methods
	##
	########################################################################

	def getProperties(self):
		return self.propertiesList

	def getPropertyAsStrOrList(self, propertyName):

		if propertyName == "ID":
			return self.sourceId
		elif propertyName == "Type":
			return self.sourceType
		elif propertyName == "Date":
			return self.sourceDate
		elif propertyName == "Title":
			return self.getName(lang="hr")
		elif propertyName == "URL":
			return self.url
		elif propertyName == "CVE":
			return self.cve
		elif propertyName == "Description":
			return self.getDescription(lang="hr")

		return "N/A"

	def getName(self, lang="en"):
		try:
			return unicode(self.sourceName[lang])
		except KeyError:
			return unicode(self.sourceName['en'])

	def getDescription(self, lang="en"):
		try:
			return unicode(self.description[lang])
		except KeyError:
			return unicode(self.description['en'])

	def getId(self):
		return self.sourceId

	def getType(self):
		return self.sourceType

	def getDate(self):
		return self.sourceDate

	def getUrl(self):
		try:
			return self.url
		except AttributeError:
			traceback.print_exc(file=sys.stdout)
			return None

	def getRelevanceType(self):
		return self.relevanceType

	def getRelevanceValue(self):
		return self.relevanceInitialValue

	def getIdentifiedThreats(self):
		return self.identifiedThreats

	def getIdentifiedVulnerabilities(self):
		return self.identifiedVulnerabilities

	def getThreats(self):
		return self.threats

	def getVulnerabilities(self):
		return self.vulnerabilities

	def getResources(self):
		return self.resources

	def getThreatSources(self):
		return self.threatSources

	def getIdentifiedRisks(self):
		return self.identifiedRisks

	def getIdentifiedRisksByResource(self, orderByMethod = None):
		if orderByMethod is not None:
			return sorted(self.identifiedRisksByResource, key=orderByMethod)

		return self.identifiedRisksByResource

	def getChangeLogs(self):
		return self.changeLogs

	########################################################################
	##
	## Proxy methods. These methods are used to access embedded objects
	## so that external methods don't access them directly and in that
	## way know the internal structure of the class.
	##
	## Maybe there's a better way to do this with Python's features
	##
	########################################################################

	def getThreatSourceById(self, threatSourceId):
		return self.informationSourcesCollection.getThreatSourceById(threatSourceId)

	def getThreatById(self, threatId):
		return self.informationSourcesCollection.getThreatById(threatId)

	def getVulnerabilityById(self, vulnerabilityId):
		return self.informationSourcesCollection.getVulnerabilityById(vulnerabilityId)

	def getResourceById(self, resourceId):
		return self.informationSourcesCollection.getResourceById(resourceId)

class InformationSources:

	def __cleanLocalData(self):

		self.informationSources = []
		self.informationSourcesById = {}

		# All identified threats from the threat catalogs
		self.threats = set()

		# All identified vulnerabilities from the vulnerability catalogs
		self.vulnerabilities = set()

		self.informationSourcesByVulnerability = {}
		self.informationSourcesByThreat = {}

		self.identifiedThreatSourcesByID = {}
		self.identifiedThreatsByID = {}
		self.identifiedVulnerabilitiesByID = {}

		self.identifiedThreats = []
		self.identifiedVulnerabilities = []
		self.identifiedRisks = []

		self.identifiedRisksByResource = {}

	def __init__(self, threatSourcesCatalog, threatCatalog, vulnerabilityCatalog, resources):
		"""
		The argument to this function are objects that contain necessary
		information in order to fetch all the relevant data for each
		information source.
		"""

		self.__cleanLocalData()
		self.threatCatalog = threatCatalog
		self.threatSourcesCatalog = threatSourcesCatalog
		self.vulnerabilityCatalog = vulnerabilityCatalog
		self.resources = resources

	def loadFromXMLFile(self, xmlFile):
		self.__cleanLocalData()
		self.addFromXMLFile(xmlFile)

	# TODO: change xmlFile into xmlFileObject
	def addFromXMLFile(self, xmlFile):

		data = xmltodict.parse(open(xmlFile))

		for informationSource in data[u'information_sources']['information_source']:
			i = InformationSource(self, informationSource)

			isid = i.getId()
			if self.informationSourcesById.has_key(isid):
				raise InformationSourcesDuplicateIDException(isid)

			for vulnerability in i.getVulnerabilities():

				if not self.informationSourcesByVulnerability.has_key(vulnerability):
					self.informationSourcesByVulnerability[vulnerability] = []

				self.informationSourcesByVulnerability[vulnerability].append(i)
				self.vulnerabilities.add(vulnerability)

			for threat in i.getThreats():

				if not self.informationSourcesByThreat.has_key(threat):
					self.informationSourcesByThreat[threat] = []

				self.informationSourcesByThreat[threat].append(i)
				self.threats.add(threat)

			# Objects should be connected

                        self.informationSourcesById[isid] = i
			self.informationSources.append(i)

			self.identifiedThreats.extend(i.getIdentifiedThreats())
			self.identifiedVulnerabilities.extend(i.getIdentifiedVulnerabilities())
			self.identifiedRisks.extend(i.getIdentifiedRisks())

			risksByResource = i.getIdentifiedRisksByResource()
			for resource in risksByResource:

				if not self.identifiedRisksByResource.has_key(resource):
					self.identifiedRisksByResource[resource] = []

				self.identifiedRisksByResource[resource].extend(risksByResource[resource])

	def getInformationSources(self):
		return self.informationSources

	def getInformationSourceById(self, isid):
		return self.informationSourcesById[isid]

	def getInformationSourcesByVulnerability(self):
		return self.informationSourcesByVulnerability

	def getInformationSourcesByThreat(self):
		return self.informationSourcesByThreat

	def getThreats(self):
		return self.threats

	def getThreatSourcesCatalog(self):
		return self.threatSourcesCatalog

	def getVulnerabilities(self):
		return self.vulnerabilities

	def getIdentifiedThreats(self):
		return self.identifiedThreats

	def getIdentifiedVulnerabilities(self):
		return self.identifiedVulnerabilities

	def getIdentifiedRisks(self):
		return self.identifiedRisks

	def getIdentifiedRisksByResource(self, orderByMethod = None):
		return self.identifiedRisksByResource

	def getRiskForResource(self, mainResource, depth=-1, debugPrefix = None):
		"""
		Recursively add all the risks affecting given resource.

		When adding risk for a given resource, a formula elaborated on blog
		is used.
		"""

		cumulativeRisk = 0
		maxRiskValue = -1
		elements = 0

		if debugPrefix: print u"{}{}".format(debugPrefix, mainResource.getName())

		if self.identifiedRisksByResource.has_key(mainResource):

			elements = len(self.identifiedRisksByResource[mainResource])

			# Handle special case
			if elements != 0:
				for risk in self.identifiedRisksByResource[mainResource]:
					newRisk = risk.getValue()
					cumulativeRisk += newRisk
					if newRisk > maxRiskValue: maxRiskValue = newRisk

		if debugPrefix: print u"{}    cumulativeRisk={}".format(debugPrefix, cumulativeRisk)

		mainResourceBasicValue = mainResource.getBasicValue()
		if depth != 0 and mainResourceBasicValue is not None:

			# Next, recursively descend into lower level resources and for each
			# of them get its risk value and then add it to the risk on a given
			# resource
			for resource in mainResource.getIsComposedOfResources():
				dP = debugPrefix + "        " if debugPrefix else None
				newRisk = self.getRiskForResource(resource, depth - 1, dP)
				if newRisk == 0: continue

				elements += 1
				cumulativeRisk += int(round(newRisk * resource.getBasicValue() / mainResourceBasicValue))
				if newRisk > maxRiskValue: maxRiskValue = newRisk

			if debugPrefix: print u"{}    cumulativeRisk={}".format(debugPrefix, cumulativeRisk)

		# Handle special cases
		if elements == 0: return 0
		if elements == 1: return cumulativeRisk

		normalizedRisk = int(round(maxRiskValue + cumulativeRisk / maxRiskValue / (elements ** 0.5)))

		if normalizedRisk > 10: normalizedRisk = 10

		if debugPrefix: print u"{}    normalizedRisk={}".format(debugPrefix, normalizedRisk)

		return normalizedRisk

	########################################################################
	##
	## Proxy methods. These methods are used to access embedded objects
	## so that external methods don't access them directly and in that
	## way know the internal structure of the class.
	##
	## Maybe there's a better way to do this with Python's features
	##
	########################################################################

	def getThreatSourceById(self, threatSourceId):
		if self.identifiedThreatSourcesByID.has_key(threatSourceId):
			return self.identifiedThreatSourcesByID[threatSourceId]

		return self.threatSourcesCatalog.getThreatSourceById(threatSourceId)

	def getThreatById(self, threatId):
		return self.threatCatalog.getThreatById(threatId)

	def getVulnerabilityById(self, vulnerabilityId):
		return self.vulnerabilityCatalog.getVulnerabilityById(vulnerabilityId)

	def getResourceById(self, resourceId):
		return self.resources.getResourceById(resourceId)

def main(xmlFile):
	# This doesn't work!
	informationSources = InformationSources(None, None, None, None)
	informationSources.loadFromXMLFile(xmlFile)

	for iS in informationSources.getInformationSources():
		print(u"{} {}".format(iS.getId(), iS.getName(lang="hr")))

if __name__ == '__main__':
	main(sys.argv[1])
