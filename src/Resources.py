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

class ResourcesException(Exception): pass
class ResourcesDuplicateIDException(ResourcesException): pass
class ResourcesUnknownValueTypeException(ResourcesException): pass

class Resource():
	"""
	Class that represents a single resource.
	"""

	def __init__(self, data):
		"""
		Initialize class from XML data read by xmltodict parser
        
		resources parametar is a class with all the resources
		"""

		try:
			self.resourceId = data['@id']
			self.resourceBaseId = None
		except KeyError:
			self.resourceId = None
			self.resourceBaseId = data['@baseid']

		try:
			self.classification = data['@classification']
		except KeyError:
			self.classification = 'classified'

		self.vulnerabilities = set()
		self.threats = set()
		self.identifiedVulnerabilities = set()
		self.identifiedThreats = set()
		self.identifiedRisks = set()
		self.isInResources = set()
		self.hasResources = set()
		self.isPartOfResources = set()
		self.isComposedOfResources = set()
		self.storesResources = set()
		self.isStoredOn = set()
		self.usesResources = set()
		self.isUsedByResources = set()

		try:
			self.basicValueType = data['value']['@type']
			if self.basicValueType == 'absolute':
				self.basicValue = int(data['value']['#text'])
			else:
				raise ResourcesUnknownValueTypeException(self.valueType)
		except KeyError:
			self.basicValue = None
			self.basicValueType = None

		self.resourceName = {}
		if isinstance(data['name'], list):
			for name in data['name']:
				self.resourceName[name['@lang']] = name['#text']

		else:
			self.resourceName[data['name']['@lang']] = data['name']['#text']

		self.isInResourceIds = set()
		if data.has_key('isin'):
			if isinstance(data['isin'], list):
				for isIn in data['isin']:
					self.isInResourceIds.add(isIn['@resourceid'])

			else:
				self.isInResourceIds.add(data['isin']['@resourceid'])

		self.hasResourceIds = set()
		if data.has_key('has'):
			if isinstance(data['has'], list):
				for has in data['has']:
					self.hasResourceIds.add(has['@resourceid'])

			else:
				self.hasResourceIds.add(data['has']['@resourceid'])

		self.isPartOfResourceIds = set()
		if data.has_key('ispartof'):
			if isinstance(data['ispartof'], list):
				for isPartOf in data['ispartof']:
					try:
						share_type = isPartOf['@share_type']
						share = isPartOf['@share']
					except KeyError:
						share_type = share = None

					self.isPartOfResourceIds.add((isPartOf['@resourceid'], share_type, share))

			else:
				try:
					share_type = data['ispartof']['@share_type']
					share = data['ispartof']['@share']
				except KeyError:
					share_type = share = None

				self.isPartOfResourceIds.add((data['ispartof']['@resourceid'], share_type, share))

		self.isComposedOfResourceIds = set()
		if data.has_key('iscomposedof'):
			if isinstance(data['iscomposedof'], list):
				for isComposedOf in data['iscomposedof']:
					self.isComposedOfResourceIds.add(isComposedOf['@resourceid'])

			else:
				self.isComposedOfResourceIds.add(data['iscomposedof']['@resourceid'])

		self.storesResourceIds = set()
		if data.has_key('stores'):
			if isinstance(data['stores'], list):
				for stores in data['stores']:
					self.storesResourceIds.add(stores['@resourceid'])

			else:
				self.storesResourceIds.add(data['stores']['@resourceid'])

		self.isStoredOnResourceIds = set()
		if data.has_key('isstoredon'):
			if isinstance(data['isstoredon'], list):
				for has in data['isstoredon']:
					self.isStoredOnResourceIds.add(has['@resourceid'])

			else:
				self.isStoredOnResourceIds.add(data['isstoredon']['@resourceid'])

		self.usesResourceIds = set()
		if data.has_key('uses'):
			if isinstance(data['uses'], list):
				for stores in data['uses']:
					self.usesResourceIds.add(stores['@resourceid'])

			else:
				self.usesResourceIds.add(data['uses']['@resourceid'])

		self.isUsedByResourceIds = set()
		if data.has_key('isuseby'):
			if isinstance(data['isusedby'], list):
				for has in data['isusedby']:
					self.isUsedByResourceIds.add(has['@resourceid'])

			else:
				self.isUsedByResourceIds.add(data['isusedby']['@resourceid'])

	def _reconnectResources(self, resources):
		"""
		This method is called when all the resources were loaded to
		connect object into hierarchy (instead of IDs)
		"""
		for rid in self.isInResourceIds:
			r = resources.getResourceById(rid)
			self.isInResources.add(r)
			r.addHasResource(self)

		for rid in self.hasResourceIds:
			r = resources.getResourceById(rid)
			self.hasResources.add(r)
			r.addIsInResource(self)

		for rid in self.isPartOfResourceIds:
			r = resources.getResourceById(rid[0])
			self.isPartOfResources.add((r, rid[1], rid[2]))
			r.addIsComposedOfResource((self, rid[1], rid[2]))

		for rid in self.isComposedOfResourceIds:
			r = resources.getResourceById(rid)
			self.isComposedOfResources.add(r)
			r.addIsPartOfResource(self)

		for rid in self.storesResourceIds:
			r = resources.getResourceById(rid)
			self.storesResources.add(r)
			r.addIsStoredOnResource(self)

		for rid in self.isStoredOnResourceIds:
			r = resources.getResourceById(rid)
			self.isStoredOn.add(r)
			r.addStoresResource(self)

		for rid in self.usesResourceIds:
			r = resources.getResourceById(rid)
			self.usesResources.add(r)
			r.addIsUsedByResource(self)

		for rid in self.isUsedByResourceIds:
			r = resources.getResourceById(rid)
			self.isUsedByResources.add(r)
			r.addUsesResource(self)

	def addIsInResource(self, r):
		self.isInResources.add(r)

	def addHasResource(self, r):
		self.hasResources.add(r)

	def addIsPartOfResource(self, r):
		self.isPartOfResources.add(r)

	def addIsComposedOfResource(self, r):
		self.isComposedOfResources.add(r)

	def addIsStoredOnResource(self, r):
		self.isStoredOn.add(r)

	def addStoresResource(self, r):
		self.storesResources.add(r)

	def addUsesResource(self, r):
		self.usesResources.add(r)

	def addIsUsedByResource(self, r):
		self.isUsedByResources.add(r)

	def isSpecializationResource(self):
		return self.resourceBaseId is not None

	def specialize(self, resource):
		"""
		Specialize youself with values given in a temporary resource
		"""
		self.vulnerabilities.update(resource.vulnerabilities)
		self.isInResources.update(resource.isInResources)
		self.hasResources.update(resource.hasResources)
		self.isPartOfResources.update(resource.isPartOfResources)
		self.isComposedOfResources.update(resource.isComposedOfResources)
		if resource.basicValue is not None:
			self.basicValueType = resource.basicValueType
			self.basicValue = resource.basicValue
		for k, v in resource.resourceName.iteritems():
			self.resourceName[k] = v

		self.isInResourceIds.update(resource.isInResourceIds)
		self.hasResourceIds.update(resource.hasResourceIds)
		self.isPartOfResourceIds.update(resource.isPartOfResourceIds)
		self.isComposedOfResourceIds.update(resource.isComposedOfResourceIds)

	def getIsInResources(self):
		return self.isInResources

	def getHasResources(self):
		return self.hasResources

	def _getIsPartOfResources(self):
		return self.isPartOfResources

	def getIsPartOfResources(self):
		return [ x[0] for x in self.isPartOfResources ]

	def _getIsComposedOfResources(self):
		return self.isComposedOfResources

	def getIsComposedOfResources(self):
		return [ x[0] for x in self.isComposedOfResources ]

	def getStoresResources(self):
		return self.storesResources

	def getIsStoredOnResources(self):
		return self.isStoredOn

	def getUsesResources(self):
		return self.usesResources

	def getIsUsedByResources(self):
		return self.isUsedByResources

	def getName(self, lang = 'hr'):
		try:
			return unicode(self.resourceName[lang])
		except KeyError:
			return unicode(self.resourceName['en'])

	def getBasicValue(self):
		return self.basicValue

	def getStoredValue(self):
		return self.storedValue

	def getBasicValueOrZero(self):
		if self.basicValue is not None:
			return self.basicValue

		return 0

	def setStoredValue(self, value):
		self.storedValue = value

	def setBasicValue(self, value):
		self.basicValue = value

	def getNormalizedValue(self, resource):
		"""
		Value normalized to the value of the given resource.
        
		The given resource must be of type ispartof and it has to be
		higher in the hierarchy.
		"""
		return int(self.basicValue / resource.getBasicValue())

	def getId(self):
		return self.resourceId

	def getBaseId(self):
		return self.resourceBaseId

	def addVulnerability(self, vulnerability):
		self.vulnerabilities.add(vulnerability)

	def getVulnerabilities(self):
		return self.vulnerabilities

	def addThreat(self, threat):
		self.threats.add(threat)

	def getThreats(self):
		return self.threats


class Resources():
	"""
	Class holding all the resources and their dependencies.
	"""

	def __init__(self):
		self.resources = []
		self.resourcesById = {}
		self.topLevelResources = []

	def loadFromXMLFile(self, xmlFile):
		self.resources = []
		self.resourcesById = {}
		self.topLevelResources = []
		self.addFromXMLFile(xmlFile)

	def addFromXMLFile(self, xmlFile):

		def _parseResource(resourceData):
			r = Resource(resource)
			if r.isSpecializationResource():
				self.resourcesById[r.getBaseId()].specialize(r)
				return
			self.resources.append(r)
			rid = r.getId()
			if self.resourcesById.has_key(rid):
				raise ResourcesDuplicateIDException(rid)
			self.resourcesById[rid] = r

		data = xmltodict.parse(open(xmlFile))
		if isinstance(data[u'resources'][u'resource'], list):
			for resource in data[u'resources'][u'resource']:
				_parseResource(resource)

		else:
			_parseResource(data[u'resources'][u'resource'])
		self._reconnectResources()

		for r in self.resources:
			if len(r.getIsPartOfResources()) == 0:
				self.topLevelResources.append(r)

		for resource in self.getTopLevelResources():
			self._recalculateValues(resource)

	def _reconnectResources(self):
		for resource in self.resources:
			resource._reconnectResources(self)

	def _recalculateValues(self, resource):
		"""
		This internal method is called when all the resources are
		loaded to recalculate values based on data provided and
		hierarcy.
        
		To calculate value currently supported relationships are:
        
			is-part-of (is-composed-of)
        
			stores (is-stored-on)
        
		"""

		def _recalculateIsPartOfValues():
			remainingValue = resourceValue = resource.getBasicValue()
			resources = resource._getIsComposedOfResources()

			if not resourceValue or len(resources) == 0:
				return

			remainingResources = []

			for r in resources:
				if r[1] is None or r[2] is None:
					remainingResources.append(r[0])
					continue

				rValue = int(round(resourceValue * float(r[2]) / 100))
				r[0].setBasicValue(rValue)
				remainingValue -= rValue
				if remainingValue < 0:
					raise
				self._recalculateValues(r[0])

			if len(remainingResources):
				defaultSubresourceValue = remainingValue / len(remainingResources)
				for r in remainingResources:
       					rValue = r.getBasicValue()
					if not rValue:
						rValue = defaultSubresourceValue
						r.setBasicValue(defaultSubresourceValue)
					self._recalculateValues(r)

		def _recalculateStoresValue():
			value = 0
			for storedResource in resource.getStoresResources():
				value += storedResource.getBasicValue() * 0.1

			resource.setStoredValue(value)

		_recalculateIsPartOfValues()
		_recalculateStoresValue()


	def getResources(self):
		return self.resources

	def getTopLevelResources(self):
		return self.topLevelResources

	def getResourceById(self, resourceId):
		return self.resourcesById[resourceId]


def _dumpResourceIsComposedOfTree(prefix, r, resources):
	sr = r.getIsComposedOfResources()
	print u'{} value={} subresources={}'.format(prefix + r.getName(), r.getValue(), len(sr))
	for res in sr:
		_dumpResourceIsComposedOfTree(prefix + '\t', res, resources)


def _dumpResourceHasTree(prefix, r, resources):
	print prefix + r.getName()
	for res in r.getHasResources():
		_dumpResourceHasTree(prefix + '\t', res, resources)

def main(xmlFile):
	resources = Resources()
	resources.loadFromXMLFile(xmlFile)
	_dumpResourceIsComposedOfTree('', resources.getResourceById('r00000'), resources)

if __name__ == '__main__':
	main(sys.argv[1])
