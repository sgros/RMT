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

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, PageBreak, Table, TableStyle

from InformationSources import InformationSources
from ThreatSources import ThreatSources
from ThreatCatalog import ThreatCatalog
from ControlCatalog import ControlCatalog
from Resources import Resources
from VulnerabilityCatalog import VulnerabilityCatalog

class RiskManagement:

	def loadManifestFile(self, manifestFileName):

		def _parseThreatSourcesFromManifest(data):

			threat_sources = []
			if isinstance(data['threat_source'], list):

				for ts in data['threat_source']:
					threat_sources.append(ts['@file'])
			else:
				threat_sources.append(data['threat_source']['@file'])

			return threat_sources

		def _parseVulnerabilityCatalogsFromManifest(data):

			vulnerability_catalogs = []
			if isinstance(data['vulnerability_catalog'], list):

				for ts in data['vulnerability_catalog']:
					vulnerability_catalogs.append(ts['@file'])
			else:
				vulnerability_catalogs.append(data['vulnerability_catalog']['@file'])

			return vulnerability_catalogs

		def _parseThreatCatalogsFromManifest(data):

			threat_catalogs = []
			if isinstance(data['threat_catalog'], list):

				for ts in data['threat_catalog']:
					threat_catalogs.append(ts['@file'])
			else:
				threat_catalogs.append(data['threat_catalog']['@file'])

			return threat_catalogs

		def _parseControlsCatalogsFromManifest(data):

			controls_catalogs = []
			if isinstance(data['controls_catalog'], list):

				for ts in data['controls_catalog']:
					controls_catalogs.append(ts['@file'])
			else:
				controls_catalogs.append(data['controls_catalog']['@file'])

			return controls_catalogs

		def _parseResourcesFromManifest(data):

			resources = []
			if isinstance(data['resource'], list):

				for ts in data['resource']:
					resources.append(ts['@file'])
			else:
				resources.append(data['resource']['@file'])

			return resources

		def _parseInformationSourcesFromManifest(data):

			information_sources = []
			if isinstance(data['information_source'], list):

				for ts in data['information_source']:
					information_sources.append(ts['@file'])
			else:
				information_sources.append(data['information_source']['@file'])

			return information_sources

		data = xmltodict.parse(open(manifestFileName))

		manifest = {}
		manifest['threat_sources'] = []
		manifest['vulnerability_catalogs'] = []
		manifest['threat_catalogs'] = []
		manifest['controls_catalogs'] = []
		manifest['resources'] = []
		manifest['information_sources'] = []

		if data[u'risk_management'].has_key('threat_sources'):
			manifest['threat_sources'] = _parseThreatSourcesFromManifest(data[u'risk_management']['threat_sources'])
		if data[u'risk_management'].has_key('vulnerability_catalogs'):
			manifest['vulnerability_catalogs'] = _parseVulnerabilityCatalogsFromManifest(data[u'risk_management']['vulnerability_catalogs'])
		if data[u'risk_management'].has_key('threat_catalogs'):
			manifest['threat_catalogs'] = _parseThreatCatalogsFromManifest(data[u'risk_management']['threat_catalogs'])
		if data[u'risk_management'].has_key('controls_catalogs'):
			manifest['controls_catalogs'] = _parseControlsCatalogsFromManifest(data[u'risk_management']['controls_catalogs'])
		if data[u'risk_management'].has_key('resources'):
			manifest['resources'] = _parseResourcesFromManifest(data[u'risk_management']['resources'])
		if data[u'risk_management'].has_key('information_sources'):
			manifest['information_sources'] = _parseInformationSourcesFromManifest(data[u'risk_management']['information_sources'])

		return manifest

	def __init__(self, xmlDir):

		self.manifest = self.loadManifestFile(xmlDir + '/manifest.xml')

		print "Loading threat sources..."
		self.threatSources = ThreatSources()
		for threat_source in self.manifest['threat_sources']:
			self.threatSources.addFromXMLFile(xmlDir + "/" + threat_source)

		print "Loading vulnerability catalog..."
		self.vulnerabilityCatalog = VulnerabilityCatalog()
		for vulnerability_catalog in self.manifest['vulnerability_catalogs']:
			self.vulnerabilityCatalog.addFromXMLFile(xmlDir + "/" + vulnerability_catalog)

		print "Loading threat catalog..."
		self.threatCatalog = ThreatCatalog()
		for threat_catalog in self.manifest['threat_catalogs']:
			self.threatCatalog.addFromXMLFile(xmlDir + "/" + threat_catalog)

		print "Loading controls catalog..."
		self.controlsCatalog = ControlCatalog()
		for controls_catalog in self.manifest['controls_catalogs']:
			self.controlsCatalog.addFromXMLFile(xmlDir + "/" + controls_catalog)

		print "Loading resources..."
		self.resources = Resources()
		for resource in self.manifest['resources']:
			self.resources.addFromXMLFile(xmlDir + "/" + resource)

		print "Loading information sources..."
		self.informationSources = InformationSources(self.threatSources, self.threatCatalog, self.vulnerabilityCatalog, self.resources)
		for information_source in self.manifest['information_sources']:
			self.informationSources.addFromXMLFile(xmlDir + "/" + information_source)

	def getInformationSources(self):
		return self.informationSources.getInformationSources()

	def getInformationSourcesByThreat(self):
		return self.informationSources.getInformationSourcesByThreat()

	def getThreats(self):
		return self.informationSources.getThreats()

	def getVulnerabilities(self):
		return self.informationSources.getVulnerabilities()

	def getIdentifiedThreats(self):
		return self.informationSources.getIdentifiedThreats()

	def getIdentifiedThreats(self):
		return self.informationSources.getIdentifiedThreats()

	def getIdentifiedThreatsByThreat(self):
		return self.informationSources.getIdentifiedThreatsByThreat()

	def getIdentifiedThreatsByThreatSource(self):
		return self.informationSources.getIdentifiedThreatsByThreatSource()

	def getIdentifiedThreatsByResource(self):
		return self.informationSources.getIdentifiedThreatsByResource()

	def getIdentifiedVulnerabilities(self):
		return self.informationSources.getIdentifiedVulnerabilities()

	def getIdentifiedRisks(self):
		return self.informationSources.getIdentifiedRisks()

	def getIdentifiedRisksByResource(self, orderByMethod = None):
		return self.informationSources.getIdentifiedRisksByResource(orderByMethod)

	def getRiskForResource(self, resource, depth = -1, debugPrefix = None):
		return self.informationSources.getRiskForResource(resource, depth, debugPrefix)

	def getCummulativeNormalizedRiskForResource(self, resource, referenceResource):
		return self.informationSources.getCummulativeNormalizedRiskForResource(resource, referenceResource)

	def getResources(self):
		return self.resources.getResources()

	def getIdentifiedVulnerabilities(self):
		return self.informationSources.getIdentifiedVulnerabilities()

	def getInformationSourcesByVulnerability(self):
		return self.informationSources.getInformationSourcesByVulnerability()

	def getInformationSourcesByThreat(self):
		return self.informationSources.getInformationSourcesByThreat()

	def getControlsCatalog(self):
		return self.controlsCatalog.getControls()

	def getThreatSources(self):
		return self.threatSources.getThreatSources()

	def getThreatGroups(self):
		return self.threatCatalog.getThreatGroups()

	def getVulnerabilities(self):
		return self.vulnerabilityCatalog.getVulnerabilities()

	########################################################################
	## CODE TO GENERATE PDF REPORTS
	########################################################################

	def getInformationSourcesReportInPDF(self, doc, styles):
		"""
		Dump all information sources
		"""

		p = []
		p.append(Paragraph(u"Izvori informacija", styles['Heading1']))

		for iS in self.getInformationSources():
			p.append(Paragraph(iS.getName(lang="hr"), styles['Heading4']))
			p.append(Paragraph(u"Tip informacijskog izvora: {}".format(iS.getType()), styles['BodyText']))
			p.append(Paragraph(u"Datum nastanka: {}".format(iS.getDate()), styles['BodyText']))

			p.append(Paragraph(u"Opis", styles['Heading5']))
			try:
				p.append(Paragraph(iS.getDescription(lang="hr"), styles['BodyText']))
			except KeyError:
				p.append(Paragraph("Nema opisa", styles['BodyText']))

			changeLogs = iS.getChangeLogs()
			if changeLogs is not None and len(changeLogs) > 0:

				p.append(Paragraph(u"Dnevnik izmjena", styles['Heading5']))

				tableData = [(u"Datum", u"Izmjenu napravio", u"Zapis")]
				tableStyle = [('FONTNAME',(0,0),(-1,-1),'FreeSans'), ('TEXTCOLOR',(0,0),(-1,0),colors.black)]

				for cL in changeLogs:
					tableData.append((cL['date'], cL['user'], cL['logEntry']))

				t=Table(tableData)
				t.setStyle(TableStyle(tableStyle))
				p.append(t)

		return p

	def getThreatReportInPDF(self, doc, styles):
		"""
		Dump all unique threats identified in information sources
		"""

		p = []
		p.append(Paragraph(u"Identificirane prijetnje", styles['Heading1']))

		iSByT = self.getInformationSourcesByThreat()
		for t in iSByT:
			p.append(Paragraph(u"{}".format(t), styles['Heading4']))
			p.append(Paragraph(u"Izvori informacija", styles['Heading5']))
			for iS in iSByT[t]:
				p.append(Paragraph(u"{}".format(iS.getName(lang="hr")), styles['BodyText']))

		return p

	def getVulnerabilityReportInPDF(self, doc, styles):
		"""
		Dump all unique vulnerabilities identified in information sources
		"""

		p = []
		p.append(Paragraph(u"Identificirane ranjivosti", styles['Heading1']))

		iSByV = self.getInformationSourcesByVulnerability()
		for v in iSByV:
			p.append(Paragraph(u"{}".format(v), styles['Heading4']))
			p.append(Paragraph(u"Izvori informacija", styles['Heading5']))
			for iS in iSByV[v]:
				p.append(Paragraph(u"{}".format(iS.getName(lang="hr")), styles['BodyText']))

		return p

	def getRisksByResourceReportInPDF(self, doc, styles, highRiskThreshold = 7):
		"""
		Dump resources that have identified risks
		"""

		p = []
		p.append(Paragraph(u"Identificirani resursi s rizicima", styles['Heading1']))

		identifiedRisks = sorted(self.getIdentifiedRisksByResource(), key=lambda r: -self.getRiskForResource(r))

		tableData = [(Paragraph(u"<b>Resurs</b>", styles['Normal']), Paragraph(u"<b>Razina rizika</b>", styles['Normal']))]
		tableStyle = [('FONTNAME',(0,0),(-1,-1),'FreeSans'), ('TEXTCOLOR',(0,0),(-1,0),colors.black)]
		row = 0
		for resource in identifiedRisks:
			riskValue = self.getRiskForResource(resource)
			tableData.append((resource.getName(lang="hr"), riskValue))
			row += 1
			if riskValue >= highRiskThreshold:
				tableStyle.append(('TEXTCOLOR',(0,row),(-1,row),colors.red))

		t=Table(tableData)
		t.setStyle(TableStyle(tableStyle))
		p.append(t)

		return p

def cap(s, l):
	return s if len(s)<=l else s[0:l-3]+'...'

def dumpInformationSources(riskManagement):
	"""
	Dump all information sources
	"""
	for iS in riskManagement.getInformationSources():
		print(u"{:70} {} {}".format(cap(iS.getName(lang="hr"), 70), iS.getDate(), iS.getType()))

def dumpThreats(riskManagement):
	"""
	Dump all unique threats identified in information sources
	"""

	iSByT = riskManagement.getInformationSourcesByThreat()
	for t in iSByT:
		print u"{}".format(t)
		for iS in iSByT[t]:
			print(u"\t{:70} {} {}".format(cap(iS.getName(lang="hr"), 70), iS.getDate(), iS.getType()))

def dumpVulnerabilities(riskManagement):
	"""
	Dump all unique vulnerabilities identified in information sources
	"""

	iSByV = riskManagement.getInformationSourcesByVulnerability()
	for v in iSByV:
		print u"{}".format(v)
		for iS in iSByV[v]:
			print(u"\t{:70} {} {}".format(cap(iS.getName(lang="hr"), 70), iS.getDate(), iS.getType()))

def dumpIdentifiedThreats(riskManagement):

	for iT in riskManagement.getIdentifiedThreats():
		print u"{:65} {:30} {:30} {:5} {:5}".format(cap(iT.getThreatName(lang="hr"), 65), cap(iT.getThreatSourceName(lang="hr"), 30), cap(iT.getResourceName(lang="hr"), 30), iT.getProbability(), iT.getImpact())

def dumpIdentifiedVulnerabilities(riskManagement):

	for iV in riskManagement.getIdentifiedVulnerabilities():
		print u"{:65} {:30} {:5}".format(cap(iV.getVulnerabilityName(lang="hr"), 65), cap(iV.getResourceName(lang="hr"), 30), iV.getSeverity())

def dumpIdentifiedRisks(riskManagement):

	for iR in riskManagement.getIdentifiedRisks():
		print u"{:35} {:55} {:55} {:15} {}".format(cap(iR.getResourceName(), 35), cap(iR.getVulnerabilityName(), 55), cap(iR.getThreatName(), 55), cap(iR.getThreatSourceName(lang = "hr"), 15), iR.getValue())

def dumpIdentifiedRisksByResource(riskManagement):

	print
	for resource in riskManagement.getIdentifiedRisksByResource():
		print u"{:45} {}".format(resource.getName(lang="hr"),
				riskManagement.getRiskForResource(resource))

def dumpIdentifiedRisksByResourceHierarchy(riskManagement, startingResourceId, indent = ""):

	def _dumpIdentifiedRisksByResourceHierarchy(resource, startingResource, indent):
		print u"{}{:40} risk={} value={}".format(indent, resource.getName(), riskManagement.getRiskForResource(resource), resource.getBasicValue())
		for r in resource.getIsComposedOfResources():
			_dumpIdentifiedRisksByResourceHierarchy(r, startingResource, indent + "\t")

	startingResource = riskManagement.resources.getResourceById(startingResourceId)
	print u"{}{:40} risk={} value={}".format(indent, startingResource.getName(), riskManagement.getRiskForResource(startingResource), startingResource.getBasicValue())
	for resource in startingResource.getIsComposedOfResources():
		_dumpIdentifiedRisksByResourceHierarchy(resource, startingResource, indent + "\t")

def dumpIdentifiedRiskForOrganization(riskManagement):

	print
	resource = riskManagement.resources.getResourceById("r00000")
	print u"{:45} {}".format(resource.getName(lang="hr"), riskManagement.getRiskForResource(resource))
	resource = riskManagement.resources.getResourceById("r00013")
	print u"{:45} {}".format(resource.getName(lang="hr"), riskManagement.getRiskForResource(resource))
	resource = riskManagement.resources.getResourceById("r00153")
	print u"{:45} {}".format(resource.getName(lang="hr"), riskManagement.getRiskForResource(resource))

def dumpIdentifiedRiskForResource(riskManagement, resource):

	print
	resource = riskManagement.resources.getResourceById(resource)
	print u"{:45} {}".format(resource.getName(lang="hr"), riskManagement.getRiskForResource(resource, depth=0))

def main(xmlDir):
	riskManagement = RiskManagement(xmlDir)

	print "Generating PDF report"
	pdfmetrics.registerFont(TTFont('FreeSans', '/usr/share/fonts/gnu-free/FreeSans.ttf'))
	pdfmetrics.registerFont(TTFont('FreeSans-Bold', '/usr/share/fonts/gnu-free/FreeSansBold.ttf'))
	pdfmetrics.registerFont(TTFont('FreeSans-Italic', '/usr/share/fonts/gnu-free/FreeSansOblique.ttf'))
	pdfmetrics.registerFont(TTFont('FreeSans-BoldItalic', '/usr/share/fonts/gnu-free/FreeSansBoldOblique.ttf'))

	# ['BodyText', 'Code', 'Bullet', 'Title', 'Normal', 'Definition', 'Heading6', 'Heading4', 'Heading5', 'Heading2', 'Heading3', 'Italic', 'Heading1']
	styles = getSampleStyleSheet()
	styles['Heading1'].fontName = 'FreeSans-Bold'
	styles['Heading2'].fontName = 'FreeSans-Bold'
	styles['Heading3'].fontName = 'FreeSans-Bold'
	styles['Heading4'].fontName = 'FreeSans-Bold'
	styles['Heading5'].fontName = 'FreeSans-Bold'
	styles['BodyText'].fontName = 'FreeSans'
	#styles['Heading1'].backColor = colors.red
	#styles['Heading2'].backColor = colors.red
	#styles['Heading3'].backColor = colors.red
	styles['Heading4'].backColor = colors.red
	#styles['Heading5'].backColor = colors.red
	doc = BaseDocTemplate('RiskAssessmentReport.pdf', pagesize=A4)
	frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
	template = PageTemplate(id='test', frames=frame)
	doc.addPageTemplates([template])
	pageElements = []
	pageElements.extend(riskManagement.getRisksByResourceReportInPDF(doc, styles))
	pageElements.append(PageBreak())
	pageElements.extend(riskManagement.getInformationSourcesReportInPDF(doc, styles))
	pageElements.append(PageBreak())
	pageElements.extend(riskManagement.getThreatReportInPDF(doc, styles))
	pageElements.append(PageBreak())
	pageElements.extend(riskManagement.getVulnerabilityReportInPDF(doc, styles))
	doc.build(pageElements)

	#dumpInformationSources(riskManagement)
	#dumpThreats(riskManagement)
	#dumpVulnerabilities(riskManagement)
	#dumpIdentifiedThreats(riskManagement)
	#dumpIdentifiedVulnerabilities(riskManagement)
	#dumpIdentifiedRisks(riskManagement)
	#dumpIdentifiedRisksByResource(riskManagement)
	#dumpIdentifiedRiskForOrganization(riskManagement)
	dumpIdentifiedRisksByResourceHierarchy(riskManagement, "r00000")
	#dumpIdentifiedRisksByResourceHierarchy(riskManagement, "r00106")
	#dumpIdentifiedRisksByResourceHierarchy(riskManagement, "r00112")
	#dumpIdentifiedRiskForResource(riskManagement, "r00013")
	#dumpIdentifiedRiskForResource(riskManagement, "r00013")

if __name__ == '__main__':
	main(sys.argv[1])
