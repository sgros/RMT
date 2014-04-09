#!/usr/bin/python

import sys
import os

from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import *
from PyQt4 import uic

from RiskManagement import RiskManagement

LANG="hr"

class InformationSourcesUI:
	"""
	Information Sources tab/widget
	"""

	## Column definitions for Information sources tab
	IS_DATE = 0			# Date when IS was issuded
	IS_TITLE = 1

	def __init__(self, parentWidget, riskManagement):
		self.parentWidget = parentWidget
		self.riskManagement = riskManagement

		self.contextMenu = QMenu()
		self.newAction = self.contextMenu.addAction("New...")
		self.editAction = self.contextMenu.addAction("Edit...")
		self.removeAction = self.contextMenu.addAction("Remove")
		self.contextMenuSortBySubmenu = self.contextMenu.addMenu("Sort by")

		self.contextMenuSortBySubmenuSortByName = self.contextMenuSortBySubmenu.addAction("Name")
		self.contextMenuSortBySubmenuSortByName.setCheckable(True)
		self.contextMenuSortBySubmenuSortByName.setChecked(True)
		self.contextMenuSortBySubmenuSortByDate = self.contextMenuSortBySubmenu.addAction("Date")
		self.contextMenuSortBySubmenuSortByDate.setCheckable(True)
		self.contextMenuSortBySubmenu.addSeparator()
		self.contextMenuSortBySubmenuSortByReverse = self.contextMenuSortBySubmenu.addAction("Reverse")
		self.contextMenuSortBySubmenuSortByReverse.setCheckable(True)

		self.sortKey = lambda infsource: infsource.getName(lang=LANG)

		self.parentWidget.InformationSourcesWidget.resizeColumnToContents(InformationSourcesUI.IS_TITLE)

	def rightClickMenu(self, pos):

		action = self.contextMenu.exec_(self.parentWidget.InformationSourcesWidget.mapToGlobal(pos))
		if action == self.newAction:
			print "newAction"
		elif action == self.editAction:
			print "editAction"
		elif action == self.removeAction:
			print "removeAction"
		elif action == self.contextMenuSortBySubmenuSortByName:
			self.sortKey = lambda infsource: infsource.getName(lang=LANG)
			self.contextMenuSortBySubmenuSortByName.setChecked(True)
			self.contextMenuSortBySubmenuSortByDate.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByDate:
			self.sortKey = lambda infsource: infsource.getDate()
			self.contextMenuSortBySubmenuSortByName.setChecked(False)
			self.contextMenuSortBySubmenuSortByDate.setChecked(True)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByReverse:
			print "sortByReverse"
		else:
			print "UNKNOWN"

	def onSelectedItems(self):

		item = self.parentWidget.InformationSourcesWidget.selectedItems()[0]
		informationSource = self.informationSources[item]

		self.parentWidget.InformationSourcesWidget_Properties.clear()
		for isProperty in informationSource.getProperties():

			properties = informationSource.getPropertyAsStrOrList(isProperty)
			if isinstance(properties, list):

				for property in properties:

					item = QTreeWidgetItem()
					item.setText(0, isProperty)
					item.setText(1, property)
					self.parentWidget.InformationSourcesWidget_Properties.addTopLevelItem(item)

			else:

				item = QTreeWidgetItem()
				item.setText(0, isProperty)
				item.setText(1, properties)
				self.parentWidget.InformationSourcesWidget_Properties.addTopLevelItem(item)

		for i in xrange(2):
			self.parentWidget.InformationSourcesWidget_Properties.resizeColumnToContents(i)

		self.parentWidget.InformationSourcesWidget_Risks.clear()
#		risksByResource = informationSource.getIdentifiedRisksByResource()
#		for risk in risksByResource:
#
#			item = QTreeWidgetItem()
#			item.setText(0, risk.getResourceName())
#			item.setText(1, risk.getValue(lang=LANG))
#			self.parentWidget.InformationSourcesWidget_Risks.addTopLevelItem(item)
#
#		for i in xrange(2):
#			self.parentWidget.InformationSourcesWidget_Threats.resizeColumnToContents(i)
#
#		self.parentWidget.InformationSourcesWidget_Threats.clear()
#		for threat in informationSource.getIdentifiedThreats():
#			item = QTreeWidgetItem()
#			item.setText(0, threat.getThreatName())
#			item.setText(1, threat.getThreatSourceName(lang=LANG))
#			item.setText(2, str(threat.getThreatSourceRelevance()))
#			item.setText(3, str(threat.getImpact()))
#			self.parentWidget.InformationSourcesWidget_Threats.addTopLevelItem(item)
#
#		for i in xrange(4):
#			self.parentWidget.InformationSourcesWidget_Threats.resizeColumnToContents(i)
#
#		self.parentWidget.InformationSourcesWidget_Vulnerabilities.clear()
#		for vulnerability in informationSource.getIdentifiedVulnerabilities():
#			item = QTreeWidgetItem()
#			item.setText(0, vulnerability.getVulnerabilityName())
#			item.setText(1, str(vulnerability.getSeverity()))
#			self.parentWidget.InformationSourcesWidget_Vulnerabilities.addTopLevelItem(item)
#
#		for i in xrange(3):
#			self.parentWidget.InformationSourcesWidget_Vulnerabilities.resizeColumnToContents(i)

	def show(self):

		self.informationSources = {}
		self.parentWidget.InformationSourcesWidget.clear()
		for informationSource in sorted(self.riskManagement.getInformationSources(), key=self.sortKey):

			item = QTreeWidgetItem()
			item.setText(InformationSourcesUI.IS_DATE, informationSource.getDate())
			item.setText(InformationSourcesUI.IS_TITLE, informationSource.getName(lang=LANG))

			self.informationSources[item] = informationSource

			self.parentWidget.InformationSourcesWidget.addTopLevelItem(item)

		self.parentWidget.InformationSourcesWidget.setContextMenuPolicy(Qt.CustomContextMenu)
		self.parentWidget.InformationSourcesWidget.customContextMenuRequested.connect(self.rightClickMenu)
		self.parentWidget.InformationSourcesWidget.itemSelectionChanged.connect(self.onSelectedItems)

class ResourcesWidget:
	"""
	Resources tab/widget
	"""

	def __init__(self, parentWidget, riskManagement):
		self.parentWidget = parentWidget
		self.riskManagement = riskManagement

		self.contextMenu = QMenu()
		self.newAction = self.contextMenu.addAction("New...")
		self.editAction = self.contextMenu.addAction("Edit...")
		self.removeAction = self.contextMenu.addAction("Remove")
		self.contextMenuSortBySubmenu = self.contextMenu.addMenu("Sort by")

		self.contextMenuSortBySubmenuSortByRisk = self.contextMenuSortBySubmenu.addAction("Risk")
		self.contextMenuSortBySubmenuSortByRisk.setCheckable(True)
		self.contextMenuSortBySubmenuSortByRisk.setChecked(True)
		self.contextMenuSortBySubmenuSortByName = self.contextMenuSortBySubmenu.addAction("Name")
		self.contextMenuSortBySubmenuSortByName.setCheckable(True)
		self.contextMenuSortBySubmenuSortByValue = self.contextMenuSortBySubmenu.addAction("Value")
		self.contextMenuSortBySubmenuSortByValue.setCheckable(True)
		self.contextMenuSortBySubmenu.addSeparator()
		self.contextMenuSortBySubmenuSortByReverse = self.contextMenuSortBySubmenu.addAction("Reverse")
		self.contextMenuSortBySubmenuSortByReverse.setCheckable(True)

		self.sortKey = lambda resource: -self.riskManagement.getRiskForResource(resource)

	def rightClickMenu(self, pos):

		action = self.contextMenu.exec_(self.parentWidget.ResourcesWidget.mapToGlobal(pos))
		if action == self.newAction:
			print "newAction"
		elif action == self.editAction:
			print "editAction"
		elif action == self.removeAction:
			print "removeAction"
		elif action == self.contextMenuSortBySubmenuSortByName:
			self.sortKey = lambda resource: resource.getName(lang=LANG)
			self.contextMenuSortBySubmenuSortByName.setChecked(True)
			self.contextMenuSortBySubmenuSortByValue.setChecked(False)
			self.contextMenuSortBySubmenuSortByRisk.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByValue:
			self.sortKey = lambda resource: -resource.getBasicValueOrZero()
			self.contextMenuSortBySubmenuSortByName.setChecked(False)
			self.contextMenuSortBySubmenuSortByValue.setChecked(True)
			self.contextMenuSortBySubmenuSortByRisk.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByRisk:
			self.sortKey = lambda resource: -self.riskManagement.getRiskForResource(resource)
			self.contextMenuSortBySubmenuSortByName.setChecked(False)
			self.contextMenuSortBySubmenuSortByValue.setChecked(False)
			self.contextMenuSortBySubmenuSortByRisk.setChecked(True)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByReverse:
			print "sortByReverse"
		else:
			print "UNKNOWN"

	def onSelectedItems(self):

		def _addResources(name, resourcesList):

			item = QTreeWidgetItem()
			item.setText(0, name)

			for parent in resourcesList:
				subitem = QTreeWidgetItem()
				subitem.setText(0, parent.getName())
				item.addChild(subitem)

			return item

		item = self.parentWidget.ResourcesWidget.selectedItems()[0]
		resource = self.resources[item]

		self.parentWidget.ResourceWidget_ConnectionResources.clear()
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Physically stored in (is-in)", resource.getIsInResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Is part of (is-part-of)", resource.getIsPartOfResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Is composed of (is-composed-of)", resource.getIsComposedOfResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Is stored on (is-stored-on)", resource.getIsStoredOnResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Stores (stores)", resource.getStoresResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Uses", resource.getUsesResources()))
		self.parentWidget.ResourceWidget_ConnectionResources.addTopLevelItem(_addResources("Used by", resource.getIsUsedByResources()))

		self.parentWidget.ResourceWidget_Threats.clear()
		for threats in resource.getThreats():

			item = QTreeWidgetItem()
			item.setText(0, threats.getName(lang=LANG))
			self.parentWidget.ResourceWidget_Threats.addTopLevelItem(item)

		self.parentWidget.ResourceWidget_Vulnerabilities.clear()
		for vulnerability in resource.getVulnerabilities():

			item = QTreeWidgetItem()
			item.setText(0, vulnerability.getName(lang=LANG))
			self.parentWidget.ResourceWidget_Vulnerabilities.addTopLevelItem(item)

	def show(self, sortBy = "name"):

		def _showChildren(resource, item, resources):

			for child in sorted(resource.getIsComposedOfResources(), key=self.sortKey):
				subitem = QTreeWidgetItem()
				subitem.setText(0, child.getName(lang=LANG))
				subitem.setText(1, str(child.getBasicValue()))
				subitem.setText(2, str(self.riskManagement.getRiskForResource(child)))

				_showChildren(child, subitem, resources)

				item.addChild(subitem)
				resources[subitem] = child

		self.resources = {}
		self.parentWidget.ResourcesWidget.clear()
		for resource in sorted(self.riskManagement.getResources(), key=self.sortKey):

			item = QTreeWidgetItem()
			item.setText(0, resource.getName(lang=LANG))
			item.setText(1, str(resource.getBasicValue()))
			item.setText(2, str(self.riskManagement.getRiskForResource(resource)))
			self.parentWidget.ResourcesWidget.addTopLevelItem(item)

			_showChildren(resource, item, self.resources)
			self.resources[item] = resource

		self.parentWidget.ResourcesWidget.itemSelectionChanged.connect(self.onSelectedItems)
		self.parentWidget.ResourcesWidget.setContextMenuPolicy(Qt.CustomContextMenu)
		self.parentWidget.ResourcesWidget.customContextMenuRequested.connect(self.rightClickMenu)

		self.parentWidget.ResourcesWidget.setColumnWidth(0, 400);

class IdentifiedVulnerabilitiesWidget:
	"""
	Identified vulnerabilities tab/widget
	"""

	def __init__(self, parentWidget, riskManagement):
		self.parentWidget = parentWidget
		self.riskManagement = riskManagement

		self.contextMenu = QMenu()
		self.newAction = self.contextMenu.addAction("New...")
		self.editAction = self.contextMenu.addAction("Edit...")
		self.removeAction = self.contextMenu.addAction("Remove")
		self.contextMenuSortBySubmenu = self.contextMenu.addMenu("Sort by")

		self.contextMenuSortBySubmenuSortByName = self.contextMenuSortBySubmenu.addAction("Name")
		self.contextMenuSortBySubmenuSortByName.setCheckable(True)
		self.contextMenuSortBySubmenuSortByName.setChecked(True)
		self.contextMenuSortBySubmenuSortByDate = self.contextMenuSortBySubmenu.addAction("Date")
		self.contextMenuSortBySubmenuSortByDate.setCheckable(True)
		self.contextMenuSortBySubmenu.addSeparator()
		self.contextMenuSortBySubmenuSortByReverse = self.contextMenuSortBySubmenu.addAction("Reverse")
		self.contextMenuSortBySubmenuSortByReverse.setCheckable(True)

		self.sortKey = lambda vulnerability: vulnerability.getName(lang=LANG)

	def rightClickMenu(self, pos):

		action = self.contextMenu.exec_(self.parentWidget.ResourcesWidget.mapToGlobal(pos))
		if action == self.newAction:
			print "newAction"
		elif action == self.editAction:
			print "editAction"
		elif action == self.removeAction:
			print "removeAction"
		elif action == self.contextMenuSortBySubmenuSortByName:
			self.sortKey = lambda vulnerability: vulnerability.getName(lang=LANG)
			self.contextMenuSortBySubmenuSortByName.setChecked(True)
			self.contextMenuSortBySubmenuSortByDate.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByDate:
			self.sortKey = lambda vulnerability: vulnerability.getDate()
			self.contextMenuSortBySubmenuSortByName.setChecked(False)
			self.contextMenuSortBySubmenuSortByDate.setChecked(True)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByReverse:
			print "sortByReverse"
		else:
			print "UNKNOWN"

	def onSelectedItems(self):

		item = self.parentWidget.IdentifiedVulnerabilitiesWidget.selectedItems()[0]
		informationSources = self.identifiedVulnerabilities[item]

		self.parentWidget.IdentifiedVulnerabilitiesWidget_InformationSources.clear()
		self.parentWidget.IdentifiedVulnerabilitiesWidget_Resources.clear()

		resources = set()

		for informationSource in informationSources:

			item = QTreeWidgetItem()
			item.setText(0, informationSource.getName(lang=LANG))
			self.parentWidget.IdentifiedVulnerabilitiesWidget_InformationSources.addTopLevelItem(item)

			for resource in informationSource.getResources():
				resources.add(resource)

		for resource in resources:
			item = QTreeWidgetItem()
			item.setText(0, resource.getName(lang=LANG))
			self.parentWidget.IdentifiedVulnerabilitiesWidget_Resources.addTopLevelItem(item)

	def show(self):

		self.identifiedVulnerabilities = {}
		informationSources = self.riskManagement.getInformationSourcesByVulnerability()
		for vulnerability in sorted(informationSources.keys(), key=self.sortKey):

			item = QTreeWidgetItem()
			item.setText(0, vulnerability.getName(lang=LANG))
			self.parentWidget.IdentifiedVulnerabilitiesWidget.addTopLevelItem(item)

			self.identifiedVulnerabilities[item] = informationSources[vulnerability]

		self.parentWidget.IdentifiedVulnerabilitiesWidget.itemSelectionChanged.connect(self.onSelectedItems)
		self.parentWidget.IdentifiedVulnerabilitiesWidget.setContextMenuPolicy(Qt.CustomContextMenu)
		self.parentWidget.IdentifiedVulnerabilitiesWidget.customContextMenuRequested.connect(self.rightClickMenu)

		self.parentWidget.IdentifiedVulnerabilitiesWidget.setColumnWidth(0, 800);

class IdentifiedThreatsWidget:
	"""
	Identified threats tab/widget
	"""

	def __init__(self, parentWidget, riskManagement):
		self.parentWidget = parentWidget
		self.riskManagement = riskManagement

		self.contextMenu = QMenu()
		self.newAction = self.contextMenu.addAction("New...")
		self.editAction = self.contextMenu.addAction("Edit...")
		self.removeAction = self.contextMenu.addAction("Remove")
		self.contextMenuSortBySubmenu = self.contextMenu.addMenu("Sort by")

		self.contextMenuSortBySubmenuSortByName = self.contextMenuSortBySubmenu.addAction("Name")
		self.contextMenuSortBySubmenuSortByName.setCheckable(True)
		self.contextMenuSortBySubmenuSortByName.setChecked(True)
		self.contextMenuSortBySubmenuSortByDate = self.contextMenuSortBySubmenu.addAction("Date")
		self.contextMenuSortBySubmenuSortByDate.setCheckable(True)
		self.contextMenuSortBySubmenu.addSeparator()
		self.contextMenuSortBySubmenuSortByReverse = self.contextMenuSortBySubmenu.addAction("Reverse")
		self.contextMenuSortBySubmenuSortByReverse.setCheckable(True)

		self.sortKey = lambda threat: threat.getName(lang=LANG)

	def rightClickMenu(self, pos):

		action = self.contextMenu.exec_(self.parentWidget.ResourcesWidget.mapToGlobal(pos))
		if action == self.newAction:
			print "newAction"
		elif action == self.editAction:
			print "editAction"
		elif action == self.removeAction:
			print "removeAction"
		elif action == self.contextMenuSortBySubmenuSortByName:
			self.sortKey = lambda threat: threat.getName(lang=LANG)
			self.contextMenuSortBySubmenuSortByName.setChecked(True)
			self.contextMenuSortBySubmenuSortByDate.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByDate:
			self.sortKey = lambda threat: threat.getDate()
			self.contextMenuSortBySubmenuSortByName.setChecked(False)
			self.contextMenuSortBySubmenuSortByDate.setChecked(True)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByReverse:
			print "sortByReverse"
		else:
			print "UNKNOWN"

	def onSelectedItems(self):

		item = self.parentWidget.IdentifiedThreatsWidget.selectedItems()[0]
		informationSources = self.identifiedThreats[item]

		self.parentWidget.IdentifiedThreatsWidget_InformationSources.clear()
		self.parentWidget.IdentifiedThreatsWidget_ThreatSources.clear()

		threatSources = set()

		for informationSource in informationSources:

			item = QTreeWidgetItem()
			item.setText(0, informationSource.getName(lang=LANG))
			self.parentWidget.IdentifiedThreatsWidget_InformationSources.addTopLevelItem(item)

			for threatSource in informationSource.getThreatSources():
				threatSources.add(threatSource)

		for threatSource in threatSources:
			item = QTreeWidgetItem()
			item.setText(0, threatSource.getName(lang=LANG))
			self.parentWidget.IdentifiedThreatsWidget_ThreatSources.addTopLevelItem(item)

	def show(self):

		self.parentWidget.IdentifiedThreatsWidget.clear()

		self.identifiedThreats = {}
		informationSources = self.riskManagement.getInformationSourcesByThreat()
		for threat in sorted(informationSources.keys(), key=self.sortKey):

			item = QTreeWidgetItem()
			item.setText(0, threat.getName(lang=LANG))
			self.parentWidget.IdentifiedThreatsWidget.addTopLevelItem(item)

			self.identifiedThreats[item] = informationSources[threat]

		self.parentWidget.IdentifiedThreatsWidget.itemSelectionChanged.connect(self.onSelectedItems)
		self.parentWidget.IdentifiedThreatsWidget.setContextMenuPolicy(Qt.CustomContextMenu)
		self.parentWidget.IdentifiedThreatsWidget.customContextMenuRequested.connect(self.rightClickMenu)

		self.parentWidget.IdentifiedThreatsWidget.setColumnWidth(0, 800);

class IdentifiedRisksWidget:
	"""
	Identified risks tab/widget
	"""

	def __init__(self, parentWidget, riskManagement):
		self.parentWidget = parentWidget
		self.riskManagement = riskManagement

		self.contextMenu = QMenu()
		self.newAction = self.contextMenu.addAction("New...")
		self.editAction = self.contextMenu.addAction("Edit...")
		self.removeAction = self.contextMenu.addAction("Remove")
		self.contextMenuSortBySubmenu = self.contextMenu.addMenu("Sort by")

		self.contextMenuSortBySubmenuSortByRiskValue = self.contextMenuSortBySubmenu.addAction("Risk value")
		self.contextMenuSortBySubmenuSortByRiskValue.setCheckable(True)
		self.contextMenuSortBySubmenuSortByRiskValue.setChecked(True)
		self.contextMenuSortBySubmenuSortByResource = self.contextMenuSortBySubmenu.addAction("Resource")
		self.contextMenuSortBySubmenuSortByResource.setCheckable(True)
		self.contextMenuSortBySubmenu.addSeparator()
		self.contextMenuSortBySubmenuSortByReverse = self.contextMenuSortBySubmenu.addAction("Reverse")
		self.contextMenuSortBySubmenuSortByReverse.setCheckable(True)

		self.sortKey = lambda risk: -risk.getValue()

	def rightClickMenu(self, pos):

		action = self.contextMenu.exec_(self.parentWidget.ResourcesWidget.mapToGlobal(pos))
		if action == self.newAction:
			print "newAction"
		elif action == self.editAction:
			print "editAction"
		elif action == self.removeAction:
			print "removeAction"
		elif action == self.contextMenuSortBySubmenuSortByResource:
			self.sortKey = lambda risk: risk.getResourceName()
			self.contextMenuSortBySubmenuSortByResource.setChecked(True)
			self.contextMenuSortBySubmenuSortByRiskValue.setChecked(False)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByRiskValue:
			self.sortKey = lambda risk: -risk.getValue()
			self.contextMenuSortBySubmenuSortByResource.setChecked(False)
			self.contextMenuSortBySubmenuSortByRiskValue.setChecked(True)
			self.show()
		elif action == self.contextMenuSortBySubmenuSortByReverse:
			print "sortByReverse"
		else:
			print "UNKNOWN"

	def onSelectedItems(self):
		pass

	def show(self):

		self.parentWidget.IdentifiedRisksWidget.clear()

		for risk in sorted(self.riskManagement.getIdentifiedRisks(), key=self.sortKey):

			item = QTreeWidgetItem()
			item.setText(0, risk.getResourceName())
			item.setText(1, risk.getVulnerabilityName())
			item.setText(2, risk.getThreatName())
			item.setText(3, risk.getThreatSourceName(lang=LANG))
			item.setText(4, str(risk.getValue()))
			self.parentWidget.IdentifiedRisksWidget.addTopLevelItem(item)

		self.parentWidget.IdentifiedRisksWidget.itemSelectionChanged.connect(self.onSelectedItems)
		self.parentWidget.IdentifiedRisksWidget.setContextMenuPolicy(Qt.CustomContextMenu)
		self.parentWidget.IdentifiedRisksWidget.customContextMenuRequested.connect(self.rightClickMenu)

		self.parentWidget.IdentifiedRisksWidget.setColumnWidth(0, 200);
		self.parentWidget.IdentifiedRisksWidget.setColumnWidth(1, 400);
		self.parentWidget.IdentifiedRisksWidget.setColumnWidth(2, 400);
		self.parentWidget.IdentifiedRisksWidget.setColumnWidth(3, 200);
		self.parentWidget.IdentifiedRisksWidget.setColumnWidth(4, 30);


class RiskManagementUI(QMainWindow):

	# Column definitions for RISK tab
	RISK_THREAT = 0
	RISK_THREATSOURCE = 1
	RISK_VULNERABILITY = 2
	RISK_RESOURCE = 3
	RISK_RISK = 4

	def __init__(self, xmlDir):

		self.riskManagement = RiskManagement(xmlDir)

		QMainWindow.__init__(self)

		self.main_window = uic.loadUi('ui/main_window.ui')
		self.controls_catalog = uic.loadUi('ui/controls_catalog.ui')
		self.threat_sources = uic.loadUi('ui/threat_sources.ui')
		self.threats = uic.loadUi('ui/threats.ui')
		self.vulnerabilities = uic.loadUi('ui/vulnerabilities.ui')

		self.informationSourcesUI = InformationSourcesUI(self.main_window, self.riskManagement)
		self.resourcesWidget = ResourcesWidget(self.main_window, self.riskManagement)
		self.identifiedVulnerabilities = IdentifiedVulnerabilitiesWidget(self.main_window, self.riskManagement)
		self.identifiedThreats = IdentifiedThreatsWidget(self.main_window, self.riskManagement)
		self.identifiedRisks = IdentifiedRisksWidget(self.main_window, self.riskManagement)

		self.main_window.menuFileNew.triggered.connect(self.menuNotImplemented)
		self.main_window.menuFileOpen.triggered.connect(self.menuFileOpen)
		self.main_window.menuFileSave.triggered.connect(self.menuNotImplemented)
		self.main_window.menuFileSaveAs.triggered.connect(self.menuNotImplemented)
		self.main_window.menuFileQuit.triggered.connect(self.menuFileQuit)

		self.main_window.menuCatalogsControls.triggered.connect(self.menuCatalogsControls)
		self.main_window.menuCatalogsThreatSources.triggered.connect(self.menuCatalogsThreatSources)
		self.main_window.menuCatalogsThreats.triggered.connect(self.menuCatalogsThreats)
		self.main_window.menuCatalogsVulnerabilities.triggered.connect(self.menuCatalogsVulnerabilities)

		self.informationSourcesUI.show()
		self.resourcesWidget.show()
		self.identifiedVulnerabilities.show()
		self.identifiedThreats.show()
		self.identifiedRisks.show()

		self.main_window.show()

	########################################################################
	##
	## Risks tab/widget
	##
	########################################################################

	def displayRisksByThreat(self):

		grouping = self.riskManagement.getGroupedRisksByT_TS_V_R()

		for threat in grouping:

			item0 = QTreeWidgetItem()
			item0.setText(RiskManagementUI.RISK_THREAT, threat.getThreatName(lang=LANG))

			self.main_window.treeWidget_Risks.addTopLevelItem(item0)

			for threatSource in grouping[threat]:

				item1 = QTreeWidgetItem()
				item1.setText(RiskManagementUI.RISK_THREATSOURCE, threatSource.getName(lang=LANG))

				for vulnerability in grouping[threat][threatSource]:

					item2 = QTreeWidgetItem()
					item2.setText(RiskManagementUI.RISK_VULNERABILITY, vulnerability.getName(lang=LANG))

					for resource in grouping[threat][threatSource][vulnerability]:

						item3 = QTreeWidgetItem()
						item3.setText(RiskManagementUI.RISK_RESOURCE, resource.getName(lang=LANG))

						item2.addChild(item3)

					item1.addChild(item2)

				item0.addChild(item1)

		self.main_window.treeWidget_Risks.setColumnWidth(0, 800);
		self.main_window.treeWidget_Risks.setColumnWidth(1, 150);

			

#		for risks in self.riskManagement.getRisksByThreatId().values():
#
#
#			for risk in risks:
#				subitem = QTreeWidgetItem()
#				subitem.setText(RiskManagementUI.RISK_THREATSOURCE, risk.getThreatSourceName(lang=LANG))
#				subitem.setText(RiskManagementUI.RISK_VULNERABILITY, risk.getVulnerabilityName(lang=LANG))
#				subitem.setText(RiskManagementUI.RISK_RESOURCE, risk.getResourceName(lang=LANG))
#				subitem.setText(RiskManagementUI.RISK_RISK, "N/A")
#

	########################################################################
	##
	## Information Sources tab/widget
	##
	########################################################################

	def menuNotImplemented(self):
		"""
		Action that is triggered when user selects a Quit from File menu.
		"""
		print "NOT IMPLEMENTED"

	def menuFileQuit(self):
		"""
		Action that is triggered when user selects a Quit from File menu.
		"""
		sys.exit(1)

	def menuFileOpen(self):
		qFileDialog = QFileDialog()

		qFileDialog.setNameFilter("*.xml")
		fileName = qFileDialog.getOpenFileName(parent=self.main_window)
		if fileName != "":
			self.riskManagement.loadInformationSourcesFromXML(fileName)
			self.informationSources.show()

	def menuCatalogsControls(self):
		self.controls_catalog.ControlsCatalog_List.clear()
		for control in self.riskManagement.getControlsCatalog():
			item = QTreeWidgetItem()
			item.setText(0, control.getId())
			item.setText(1, control.getTitle())
			self.controls_catalog.ControlsCatalog_List.addTopLevelItem(item)

		self.controls_catalog.show()

	def _menuCatalogsThreatSources(self, threatSource):

		item = QTreeWidgetItem()
		item.setText(0, threatSource.getId())
		item.setText(1, threatSource.getName())

		threatSources = threatSource.getThreatSources()
		for ts in threatSources:
			item.addChild(self._menuCatalogsThreatSources(ts))

		return item

		for threatSource in threatSources:
			item = QTreeWidgetItem()
			item.setText(0, threatSource.getId())
			item.setText(1, threatSource.getName())

	def menuCatalogsThreatSources(self):
		self.threat_sources.ThreatSources_List.clear()
		for threatSource in self.riskManagement.getThreatSources():
			self.threat_sources.ThreatSources_List.addTopLevelItem(self._menuCatalogsThreatSources(threatSource))

		self.threat_sources.show()

	def _menuCatalogsThreats(self, item, threatGroup):

		for threat in threatGroup.getThreats():
			subitem = QTreeWidgetItem()
			subitem.setText(0, threat.getId())
			subitem.setText(1, threat.getName())
			item.addChild(subitem)

	def menuCatalogsThreats(self):
		self.threats.Threats_List.clear()
		for threatGroup in self.riskManagement.getThreatGroups():
			item = QTreeWidgetItem()
			item.setText(0, threatGroup.getId())
			item.setText(1, threatGroup.getName())
			self._menuCatalogsThreats(item, threatGroup)
			self.threats.Threats_List.addTopLevelItem(item)

		self.threats.show()

	def menuCatalogsVulnerabilities(self):
		self.vulnerabilities.Vulnerabilities_List.clear()
		for vulnerability in self.riskManagement.getVulnerabilities():
			item = QTreeWidgetItem()
			item.setText(0, vulnerability.getId())
			item.setText(1, vulnerability.getName(lang=LANG))
			self.vulnerabilities.Vulnerabilities_List.addTopLevelItem(item)

		self.vulnerabilities.show()

def main():
	app = QApplication(sys.argv)
	win = RiskManagementUI(sys.argv[1])
	sys.exit(app.exec_())

if __name__ == '__main__':
	main()
