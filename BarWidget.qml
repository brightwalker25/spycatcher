import QtQuick
import qs.Commons
import qs.Ui

// Derived from Omarchy's own `omarchy.weather` bar widget
// (https://github.com/basecamp/omarchy, MIT, Copyright (c) David Heinemeier
// Hansson). The injectPanel / open / close / closeForPopoutSwitch contract
// below is what the bar requires of any widget hosting a panel, and this file
// follows that implementation closely. See LICENSE for the full notice.

// One lock in the bar, tinted green, amber or red to match the report; every
// section and finding lives in the panel. When the report could not be read
// at all the lock is amber, since a silent failure would otherwise look the
// same as green. Standing advice never tints the lock: the report keeps it
// out of the overall rating, and the panel shows it in its own block.
//
// The tint can be trusted even though it is only refreshed on a timer. The
// report does not probe anything live: it reads results the scans have
// already stored, and it grades a scan that has stopped running as a finding
// in its own right. A tint that is a few minutes old cannot hide a scan that
// went quiet, because the report itself turns amber and then red when that
// happens. Re-reading it is cheap, so the bar does so on a timer.
BarWidget {
  id: root
  moduleName: "brightwalker25.spycatcher"

  readonly property bool hideWhenGreen: setting("hideWhenGreen", false) === true

  // The panel owns the collector and the parsed report, so the bar and the
  // panel can never disagree about what the report said.
  readonly property string overall: panelLoader.item ? String(panelLoader.item.overall || "") : ""
  readonly property bool failed: panelLoader.item ? String(panelLoader.item.error || "") !== "" : false

  // nf-md-lock. A lock rather than a shield, so it cannot be mistaken for
  // VPN Check, which usually sits next to it. Omarchy uses the same glyph
  // only inside its network panel, never in the bar.
  readonly property string glyph: "󰌾"

  visible: !(root.hideWhenGreen && root.overall === "green")

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  function refresh() {
    if (panelLoader.item && panelLoader.item.poll) panelLoader.item.poll()
  }

  // Shape contract for shell.summon/hide/toggle routing: Bar.findPanelWidget
  // needs open/close/opened on the bar-widget root, not on the nested panel.
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() {
    if (panelLoader.item && panelLoader.item.openFromHotkey) panelLoader.item.openFromHotkey()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  // The bar prefers closeForPopoutSwitch over close when handing one panel
  // over to another, and reads popoutSwitchClosing back off the owner.
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.glyph
    slotSize: Style.bar.iconSlot
    tooltipText: panelLoader.item ? String(panelLoader.item.tooltip || "") : ""

    // The active colour is how the bar tints a glyph. Same fixed colours as
    // the panel; see the note there on why they do not come from the theme.
    useActiveColor: true
    active: root.overall !== "" || root.failed
    activeColor: root.overall === "red" ? "#f85149"
      : (root.overall === "green" ? "#3fb950" : "#d29922")

    onPressed: function(b) {
      if (b === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }
  }
}
