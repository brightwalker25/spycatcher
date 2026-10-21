import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// The panel scaffolding here, the open/close and IPC contract, is derived
// from Omarchy's `omarchy.weather` and `omarchy.agents` plugins
// (https://github.com/basecamp/omarchy, MIT, Copyright (c) David Heinemeier
// Hansson). See LICENSE for the full notice.

// The panel behind the bar lock: the overall rating, one block per section
// of the weekly Spycatcher report, and for every finding that is not green,
// what it is, why it matters here, and what is being done about it.
//
// Every Text here shows its string as plain text (textFormat: Text.PlainText).
// The report's findings quote file names, repository names, package output
// and the names a model file imports, any of which an attacker can choose.
// Qt's default format guesses at rich text, and rich text can load an image
// from any URL, so a crafted name could make the desktop fetch a page.
//
// It renders whatever `spycatcher-report --json` hands it and decides nothing
// itself. Every judgement, what counts as amber, when a quiet scan becomes a
// finding, which known issues are managed, is made in that script and its
// risk register, both of which work from a terminal with no compositor
// involved. The panel's only job is to draw the verdict.
Panel {
  id: root
  moduleName: "brightwalker25.spycatcher"
  ipcTarget: "brightwalker25.spycatcher"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  // The bar tracks the widget mounted in its slot, not this nested panel, so
  // the popout coordinator has to be handed that widget as the identity.
  readonly property var barIdentity: hostWidget || root

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Traffic-light colours are fixed rather than drawn from the theme. A theme
  // is free to define its urgent colour as a soft pink, and a danger signal
  // that reads as decoration is not a danger signal. These are the same three
  // VPN Check uses, chosen to hold their contrast on light and dark
  // backgrounds.
  readonly property color okColor: "#3fb950"
  readonly property color warnColor: "#d29922"
  readonly property color badColor: "#f85149"

  function ratingColor(rating) {
    if (rating === "green") return root.okColor
    if (rating === "amber") return root.warnColor
    if (rating === "red") return root.badColor
    return root.dim
  }

  readonly property int refreshMs: Math.max(30000, Number(setting("refreshIntervalMs", 300000)))
  // How far back the report looks. Anything outside 1 to 7, or not a whole
  // number, falls back to the week the report was written for.
  readonly property int reportDays: {
    var d = Number(setting("reportDays", 7))
    return (Number.isInteger(d) && d >= 1 && d <= 7) ? d : 7
  }
  onReportDaysChanged: root.poll()

  property var rep: null
  property string error: ""
  property string stderrText: ""
  property bool checking: false

  // What the bar widget reads. Empty whenever there is no report that parsed
  // cleanly, which the bar marks with a grey dot rather than no dot.
  readonly property string overall: rep ? String(rep.overall) : ""

  // The bar draws the tooltip with its own text item, which already shows
  // plain text. The report's line holds only counts, and the characters
  // markup is made of are removed as well, in case a shell version renders
  // it differently.
  readonly property string tooltip: {
    if (root.rep) return "Spycatcher report: " + root.overall.toUpperCase() + ". "
      + String(root.rep.line || "").replace(/[<>&]/g, "")
    if (root.error !== "") return "Spycatcher report unavailable"
    return ""
  }

  // Bundled with the plugin and found relative to it. The copy installed in
  // /usr/local/bin is preferred because that is the one the scans were set up
  // with, but an older install may predate --json, so the collector checks
  // for the flag before using it and falls back to the bundled copy.
  readonly property string bundled: String(Qt.resolvedUrl("bin/spycatcher-report")).replace(/^file:\/\//, "")

  readonly property string collectScript:
    'r=/usr/local/bin/spycatcher-report; ' +
    'if [ -x "$r" ] && grep -q -- --json "$r"; then exec "$r" --json --days "$2"; fi; ' +
    'exec "$1" --json --days "$2"'

  // The report exits 1 on red as well as on a crash, so the exit code cannot
  // say whether the page was written. The old page is removed first and the
  // new one is checked for instead. If it could not be written, the last page
  // the weekly timer produced is opened, which is better than nothing.
  readonly property string openScript:
    'r=/usr/local/bin/spycatcher-report; [ -x "$r" ] || r=$1; ' +
    'd="$HOME/.local/share/spycatcher"; out="$d/latest-widget.html"; ' +
    'rm -f "$out"; "$r" --html "$out" --days "$2" >/dev/null 2>&1; ' +
    'if [ -s "$out" ]; then exec xdg-open "$out"; fi; ' +
    'exec xdg-open "$d/latest.html"'

  function poll() {
    if (proc.running) return
    root.checking = true
    root.stderrText = ""
    proc.running = true
  }

  function openFullReport() {
    Quickshell.execDetached(["sh", "-c", root.openScript, "sh", root.bundled, String(root.reportDays)])
    root.close()
  }

  // A report that does not parse, or parses into something without a rating
  // the panel knows, is dropped rather than drawn. Keeping the previous one
  // would leave the bar showing a colour nothing currently backs.
  function ingest(text) {
    var parsed = null
    try {
      parsed = JSON.parse(String(text))
    } catch (e) {
      root.rep = null
      root.error = "Could not parse the report output"
      return
    }
    if (!parsed || typeof parsed !== "object"
        || ["green", "amber", "red"].indexOf(parsed.overall) < 0
        || !Array.isArray(parsed.sections)) {
      root.rep = null
      root.error = "The report output is not in the expected shape"
      return
    }
    root.error = ""
    root.rep = parsed
  }

  Process {
    id: proc
    command: ["sh", "-c", root.collectScript, "sh", root.bundled, String(root.reportDays)]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.ingest(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.stderrText = String(text || "").trim()
    }
    // Exit 1 is the report's way of saying red, not a failure. Anything
    // higher means it did not run properly, whatever it printed.
    onExited: function(exitCode) {
      root.checking = false
      if (exitCode > 1) {
        root.rep = null
        root.error = "spycatcher-report exited " + exitCode
      }
    }
  }

  // Runs whether or not the panel is open, because the bar lock's dot comes
  // from the result. It reads stored scan logs and asks pacman a few read-only
  // questions, which takes a few seconds at most and touches no network.
  Timer {
    running: true
    interval: root.refreshMs
    repeat: true
    triggeredOnStart: true
    onTriggered: root.poll()
  }

  function fmtRange() {
    if (!root.rep || !root.rep.start || !root.rep.end) return ""
    var s = new Date(root.rep.start)
    var e = new Date(root.rep.end)
    if (isNaN(s.getTime()) || isNaN(e.getTime())) return ""
    return Qt.formatDate(s, "ddd d MMM") + " to " + Qt.formatDate(e, "ddd d MMM yyyy")
      + ", read " + Qt.formatTime(e, "HH:mm")
  }

  // ------------------------------------------------------ expansion state

  // Keyed by section title so the choice survives each re-read, which
  // replaces the whole report and rebuilds every delegate. A section nobody
  // has touched is open when it has something to say and closed when green,
  // or when grey, which means off or not installed and is never a problem.
  property var expandedMap: ({})
  property var greenShownMap: ({})

  function isExpanded(section, map) {
    if (section.title in map) return map[section.title] === true
    return section.rating !== "green" && section.rating !== "grey"
  }

  function toggleExpanded(section) {
    var next = Object.assign({}, root.expandedMap)
    next[section.title] = !root.isExpanded(section, root.expandedMap)
    root.expandedMap = next
  }

  function toggleGreenShown(section) {
    var next = Object.assign({}, root.greenShownMap)
    next[section.title] = !(root.greenShownMap[section.title] === true)
    root.greenShownMap = next
  }

  function itemsWhere(section, green) {
    var out = []
    var items = section && section.items ? section.items : []
    for (var i = 0; i < items.length; i++)
      if ((items[i].rating === "green") === green) out.push(items[i])
    return out
  }

  // ------------------------------------------------------- open/close contract

  property bool openedFromHotkey: false

  function open() {
    openedFromHotkey = false
    root.controller.show()
    root.poll()
  }

  function openFromHotkey() {
    openedFromHotkey = true
    root.controller.show()
    root.poll()
  }

  function close() { root.controller.hide() }

  function toggle() {
    if (root.opened) root.close()
    else root.openFromHotkey()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      root.bar.switchPanelFrom(root.barIdentity, direction)
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.openFromHotkey() }
    function close(): void { root.close() }
    function show(): void { root.openFromHotkey() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.poll() }
  }

  // ------------------------------------------------------------- components

  // The rating as a word in its own colour. Colour alone is not enough to
  // carry a verdict, so the word is always spelled out beside it.
  component RatingPill: Rectangle {
    id: pill
    property string rating: ""
    readonly property color tone: root.ratingColor(rating)
    implicitWidth: pillLabel.implicitWidth + Style.space(12)
    implicitHeight: pillLabel.implicitHeight + Style.space(4)
    radius: height / 2
    color: Qt.rgba(tone.r, tone.g, tone.b, 0.16)
    border.width: 1
    border.color: tone

    Text {
      id: pillLabel
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: pill.rating !== "" ? pill.rating.toUpperCase() : "UNKNOWN"
      color: pill.tone
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }
  }

  component StatusDot: Rectangle {
    property string rating: ""
    implicitWidth: Style.space(9)
    implicitHeight: Style.space(9)
    radius: width / 2
    color: root.ratingColor(rating)
  }

  // One finding. The first line says what it is; the lines under it carry
  // the reasoning and the response, so the list stays scannable. `compact`
  // is for green items, where the response is almost always "none needed"
  // and would only add noise.
  component FindingRow: Item {
    id: finding
    property var item: null
    property bool compact: false
    readonly property real textIndent: Style.space(9) + Style.spacing.sm
    implicitHeight: findingText.implicitHeight

    StatusDot {
      x: 0
      // Lined up with the first line of text rather than the whole block.
      y: Math.max(0, (whatText.implicitHeight / Math.max(1, whatText.lineCount) - height) / 2)
      rating: finding.item ? finding.item.rating : ""
    }

    Column {
      id: findingText
      x: finding.textIndent
      width: finding.width - finding.textIndent
      spacing: Style.spacing.xxs

      Text {
        id: whatText
        textFormat: Text.PlainText
        width: parent.width
        text: finding.item ? finding.item.what : ""
        color: finding.compact ? root.dim : root.foreground
        font.family: root.fontFamily
        font.pixelSize: finding.compact ? Style.font.caption : Style.font.body
        // Paths and package names can be long with no spaces in them, so
        // they break wherever they must rather than running off the panel.
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        visible: text !== "" && !finding.compact
        text: finding.item && finding.item.detail ? finding.item.detail : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        visible: !finding.compact && !!(finding.item && finding.item.action)
        text: finding.item && finding.item.action ? "What is being done: " + finding.item.action : ""
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      }
    }
  }

  // A small clickable line of text, used for the section headers' green
  // toggle. The panel has no other inline links, so it stays deliberately
  // plain: dim until hovered.
  component TextLink: Text {
    id: link
    textFormat: Text.PlainText
    signal activated()
    color: linkMouse.containsMouse ? root.foreground : root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    MouseArea {
      id: linkMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: link.activated()
    }
  }

  // One report section: a header you can click to fold it, the section's
  // one-line verdict, and its findings when unfolded.
  component SectionBlock: Column {
    id: block
    property var section: null
    readonly property bool expanded: section ? root.isExpanded(section, root.expandedMap) : false
    readonly property bool greenShown: section ? root.greenShownMap[section.title] === true : false
    readonly property bool sectionGreen: section ? section.rating === "green" : true
    readonly property var flagged: root.itemsWhere(section, false)
    readonly property var greens: root.itemsWhere(section, true)
    spacing: Style.spacing.sm

    PanelSeparator { width: block.width; foreground: root.foreground }

    Item {
      width: block.width
      implicitHeight: Math.max(chevron.implicitHeight, titleText.implicitHeight, sectionPill.implicitHeight)

      Text {
        id: chevron
        textFormat: Text.PlainText
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        // nf-md-chevron_down and nf-md-chevron_right.
        text: block.expanded ? "󰅀" : "󰅂"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      Text {
        id: titleText
        textFormat: Text.PlainText
        anchors.left: chevron.right
        anchors.leftMargin: Style.spacing.xs
        anchors.right: sectionPill.left
        anchors.rightMargin: Style.spacing.controlGap
        anchors.verticalCenter: parent.verticalCenter
        text: block.section ? block.section.title : ""
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      }

      RatingPill {
        id: sectionPill
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        rating: block.section ? block.section.rating : ""
      }

      MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: if (block.section) root.toggleExpanded(block.section)
      }
    }

    Text {
      textFormat: Text.PlainText
      width: block.width
      visible: text !== ""
      text: block.section && block.section.headline ? block.section.headline : ""
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
    }

    Column {
      width: block.width
      visible: block.expanded
      spacing: Style.spacing.md
      topPadding: Style.spacing.xs

      Repeater {
        model: block.expanded ? block.flagged : []
        delegate: FindingRow {
          required property var modelData
          width: block.width
          item: modelData
        }
      }

      // In a section that is itself green, the green items are the whole
      // content and are shown as soon as it is unfolded. Elsewhere they sit
      // behind a toggle so the findings that need attention come first.
      TextLink {
        visible: !block.sectionGreen && block.greens.length > 0
        text: block.greenShown ? "Hide green items" : block.greens.length + " more green"
        onActivated: root.toggleGreenShown(block.section)
      }

      Repeater {
        model: block.expanded && (block.sectionGreen || block.greenShown) ? block.greens : []
        delegate: FindingRow {
          required property var modelData
          width: block.width
          item: modelData
          compact: true
        }
      }
    }
  }

  // ------------------------------------------------------------------ layout

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: false
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(460))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(820))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: column
          width: flick.width
          spacing: Style.spacing.lg

          // ---- Header: the overall rating as a pill, the report's own
          // one-line summary, and the week it covers.
          Column {
            width: parent.width
            spacing: Style.spacing.xs

            Row {
              spacing: Style.spacing.sm

              RatingPill {
                anchors.verticalCenter: parent.verticalCenter
                rating: root.overall
              }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: "Spycatcher report"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
              }
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.rep ? (root.rep.line || "")
                : (root.checking ? "Reading the report" : (root.error !== "" ? "The report could not be read." : "Not read yet"))
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            }

            Text {
              textFormat: Text.PlainText
              visible: text !== ""
              text: root.checking ? "reading…" : root.fmtRange()
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Row {
              spacing: Style.spacing.sm
              topPadding: Style.spacing.xs

              Button {
                text: "Refresh"
                // nf-md-refresh
                iconText: "󰑐"
                bordered: true
                enabled: !root.checking
                opacity: enabled ? 1.0 : 0.45
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.poll()
              }

              Button {
                text: "Open full report"
                // nf-md-file_document
                iconText: "󰈙"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.openFullReport()
              }
            }
          }

          // ---- One block per section, in the order the report gives them.
          // The panel does not know what the sections are.
          Column {
            width: parent.width
            spacing: Style.spacing.md
            visible: root.rep !== null

            Repeater {
              model: root.rep && root.rep.sections ? root.rep.sections : []
              delegate: SectionBlock {
                required property var modelData
                width: column.width
                section: modelData
              }
            }
          }

          // Failures are shown rather than swallowed. A panel that silently
          // draws a stale verdict is the failure mode worth avoiding. Output
          // on stderr alongside a good report, such as an unreadable risk
          // register, is shown too, but dimmed, since the report still ran.
          Column {
            width: parent.width
            spacing: Style.spacing.xs
            visible: root.error !== "" || root.stderrText !== ""

            PanelSeparator { width: parent.width; foreground: root.foreground }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.error !== ""
              text: root.error
              color: root.badColor
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.stderrText !== ""
              text: root.stderrText
              color: root.rep ? root.dim : root.badColor
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            }
          }
        }
      }
    }
  }
}
