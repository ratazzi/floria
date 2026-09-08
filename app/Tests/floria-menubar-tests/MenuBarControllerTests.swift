import AppKit
import SwiftUI
import XCTest
@testable import floria_menubar

@MainActor
final class MenuBarControllerTests: XCTestCase {
    func testShownPopoverTracksAsynchronouslyMeasuredListGrowthAndShrink() throws {
        let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 400, height: 600),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let anchor = NSView(frame: NSRect(x: 180, y: 550, width: 24, height: 24))
        window.contentView?.addSubview(anchor)
        window.orderFront(nil)
        let model = PopoverListFixtureModel()
        let controller = MenuBarController { AnyView(PopoverListFixture(model: model)) }
        defer { controller.close(); window.close() }
        controller.show(relativeTo: anchor)
        for rows in [0, 6, 1, 0, 20, 0] {
            model.rows = rows
            RunLoop.main.run(until: Date().addingTimeInterval(0.2))
            let expectedHeight = 64.0 + (rows == 0 ? 80 : min(Double(rows) * 38, 350)) + 100
            XCTAssertEqual(controller.panel.frame.width, 360, accuracy: 0.5)
            XCTAssertEqual(controller.panel.frame.height, expectedHeight, accuracy: 0.5,
                           "Panel must fit header, \(rows) rows and all footer actions")
        }
        controller.close()
        controller.show(relativeTo: anchor)
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        XCTAssertEqual(controller.panel.frame.height, 244, accuracy: 0.5)
    }

    func testShownPopoverDoesNotClipHostedContent() throws {
        let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 400, height: 600),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let anchor = NSView(frame: NSRect(x: 180, y: 550, width: 24, height: 24))
        window.contentView?.addSubview(anchor)
        window.orderFront(nil)
        let controller = MenuBarController {
            AnyView(VStack(spacing: 0) {
                Text("Search and protection").frame(height: 64)
                Text("Six active grants").frame(height: 300)
                Text("Open / Clear / Quit").frame(height: 100)
            }.frame(width: 360))
        }
        defer { controller.close(); window.close() }
        controller.show(relativeTo: anchor)
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        let view = try XCTUnwrap(controller.panel.contentView)
        XCTAssertTrue(controller.panel.isVisible)
        XCTAssertEqual(controller.panel.frame.width, 360, accuracy: 0.5)
        XCTAssertEqual(controller.panel.frame.height, 464, accuracy: 0.5)
        XCTAssertGreaterThanOrEqual(view.visibleRect.width, 360)
        XCTAssertGreaterThanOrEqual(view.visibleRect.height, 464)
    }

    func testPreparedPanelFitsEntireHostedContentBeforeShowing() throws {
        let controller = MenuBarController {
            AnyView(VStack(spacing: 0) {
                Text("Search and protection").frame(height: 64)
                Text("Six active grants").frame(height: 300)
                Text("Open / Clear / Quit").frame(height: 100)
            }.frame(width: 360))
        }
        controller.prepareContent()
        let chrome = try XCTUnwrap(controller.panel.contentView)
        let hostedView = try XCTUnwrap(chrome.subviews.last)
        XCTAssertEqual(controller.panel.frame.width, 360, accuracy: 0.5)
        XCTAssertEqual(controller.panel.frame.height, 464, accuracy: 0.5)
        XCTAssertEqual(chrome.frame.width, 360, accuracy: 0.5)
        XCTAssertEqual(chrome.frame.height, 464, accuracy: 0.5)
        XCTAssertEqual(hostedView.frame.width, 360, accuracy: 0.5)
        XCTAssertEqual(hostedView.frame.height, 464, accuracy: 0.5)
    }

    func testPanelChromeClipsEveryLayerToItsRoundedOutline() throws {
        let controller = MenuBarController { AnyView(Text("Test")) }
        controller.prepareContent()
        let chrome = try XCTUnwrap(controller.panel.contentView)

        XCTAssertTrue(chrome.wantsLayer)
        XCTAssertEqual(chrome.layer?.cornerRadius, MenuBarController.panelCornerRadius)
        XCTAssertEqual(chrome.layer?.cornerCurve, .continuous)
        XCTAssertTrue(chrome.layer?.masksToBounds == true)
        XCTAssertEqual(chrome.layer?.backgroundColor, NSColor.clear.cgColor)
    }

    func testUsesArrowlessStatusItemPanel() {
        let controller = MenuBarController { AnyView(Text("Test")) }
        XCTAssertTrue(controller.panel.styleMask.contains(.borderless))
        XCTAssertTrue(controller.panel.styleMask.contains(.fullSizeContentView))
        XCTAssertTrue(controller.panel.canBecomeKey)
        XCTAssertFalse(controller.panel.canBecomeMain)
        XCTAssertTrue(controller.panel.hasShadow,
                      "The rounded content mask lets the window server draw a native shadow")
        XCTAssertEqual(controller.panel.level, .popUpMenu)
    }

    func testSizeCanGrowAndShrinkWithoutChangingWidth() {
        let controller = MenuBarController { AnyView(Text("Test")) }
        controller.applyContentSize(CGSize(width: 360, height: 939))
        XCTAssertEqual(controller.panel.frame.size, CGSize(width: 360, height: 939))
        controller.applyContentSize(CGSize(width: 360, height: 315.2))
        XCTAssertEqual(controller.panel.frame.size, CGSize(width: 360, height: 316))
        controller.applyContentSize(.zero)
        XCTAssertEqual(controller.panel.frame.size, CGSize(width: 360, height: 316))
    }

    func testRejectsInvalidLayoutMeasurements() {
        for size in [CGSize.zero, CGSize(width: 360, height: CGFloat.infinity),
                     CGSize(width: CGFloat.nan, height: 315), CGSize(width: 360, height: -1)] {
            XCTAssertNil(MenuBarController.contentSize(for: size))
        }
    }

    func testClosingReleasesHostedPresentationState() {
        let controller = MenuBarController { AnyView(Text("Test")) }
        controller.prepareContent()
        XCTAssertNotNil(controller.panel.contentView)
        controller.close()
        XCTAssertNil(controller.panel.contentView)
    }

    func testPanelPlacementCentersBelowAnchorAndStaysOnScreen() {
        let visible = NSRect(x: 0, y: 0, width: 1_000, height: 800)
        let size = CGSize(width: 360, height: 300)

        XCTAssertEqual(
            MenuBarController.panelOrigin(
                anchorFrame: NSRect(x: 488, y: 780, width: 24, height: 20),
                panelSize: size,
                visibleFrame: visible),
            NSPoint(x: 320, y: 476))
        XCTAssertEqual(
            MenuBarController.panelOrigin(
                anchorFrame: NSRect(x: 0, y: 780, width: 24, height: 20),
                panelSize: size,
                visibleFrame: visible).x,
            8)
        XCTAssertEqual(
            MenuBarController.panelOrigin(
                anchorFrame: NSRect(x: 976, y: 780, width: 24, height: 20),
                panelSize: size,
                visibleFrame: visible).x,
            632)
    }
}

@MainActor
private final class PopoverListFixtureModel: ObservableObject {
    @Published var rows = 0
}

private struct PopoverListFixture: View {
    @ObservedObject var model: PopoverListFixtureModel
    @State private var listHeight: CGFloat = 0

    var body: some View {
        VStack(spacing: 0) {
            Text("Search and protection").frame(height: 64)
            if model.rows == 0 {
                Text("No matches").frame(height: 80)
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(0..<model.rows, id: \.self) { row in
                            Text("Row \(row)").frame(height: 38)
                        }
                    }
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: {
                        listHeight = $0
                    }
                }.frame(height: min(listHeight, 350))
            }
            Text("Open / Clear / Quit").frame(height: 100)
        }.frame(width: 360)
    }
}
