import XCTest

@testable import accessfs_menubar

final class ControlProtocolTests: XCTestCase {
    func testSnapshotRequestMatchesRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.snapshot.requestData(requestID: 7, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(value["request_id"] as? UInt64, 7)
        XCTAssertEqual(value["method"] as? String, "snapshot")
        XCTAssertNil(value["params"])
    }

    func testBindingRequestEncodesEnvironmentScope() throws {
        let command = ControlCommand.bindingUpsert(
            CatalogBinding(
                id: "fixture-binding", projectID: "fixture-project",
                scope: .environment("fixture-development"), resourceID: "fixture-resource",
                keyOverride: nil, enabled: true, allowOverride: false, position: 0))
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try command.requestData(requestID: 8, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])
        let binding = try XCTUnwrap(params["binding"] as? [String: Any])
        let scope = try XCTUnwrap(binding["scope"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "binding_upsert")
        XCTAssertEqual(scope["type"] as? String, "environment")
        XCTAssertEqual(scope["environment_id"] as? String, "fixture-development")
    }

    func testProjectCreateRequestCarriesCompleteWorkspace() throws {
        let command = ControlCommand.projectCreate(
            CatalogProject(
                id: "fixture-project", name: "Fixture Project", path: "/tmp/fixture-project"),
            CatalogEnvironment(
                id: "fixture-development", projectID: "fixture-project",
                name: "Development", position: 0),
            CatalogSurface(
                id: "fixture-dotenv", environmentID: "fixture-development", name: ".env",
                kind: "dotenv_file", path: "/tmp/fixture-project/.env", resourceID: nil,
                position: 0))
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try command.requestData(requestID: 10, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])
        let environment = try XCTUnwrap(params["environment"] as? [String: Any])
        let surface = try XCTUnwrap(params["surface"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "project_create")
        XCTAssertEqual(environment["project_id"] as? String, "fixture-project")
        XCTAssertEqual(surface["environment_id"] as? String, "fixture-development")
    }

    func testDecodesRustEmptyResponseWithSnakeCaseRequestID() throws {
        let data = Data(
            #"{"request_id":9,"status":"ok","result":{"type":"empty"}}"#.utf8)
        let decoder = JSONDecoder()

        let response = try decoder.decode(
            ControlResponseEnvelope<EmptyControlValue>.self, from: data)

        XCTAssertEqual(response.requestID, 9)
        XCTAssertEqual(response.result?.type, "empty")
        XCTAssertNil(response.result?.value)
    }

    func testDecodesCatalogForeignKeysFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[{"id":"fixture-development","project_id":"fixture-project","name":"Development","position":0}],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-dotenv","environment_id":"fixture-development","name":".env","kind":"dotenv_file","path":"/tmp/fixture/.env","resource_id":null,"position":0}]}"#.utf8)
        let decoder = JSONDecoder()

        let snapshot = try decoder.decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.environments.first?.projectID, "fixture-project")
        XCTAssertEqual(snapshot.surfaces.first?.environmentID, "fixture-development")
    }
}
