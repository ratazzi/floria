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
                selection: .entries(["records/fixture-primary"]), keyOverride: nil,
                enabled: true, allowOverride: false, position: 0))
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try command.requestData(requestID: 8, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])
        let binding = try XCTUnwrap(params["binding"] as? [String: Any])
        let scope = try XCTUnwrap(binding["scope"] as? [String: Any])
        let selection = try XCTUnwrap(binding["selection"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "binding_upsert")
        XCTAssertEqual(scope["type"] as? String, "environment")
        XCTAssertEqual(scope["environment_id"] as? String, "fixture-development")
        XCTAssertEqual(selection["type"] as? String, "entries")
        XCTAssertEqual(selection["addresses"] as? [String], ["records/fixture-primary"])
    }

    func testSharedSecretCreateAllowsAKeylessValue() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.sharedSecretCreate(
            resourceID: "fixture-line", name: "Fixture Line", defaultEnvKey: nil,
            value: "fixture-host|5432|fixture-db|fixture-user|fixture-value"
        ).requestData(requestID: 9, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "shared_secret_create")
        XCTAssertNil(params["default_env_key"])
        XCTAssertEqual(
            params["value"] as? String,
            "fixture-host|5432|fixture-db|fixture-user|fixture-value")
    }

    func testEnvFileCreateRequestCarriesPlaintextOnlyInTheControlBody() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.envFileCreate(
            resourceID: "fixture-env-file", name: "Fixture Env File",
            codec: "dotenv",
            value: "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n"
        ).requestData(requestID: 12, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "env_file_create")
        XCTAssertEqual(params["resource_id"] as? String, "fixture-env-file")
        XCTAssertEqual(params["name"] as? String, "Fixture Env File")
        XCTAssertEqual(params["codec"] as? String, "dotenv")
        XCTAssertEqual(
            params["value"] as? String,
            "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n")
    }

    func testDecodesResourceEntriesWithoutLegacyExportMetadata() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[{"id":"fixture-line","name":"Fixture Line","kind":"shared_secret","shape":"scalar","codec":"opaque","default_env_key":null,"entries":[{"address":"value","label":"Fixture Line","key":null,"sensitive":true}],"source":{"type":"secret_ref","secret_id":"fixture-secret"},"detail":null}],"bindings":[],"surfaces":[]}"#.utf8)

        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.resources.first?.entries.first?.address, "value")
        XCTAssertNil(snapshot.resources.first?.entries.first?.key)
        XCTAssertEqual(snapshot.resources.first?.codec, "opaque")
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
                kind: "dotenv_file", path: "/tmp/fixture-project/.env", input: .bindings([]),
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
        XCTAssertEqual((surface["input"] as? [String: Any])?["type"] as? String, "bindings")
    }

    func testLifecycleRemoveCommandsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let commands: [(ControlCommand, String)] = [
            (.projectRemove("fixture-project"), "project_remove"),
            (.environmentRemove("fixture-environment"), "environment_remove"),
            (.bindingRemove("fixture-binding"), "binding_remove"),
            (.surfaceRemove("fixture-surface"), "surface_remove"),
        ]

        for (offset, item) in commands.enumerated() {
            let data = try item.0.requestData(requestID: UInt64(20 + offset), encoder: encoder)
            let value = try XCTUnwrap(
                JSONSerialization.jsonObject(with: data) as? [String: Any])
            let params = try XCTUnwrap(value["params"] as? [String: Any])
            XCTAssertEqual(value["method"] as? String, item.1)
            XCTAssertNotNil(params["id"] as? String)
        }
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
            #"{"projects":[],"environments":[{"id":"fixture-development","project_id":"fixture-project","name":"Development","position":0}],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-dotenv","environment_id":"fixture-development","name":".env","kind":"dotenv_file","path":"/tmp/fixture/.env","input":{"type":"bindings","binding_ids":[]},"position":0}]}"#.utf8)
        let decoder = JSONDecoder()

        let snapshot = try decoder.decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.environments.first?.projectID, "fixture-project")
        XCTAssertEqual(snapshot.surfaces.first?.environmentID, "fixture-development")
    }

    func testDecodesDirectEnvFileSurfaceFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-direct","environment_id":"fixture-development","name":".env.local","kind":"env_file_direct","path":"/tmp/fixture/.env.local","input":{"type":"resource","resource_id":"fixture-env-file"},"position":1}]}"#.utf8)
        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.surfaces.first?.kind, "env_file_direct")
        XCTAssertEqual(snapshot.surfaces.first?.input.resourceID, "fixture-env-file")
    }
}
