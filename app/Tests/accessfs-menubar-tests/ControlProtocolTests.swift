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

    func testPolicyModeRequestsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let get = try ControlCommand.policyModeGet.requestData(requestID: 70, encoder: encoder)
        let getValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: get) as? [String: Any])
        XCTAssertEqual(getValue["method"] as? String, "policy_mode_get")
        XCTAssertNil(getValue["params"])

        let set = try ControlCommand.policyModeSet(mode: .auditOnly, durationSecs: 3600)
            .requestData(requestID: 71, encoder: encoder)
        let setValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: set) as? [String: Any])
        let params = try XCTUnwrap(setValue["params"] as? [String: Any])
        XCTAssertEqual(setValue["method"] as? String, "policy_mode_set")
        XCTAssertEqual(params["mode"] as? String, "audit_only")
        XCTAssertEqual(params["duration_secs"] as? UInt64, 3600)

        let normal = try JSONDecoder().decode(
            RuntimePolicyStatus.self, from: Data(#"{"mode":"normal"}"#.utf8))
        XCTAssertEqual(normal, .normal)
    }

    func testSshAgentDiscoveryAndResourceRequestsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let discover = try ControlCommand.sshAgentDiscover(
            endpoint: "/private/tmp/fixture-agent.sock"
        ).requestData(requestID: 72, encoder: encoder)
        let discoverValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: discover) as? [String: Any])
        XCTAssertEqual(discoverValue["method"] as? String, "ssh_agent_discover")
        XCTAssertEqual(
            (discoverValue["params"] as? [String: Any])?["endpoint"] as? String,
            "/private/tmp/fixture-agent.sock")

        let resource = CatalogResource(
            id: "fixture-agent", name: "Fixture Agent", kind: "ssh_agent", shape: "socket",
            codec: "opaque", defaultEnvKey: nil,
            entries: [
                CatalogEntry(
                    address: "ssh/sha256/fixture-address", label: "Fixture key", key: nil,
                    sensitive: false)
            ], source: .socket("/private/tmp/fixture-agent.sock"), enforcement: "prompt",
            metadata: .empty)
        let upsert = try ControlCommand.resourceUpsert(resource)
            .requestData(requestID: 73, encoder: encoder)
        let upsertValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: upsert) as? [String: Any])
        let encodedResource = try XCTUnwrap(
            (upsertValue["params"] as? [String: Any])?["resource"] as? [String: Any])
        XCTAssertEqual(upsertValue["method"] as? String, "resource_upsert")
        XCTAssertEqual(encodedResource["kind"] as? String, "ssh_agent")
        XCTAssertEqual(
            (encodedResource["source"] as? [String: Any])?["endpoint"] as? String,
            "/private/tmp/fixture-agent.sock")

        let response = try JSONDecoder().decode(
            ControlResponseEnvelope<[DiscoveredSshIdentity]>.self,
            from: Data(
                #"{"request_id":72,"status":"ok","result":{"type":"ssh_agent_identities","value":[{"address":"ssh/sha256/fixture-address","fingerprint":"SHA256:fixture","comment":"Fixture key"}]}}"#.utf8))
        XCTAssertEqual(response.result?.value?.first?.comment, "Fixture key")
    }

    func testFileProtectRequestCarriesOnlyTheSelectedPath() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.fileProtect("/fixture/project/.env")
            .requestData(requestID: 71, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "file_protect")
        XCTAssertEqual(params["path"] as? String, "/fixture/project/.env")
        XCTAssertEqual(params.count, 1)
    }

    func testDecodesProtectedFileMetadataWithoutPlaintext() throws {
        let data = Data(
            #"{"id":"00000000-0000-0000-0000-000000000001","source_path":"/fixture/project/.env","mode":384,"size":42,"current_version":3,"linked":true,"enforcement":"touchid","metadata":{"note":"Local app environment","links":[]}}"#.utf8)

        let file = try JSONDecoder().decode(CatalogProtectedFile.self, from: data)

        XCTAssertEqual(file.sourcePath, "/fixture/project/.env")
        XCTAssertEqual(file.mode, 0o600)
        XCTAssertEqual(file.size, 42)
        XCTAssertEqual(file.currentVersion, 3)
        XCTAssertTrue(file.linked)
        XCTAssertEqual(file.enforcement, "touchid")
    }

    func testProtectedFileMaintenanceRequestsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let history = try ControlCommand.protectedFileHistory("fixture-secret")
            .requestData(requestID: 72, encoder: encoder)
        let historyValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: history) as? [String: Any])
        XCTAssertEqual(historyValue["method"] as? String, "protected_file_history")
        XCTAssertEqual(
            (historyValue["params"] as? [String: Any])?["id"] as? String,
            "fixture-secret")

        let rollback = try ControlCommand.protectedFileRollback(
            id: "fixture-secret", version: 2
        ).requestData(requestID: 73, encoder: encoder)
        let rollbackValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: rollback) as? [String: Any])
        let rollbackParams = try XCTUnwrap(rollbackValue["params"] as? [String: Any])
        XCTAssertEqual(rollbackValue["method"] as? String, "protected_file_rollback")
        XCTAssertEqual(rollbackParams["id"] as? String, "fixture-secret")
        XCTAssertEqual(rollbackParams["version"] as? UInt32, 2)

        let update = try ControlCommand.protectedFileMetadataUpdate(
            id: "fixture-secret", enforcement: "allow", metadata: .empty
        ).requestData(requestID: 731, encoder: encoder)
        let updateValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: update) as? [String: Any])
        let updateParams = try XCTUnwrap(updateValue["params"] as? [String: Any])
        XCTAssertEqual(updateValue["method"] as? String, "protected_file_metadata_update")
        XCTAssertEqual(updateParams["enforcement"] as? String, "allow")

        let restore = try ControlCommand.fileRestore("fixture-secret")
            .requestData(requestID: 74, encoder: encoder)
        let restoreValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: restore) as? [String: Any])
        XCTAssertEqual(restoreValue["method"] as? String, "file_restore")
        XCTAssertEqual(
            (restoreValue["params"] as? [String: Any])?["id"] as? String,
            "fixture-secret")
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
            value: "fixture-host|5432|fixture-db|fixture-user|fixture-value",
            enforcement: "allow",
            metadata: ItemMetadata(note: "Reporting database", links: [])
        ).requestData(requestID: 9, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "shared_secret_create")
        XCTAssertNil(params["default_env_key"])
        XCTAssertEqual(params["enforcement"] as? String, "allow")
        XCTAssertEqual(
            params["value"] as? String,
            "fixture-host|5432|fixture-db|fixture-user|fixture-value")
        XCTAssertEqual((params["metadata"] as? [String: Any])?["note"] as? String, "Reporting database")
    }

    func testSharedSecretMaintenanceRequestsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let update = try ControlCommand.sharedSecretUpdate(
            resourceID: "fixture-secret", name: "Renamed Secret",
            defaultEnvKey: "RENAMED_TOKEN", value: "fixture-value-three",
            enforcement: "touchid",
            metadata: .empty
        ).requestData(requestID: 91, encoder: encoder)
        let updateValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: update) as? [String: Any])
        let updateParams = try XCTUnwrap(updateValue["params"] as? [String: Any])
        XCTAssertEqual(updateValue["method"] as? String, "shared_secret_update")
        XCTAssertEqual(updateParams["resource_id"] as? String, "fixture-secret")
        XCTAssertEqual(updateParams["name"] as? String, "Renamed Secret")
        XCTAssertEqual(updateParams["default_env_key"] as? String, "RENAMED_TOKEN")
        XCTAssertEqual(updateParams["value"] as? String, "fixture-value-three")
        XCTAssertEqual(updateParams["enforcement"] as? String, "touchid")

        let remove = try ControlCommand.sharedSecretRemove(resourceID: "fixture-secret")
            .requestData(requestID: 92, encoder: encoder)
        let removeValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: remove) as? [String: Any])
        let removeParams = try XCTUnwrap(removeValue["params"] as? [String: Any])
        XCTAssertEqual(removeValue["method"] as? String, "shared_secret_remove")
        XCTAssertEqual(removeParams["resource_id"] as? String, "fixture-secret")
    }

    func testEnvFileCreateRequestCarriesPlaintextOnlyInTheControlBody() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.envFileCreate(
            resourceID: "fixture-env-file", name: "Fixture Env File",
            codec: "dotenv",
            value: "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n",
            enforcement: "prompt",
            metadata: .empty
        ).requestData(requestID: 12, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])

        XCTAssertEqual(value["method"] as? String, "env_file_create")
        XCTAssertEqual(params["resource_id"] as? String, "fixture-env-file")
        XCTAssertEqual(params["name"] as? String, "Fixture Env File")
        XCTAssertEqual(params["codec"] as? String, "dotenv")
        XCTAssertEqual(params["enforcement"] as? String, "prompt")
        XCTAssertEqual(
            params["value"] as? String,
            "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n")
    }

    func testDecodesResourceEntriesWithoutLegacyExportMetadata() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[{"id":"fixture-line","name":"Fixture Line","kind":"shared_secret","shape":"scalar","codec":"opaque","default_env_key":null,"entries":[{"address":"value","label":"Fixture Line","key":null,"sensitive":true}],"source":{"type":"secret_ref","secret_id":"fixture-secret"},"enforcement":"prompt","metadata":{}}],"bindings":[],"surfaces":[]}"#.utf8)

        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.resources.first?.entries.first?.address, "value")
        XCTAssertNil(snapshot.resources.first?.entries.first?.key)
        XCTAssertEqual(snapshot.resources.first?.codec, "opaque")
        XCTAssertEqual(snapshot.resources.first?.enforcement, "prompt")
        XCTAssertEqual(snapshot.resources.first?.metadata, .empty)
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
        XCTAssertEqual(surface["enforcement"] as? String, "prompt")
    }

    func testLifecycleRemoveCommandsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let commands: [(ControlCommand, String)] = [
            (.projectRemove("fixture-project"), "project_remove"),
            (.environmentRemove("fixture-environment"), "environment_remove"),
            (.resourceRemove("fixture-resource"), "resource_remove"),
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
            #"{"projects":[],"environments":[{"id":"fixture-development","project_id":"fixture-project","name":"Development","position":0}],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-dotenv","environment_id":"fixture-development","name":".env","kind":"dotenv_file","path":"/tmp/fixture/.env","input":{"type":"bindings","binding_ids":[]},"enforcement":"allow","position":0}]}"#.utf8)
        let decoder = JSONDecoder()

        let snapshot = try decoder.decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.environments.first?.projectID, "fixture-project")
        XCTAssertEqual(snapshot.surfaces.first?.environmentID, "fixture-development")
        XCTAssertEqual(snapshot.surfaces.first?.enforcement, "allow")
    }

    func testDecodesDirectEnvFileSurfaceFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-direct","environment_id":"fixture-development","name":".env.local","kind":"env_file_direct","path":"/tmp/fixture/.env.local","input":{"type":"resource","resource_id":"fixture-env-file"},"enforcement":"touchid","position":1}]}"#.utf8)
        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.surfaces.first?.kind, "env_file_direct")
        XCTAssertEqual(snapshot.surfaces.first?.input.resourceID, "fixture-env-file")
        XCTAssertEqual(snapshot.surfaces.first?.enforcement, "touchid")
    }

    func testDecodesIniSurfaceFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-ini","environment_id":"fixture-development","name":"credentials.ini","kind":"ini_file","path":"/tmp/fixture/credentials.ini","input":{"type":"bindings","binding_ids":["fixture-binding"]},"enforcement":"prompt","position":1}]}"#.utf8)
        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.surfaces.first?.kind, "ini_file")
        XCTAssertEqual(snapshot.surfaces.first?.input.bindingIDs, ["fixture-binding"])
    }

    func testDecodesDirenvSurfaceFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-direnv","environment_id":"fixture-development","name":".envrc","kind":"direnv_file","path":"/tmp/fixture/.envrc","input":{"type":"bindings","binding_ids":["fixture-binding"]},"enforcement":"allow","position":1}]}"#.utf8)
        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.surfaces.first?.kind, "direnv_file")
        XCTAssertEqual(snapshot.surfaces.first?.name, ".envrc")
    }
}
