import XCTest

@testable import floria_menubar

final class ControlProtocolTests: XCTestCase {
    func testPingReportsCompatibilityVersions() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.ping.requestData(requestID: 6, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(request["request_id"] as? UInt64, 6)
        XCTAssertEqual(request["method"] as? String, "ping")
        XCTAssertNil(request["params"])

        let response = Data(
            #"{"request_id":6,"status":"ok","result":{"type":"pong","value":{"protocol_version":2,"daemon_version":"0.1.0","schema_version":12,"minimum_schema_version":12,"store_format_version":2,"minimum_store_format_version":1}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<ControlServerInfo>.self, from: response)
        let info = try XCTUnwrap(decoded.result?.value)

        XCTAssertEqual(info.protocolVersion, supportedControlProtocolVersion)
        XCTAssertEqual(info.daemonVersion, "0.1.0")
        XCTAssertEqual(info.schemaVersion, 12)
        XCTAssertEqual(info.minimumSchemaVersion, 12)
        XCTAssertEqual(info.storeFormatVersion, 2)
        XCTAssertEqual(info.minimumStoreFormatVersion, 1)
    }

    func testHealthRequestAndRedactedReportMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.health.requestData(requestID: 61, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(request["method"] as? String, "health")
        XCTAssertNil(request["params"])

        let response = Data(
            #"{"request_id":61,"status":"ok","result":{"type":"health","value":{"status":"warning","checks":[{"id":"disk","status":"warning","title":"Storage space","message":"512 MB available.","guidance":"Free disk space soon."}]}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<SystemHealthReport>.self, from: response)
        let report = try XCTUnwrap(decoded.result?.value)

        XCTAssertEqual(report.status, .warning)
        XCTAssertEqual(report.issues.map(\.id), ["disk"])
        XCTAssertFalse(String(decoding: response, as: UTF8.self).contains("/Users/"))
    }

    func testControlProtocolCompatibilityRejectsOldOrNewDaemons() throws {
        XCTAssertNoThrow(try validateControlProtocolVersion(supportedControlProtocolVersion))

        for daemonVersion: UInt32? in [nil, supportedControlProtocolVersion + 1] {
            XCTAssertThrowsError(try validateControlProtocolVersion(daemonVersion)) { error in
                guard let error = error as? ControlClientError else {
                    return XCTFail("Expected ControlClientError, received \(error)")
                }
                XCTAssertTrue(error.isCompatibilityFailure)
                XCTAssertTrue(error.localizedDescription.contains("Restart Floria"))
            }
        }
    }

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

    func testDiscoverRequestAndRedactedPlanMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.discover(paths: ["/fixture/project"])
            .requestData(requestID: 8, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(request["params"] as? [String: Any])

        XCTAssertEqual(request["method"] as? String, "discover")
        XCTAssertEqual(params["paths"] as? [String], ["/fixture/project"])
        XCTAssertEqual(params.count, 1)

        let response = Data(
            #"{"request_id":8,"status":"ok","result":{"type":"discovery","value":{"paths":["/fixture/project"],"projects":[{"name":"project","path":"/fixture/project","markers":[{"kind":"git","path":"/fixture/project/.git"}],"ecosystems":[]}],"files":[{"path":"/fixture/project/.env","relative_path":".env","assignment":{"state":"assigned","project_path":"/fixture/project","candidate_project_paths":[]},"kind":"dotenv","codec":"dotenv","environment":"development","tags":["dotenv","development"],"entries":[{"address":"keys/API_TOKEN","key":"API_TOKEN","section":null,"action":{"type":"reuse_shared_secret","resource_id":"fixture-shared","resource_name":"Fixture Shared Secret"}}],"warnings":[],"action":"compose"}],"summary":{"files":1,"entries":1,"new_secrets":0,"reused_secrets":1,"missing_reference_entries":0,"warnings":0}}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<DiscoveryPlan>.self, from: response)
        let plan = try XCTUnwrap(decoded.result?.value)

        XCTAssertEqual(plan.files.first?.relativePath, ".env")
        XCTAssertEqual(plan.files.first?.entries.first?.action.resourceID, "fixture-shared")
        XCTAssertEqual(
            plan.files.first?.entries.first?.action.resourceName,
            "Fixture Shared Secret")
        XCTAssertEqual(plan.summary.reusedSecrets, 1)
        XCTAssertFalse(String(decoding: response, as: UTF8.self).contains("secret_value"))
    }

    func testAsynchronousDiscoveryCommandsAndProgressMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let startData = try ControlCommand.discoverStart(paths: ["/fixture/workspace"])
            .requestData(requestID: 81, encoder: encoder)
        let start = try XCTUnwrap(
            JSONSerialization.jsonObject(with: startData) as? [String: Any])
        XCTAssertEqual(start["method"] as? String, "discover_start")
        XCTAssertEqual(
            (start["params"] as? [String: Any])?["paths"] as? [String],
            ["/fixture/workspace"])

        for (command, method) in [
            (ControlCommand.discoverStatus(id: "discover-1"), "discover_status"),
            (.discoverCancel(id: "discover-1"), "discover_cancel"),
        ] {
            let data = try command.requestData(requestID: 82, encoder: encoder)
            let request = try XCTUnwrap(
                JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(request["method"] as? String, method)
            XCTAssertEqual(
                (request["params"] as? [String: Any])?["id"] as? String,
                "discover-1")
        }

        let response = Data(
            #"{"request_id":82,"status":"ok","result":{"type":"discovery_job","value":{"id":"discover-1","state":"running","progress":{"phase":"candidate_files","directories_scanned":64,"candidate_files":5,"project_candidates":2,"files_parsed":0}}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<DiscoveryJobStatus>.self, from: response)
        let status = try XCTUnwrap(decoded.result?.value)

        XCTAssertEqual(decoded.result?.type, "discovery_job")
        XCTAssertEqual(status.id, "discover-1")
        XCTAssertEqual(status.state, .running)
        XCTAssertFalse(status.state.isTerminal)
        XCTAssertEqual(status.progress.phase, .candidateFiles)
        XCTAssertEqual(status.progress.directoriesScanned, 64)
        XCTAssertEqual(status.progress.candidateFiles, 5)
        XCTAssertEqual(status.progress.projectCandidates, 2)
        XCTAssertNil(status.plan)
        XCTAssertNil(status.error)
    }

    func testDiscoveryCandidateGroupingMatchesRustWireShape() throws {
        let create = try JSONDecoder().decode(
            DiscoveredEntryAction.self,
            from: Data(
                #"{"type":"create_shared_secret","group_id":"discovered-1"}"#.utf8))
        let reuse = try JSONDecoder().decode(
            DiscoveredEntryAction.self,
            from: Data(
                #"{"type":"reuse_discovered_secret","group_id":"discovered-1"}"#.utf8))

        XCTAssertEqual(create.type, "create_shared_secret")
        XCTAssertEqual(create.groupID, "discovered-1")
        XCTAssertEqual(reuse.type, "reuse_discovered_secret")
        XCTAssertEqual(reuse.groupID, create.groupID)
    }

    func testManagedDiscoveryProjectMatchesRustWireShape() throws {
        let project = try JSONDecoder().decode(
            DiscoveredProject.self,
            from: Data(
                #"{"name":"project","path":"/fixture/project","markers":[],"ecosystems":[],"managed_project_id":"fixture-project"}"#.utf8))

        XCTAssertEqual(project.managedProjectID, "fixture-project")
    }

    func testManagedDiscoveryItemsMatchRustWireShape() throws {
        let response = Data(
            #"{"request_id":8,"status":"ok","result":{"type":"discovery","value":{"paths":["/fixture/project"],"projects":[{"name":"project","path":"/fixture/project","markers":[],"ecosystems":[],"managed_project_id":"fixture-project"}],"files":[],"summary":{"files":0,"entries":0,"new_secrets":0,"reused_secrets":0,"missing_reference_entries":0,"warnings":0},"managed_items":[{"id":"fixture-surface","path":"/fixture/project/.env","relative_path":".env","project_path":"/fixture/project","environment":"Development","kind":"surface","status":"linked"},{"id":"fixture-protected","path":"/fixture/project/client.p12","relative_path":"client.p12","project_path":"/fixture/project","kind":"protected_file","status":"missing"}]}}}"#.utf8)

        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<DiscoveryPlan>.self, from: response)
        let plan = try XCTUnwrap(decoded.result?.value)

        XCTAssertEqual(plan.managedItems.count, 2)
        XCTAssertEqual(plan.managedItems[0].kind, .surface)
        XCTAssertEqual(plan.managedItems[0].status, .linked)
        XCTAssertEqual(plan.managedItems[0].environment, "Development")
        XCTAssertEqual(plan.managedItems[1].kind, .protectedFile)
        XCTAssertEqual(plan.managedItems[1].status, .missing)
    }

    func testDiscoverApplyRequestAndResultMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.discoverApply(
            paths: ["/fixture/project"],
            imports: [
                DiscoveryImport(
                    path: "/fixture/project/.dev.vars",
                    destination: .projectFile(projectPath: "/fixture/project"),
                    sourceDisposition: .protectInPlace),
                DiscoveryImport(
                    path: "/fixture/project/.env",
                    destination: .projectOutput(
                        projectPath: "/fixture/project",
                        outputPath: "/fixture/project/.env"),
                    sourceDisposition: .replaceWithSurface),
                DiscoveryImport(
                    path: "/fixture/project/.env.production",
                    destination: .projectOutputs(
                        outputs: [
                            DiscoveryProjectOutput(
                                projectPath: "/fixture/project",
                                outputPath: "/fixture/project/.env.production"),
                            DiscoveryProjectOutput(
                                projectPath: "/fixture/worker",
                                outputPath: "/fixture/worker/.env.production"),
                        ]),
                    sourceDisposition: .replaceWithSurface),
            ],
            separateEntries: [
                DiscoverySeparateEntry(
                    path: "/fixture/project/.env.production",
                    address: "keys/API_TOKEN")
            ],
            promoteEntries: [],
            demoteEntries: [])
            .requestData(requestID: 9, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(request["method"] as? String, "discover_apply")
        XCTAssertEqual(
            (request["params"] as? [String: Any])?["paths"] as? [String],
            ["/fixture/project"])
        let imports = try XCTUnwrap(
            (request["params"] as? [String: Any])?["imports"] as? [[String: Any]])
        XCTAssertEqual(imports.count, 3)
        XCTAssertEqual(
            (imports[0]["destination"] as? [String: Any])?["type"] as? String,
            "project_file")
        XCTAssertEqual(imports[0]["source_disposition"] as? String, "protect_in_place")
        XCTAssertEqual(
            (imports[1]["destination"] as? [String: Any])?["type"] as? String,
            "project_output")
        XCTAssertEqual(imports[1]["source_disposition"] as? String, "replace_with_surface")
        XCTAssertEqual(
            (imports[2]["destination"] as? [String: Any])?["type"] as? String,
            "project_outputs")
        let separateEntries = try XCTUnwrap(
            (request["params"] as? [String: Any])?["separate_entries"]
                as? [[String: String]])
        XCTAssertEqual(separateEntries.first?["path"], "/fixture/project/.env.production")
        XCTAssertEqual(separateEntries.first?["address"], "keys/API_TOKEN")

        let response = Data(
            #"{"request_id":9,"status":"ok","result":{"type":"discovery_applied","value":{"project_id":"fixture-project","project_ids":["fixture-project"],"created_resources":2,"reused_resources":1,"protected_files":1,"imported_ssh_identities":0,"files":[{"path":"/fixture/project/.env","outcome":"imported","detail":"Imported as reusable secrets and a composed output"}]}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<DiscoveryApplyResult>.self, from: response)
        let result = try XCTUnwrap(decoded.result?.value)
        XCTAssertEqual(result.projectID, "fixture-project")
        XCTAssertEqual(result.projectIDs, ["fixture-project"])
        XCTAssertEqual(result.createdResources, 2)
        XCTAssertEqual(result.files.first?.outcome, "imported")
    }

    func testDiscoverReferenceResolveRequestAndResultMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.discoverReferenceResolve(
            surfaceID: "fixture-surface",
            key: "API_TOKEN",
            source: .newSharedSecret(
                name: "API token", value: "fixture-reference-value",
                enforcement: "prompt", metadata: .empty)
        )
        .requestData(requestID: 10, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(request["params"] as? [String: Any])
        let source = try XCTUnwrap(params["source"] as? [String: Any])

        XCTAssertEqual(request["method"] as? String, "discover_reference_resolve")
        XCTAssertEqual(params["surface_id"] as? String, "fixture-surface")
        XCTAssertEqual(params["key"] as? String, "API_TOKEN")
        XCTAssertEqual(source["type"] as? String, "new_shared_secret")
        XCTAssertEqual(source["value"] as? String, "fixture-reference-value")

        let response = Data(
            #"{"request_id":10,"status":"ok","result":{"type":"discovery_reference_resolved","value":{"surface_id":"fixture-surface","resource_id":"fixture-resource","binding_id":"fixture-binding","key":"API_TOKEN"}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<DiscoveryReferenceResolution>.self, from: response)
        let result = try XCTUnwrap(decoded.result?.value)
        XCTAssertEqual(result.resourceID, "fixture-resource")
        XCTAssertEqual(result.bindingID, "fixture-binding")
    }

    func testDiscoveryReviewOnlyActionMatchesRustWireShape() throws {
        let file = try JSONDecoder().decode(
            DiscoveredFile.self,
            from: Data(
                #"{"path":"/fixture/project/mise.toml","relative_path":"mise.toml","assignment":{"state":"assigned","project_path":"/fixture/project","candidate_project_paths":[]},"kind":"mise","codec":"dotenv","environment":"development","tags":["mise","development"],"entries":[],"warnings":[],"action":"review"}"#.utf8))

        XCTAssertEqual(file.action, .review)
    }

    func testDiscoveryReferenceActionMatchesRustWireShape() throws {
        let file = try JSONDecoder().decode(
            DiscoveredFile.self,
            from: Data(
                #"{"path":"/fixture/project/.env.example","relative_path":".env.example","assignment":{"state":"assigned","project_path":"/fixture/project","candidate_project_paths":[]},"kind":"dotenv","codec":"dotenv","environment":"development","tags":["dotenv","development","reference"],"entries":[{"address":"keys/API_TOKEN","key":"API_TOKEN","section":null,"action":{"type":"reference_entry","matched":false}}],"warnings":[],"action":"reference"}"#.utf8))

        XCTAssertEqual(file.action, .reference)
        XCTAssertEqual(file.environment, "development")
        XCTAssertEqual(file.entries.first?.action.type, "reference_entry")
        XCTAssertEqual(file.entries.first?.action.matched, false)
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

    func testActiveGrantRequestsAndResultMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let list = try ControlCommand.grantList.requestData(requestID: 170, encoder: encoder)
        let listValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: list) as? [String: Any])
        XCTAssertEqual(listValue["method"] as? String, "grant_list")
        XCTAssertNil(listValue["params"])

        let revoke = try ControlCommand.grantRevoke(id: "fixture-grant")
            .requestData(requestID: 171, encoder: encoder)
        let revokeValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: revoke) as? [String: Any])
        XCTAssertEqual(revokeValue["method"] as? String, "grant_revoke")
        XCTAssertEqual(
            (revokeValue["params"] as? [String: Any])?["id"] as? String,
            "fixture-grant")

        let clear = try ControlCommand.grantClear.requestData(requestID: 172, encoder: encoder)
        let clearValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: clear) as? [String: Any])
        XCTAssertEqual(clearValue["method"] as? String, "grant_clear")
        XCTAssertNil(clearValue["params"])

        let response = Data(
            #"{"request_id":170,"status":"ok","result":{"type":"active_grants","value":[{"id":"fixture-grant","subject":"exe:/usr/bin/cat","object":"secrets/fixture","operation":"read","enforcement":"prompt","expires_at":1800000600,"client":"cat","executable":"/usr/bin/cat","bundle_id":null,"target":"~/.pgpass"}]}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<[ActiveGrant]>.self, from: response)
        let grant = try XCTUnwrap(decoded.result?.value?.first)

        XCTAssertEqual(decoded.result?.type, "active_grants")
        XCTAssertEqual(grant.client, "cat")
        XCTAssertEqual(grant.target, "~/.pgpass")
        XCTAssertEqual(grant.expirationDate.timeIntervalSince1970, 1_800_000_600)
    }

    func testAccessHistoryRequestAndResultMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.accessHistory(limit: 500)
            .requestData(requestID: 72, encoder: encoder)
        let request = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        let params = try XCTUnwrap(request["params"] as? [String: Any])

        XCTAssertEqual(request["method"] as? String, "access_history")
        XCTAssertEqual(params["limit"] as? Int, 500)

        let response = Data(
            #"{"request_id":72,"status":"ok","result":{"type":"access_history","value":[{"ts":"2026-07-24T10:20:30.123Z","path":"surfaces/project-env","display":"/Users/me/project/.env","operation":"read","decision":"allowed","rule_id":"surface:project-env","policy":{"configured_enforcement":"prompt","effective_enforcement":"allow","mode":"audit_only"},"ssh":null,"identity":{"pid":42,"uid":501,"exe":"/usr/bin/cat","cwd":"/Users/me/project","cmdline":["cat",".env"],"bundle_id":null,"team_id":null,"repo":"/Users/me/project","parent_chain":[{"pid":42,"name":"cat","exe":"/usr/bin/cat"}],"chain":"zsh -> cat"}}]}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<[AccessEventMsg]>.self, from: response)
        let event = try XCTUnwrap(decoded.result?.value?.first)

        XCTAssertEqual(decoded.result?.type, "access_history")
        XCTAssertEqual(event.display, "/Users/me/project/.env")
        XCTAssertEqual(event.policy?.mode, "audit_only")
        XCTAssertEqual(event.identity.parent_chain?.first?.name, "cat")
    }

    func testBackupRequestsAndReportMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let createData = try ControlCommand.backupCreate(
            destination: "/tmp/floria-backup"
        ).requestData(requestID: 18, encoder: encoder)
        let create = try XCTUnwrap(
            JSONSerialization.jsonObject(with: createData) as? [String: Any])
        XCTAssertEqual(create["method"] as? String, "backup_create")
        XCTAssertEqual(
            (create["params"] as? [String: Any])?["destination"] as? String,
            "/tmp/floria-backup")

        let verifyData = try ControlCommand.backupVerify(
            backup: "/tmp/floria-backup"
        ).requestData(requestID: 19, encoder: encoder)
        let verify = try XCTUnwrap(
            JSONSerialization.jsonObject(with: verifyData) as? [String: Any])
        XCTAssertEqual(verify["method"] as? String, "backup_verify")
        XCTAssertEqual(
            (verify["params"] as? [String: Any])?["backup"] as? String,
            "/tmp/floria-backup")

        let response = Data(
            #"{"request_id":19,"status":"ok","result":{"type":"backup","value":{"path":"/tmp/floria-backup","catalog_schema":5,"projects":2,"resources":3,"secrets":4,"versions":5,"plaintext_bytes":6,"files":7}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<BackupReport>.self, from: response)
        let report = try XCTUnwrap(decoded.result?.value)
        XCTAssertEqual(decoded.result?.type, "backup")
        XCTAssertEqual(report.path, "/tmp/floria-backup")
        XCTAssertEqual(report.versions, 5)
        XCTAssertEqual(report.plaintextBytes, 6)
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
            ], source: .socket, enforcement: "prompt",
            metadata: .empty, origin: nil)
        let upsert = try ControlCommand.resourceUpsert(
            resource, endpoint: "/private/tmp/fixture-agent.sock")
            .requestData(requestID: 73, encoder: encoder)
        let upsertValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: upsert) as? [String: Any])
        let encodedResource = try XCTUnwrap(
            (upsertValue["params"] as? [String: Any])?["resource"] as? [String: Any])
        XCTAssertEqual(upsertValue["method"] as? String, "resource_upsert")
        XCTAssertEqual(encodedResource["kind"] as? String, "ssh_agent")
        XCTAssertNil((encodedResource["source"] as? [String: Any])?["endpoint"])
        XCTAssertEqual(
            (upsertValue["params"] as? [String: Any])?["endpoint"] as? String,
            "/private/tmp/fixture-agent.sock")

        let response = try JSONDecoder().decode(
            ControlResponseEnvelope<[DiscoveredSshIdentity]>.self,
            from: Data(
                #"{"request_id":72,"status":"ok","result":{"type":"ssh_agent_identities","value":[{"address":"ssh/sha256/fixture-address","fingerprint":"SHA256:fixture","comment":"Fixture key"}]}}"#.utf8))
        XCTAssertEqual(response.result?.value?.first?.comment, "Fixture key")
    }

    func testManagedSshIdentityRequestsMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let imported = try ControlCommand.sshIdentityImport(
            resourceID: "fixture-identity", name: "Fixture identity",
            path: "/private/tmp/fixture-id_ed25519", passphrase: "fixture passphrase",
            enforcement: "touchid", metadata: .empty
        ).requestData(requestID: 75, encoder: encoder)
        let value = try XCTUnwrap(
            JSONSerialization.jsonObject(with: imported) as? [String: Any])
        let params = try XCTUnwrap(value["params"] as? [String: Any])
        XCTAssertEqual(value["method"] as? String, "ssh_identity_import")
        XCTAssertEqual(params["resource_id"] as? String, "fixture-identity")
        XCTAssertEqual(params["path"] as? String, "/private/tmp/fixture-id_ed25519")
        XCTAssertEqual(params["passphrase"] as? String, "fixture passphrase")
        XCTAssertNil(params["private_key"])

        let removed = try ControlCommand.sshIdentityRemove(resourceID: "fixture-identity")
            .requestData(requestID: 76, encoder: encoder)
        let removedValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: removed) as? [String: Any])
        XCTAssertEqual(removedValue["method"] as? String, "ssh_identity_remove")
        XCTAssertEqual(
            (removedValue["params"] as? [String: Any])?["resource_id"] as? String,
            "fixture-identity")
    }

    func testSshConfigIntegrationRequestsAndStatusMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        for (command, method) in [
            (ControlCommand.sshConfigStatus, "ssh_config_status"),
            (.sshConfigInstall, "ssh_config_install"),
            (.sshConfigRemove, "ssh_config_remove"),
        ] {
            let data = try command.requestData(requestID: 74, encoder: encoder)
            let value = try XCTUnwrap(
                JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(value["method"] as? String, method)
            XCTAssertNil(value["params"])
        }

        let status = try JSONDecoder().decode(
            SshConfigIntegrationStatus.self,
            from: Data(
                #"{"state":"managed","writable":true,"user_config":"/fixture/.ssh/config","generated_config":"/fixture/floria/ssh/config","include_line":"Include \"/fixture/floria/ssh/config\""}"#.utf8))
        XCTAssertEqual(status.state, .managed)
        XCTAssertTrue(status.writable)
        XCTAssertEqual(status.userConfig, "/fixture/.ssh/config")
        XCTAssertEqual(status.includeLine, #"Include "/fixture/floria/ssh/config""#)
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
            #"{"id":"00000000-0000-0000-0000-000000000001","source_path":"/fixture/project/.env","mode":384,"size":42,"current_version":3,"linked":true,"enforcement":"touchid","environment_ids":["fixture-development"],"metadata":{"note":"Local app environment","links":[]}}"#.utf8)

        let file = try JSONDecoder().decode(CatalogProtectedFile.self, from: data)

        XCTAssertEqual(file.sourcePath, "/fixture/project/.env")
        XCTAssertEqual(file.mode, 0o600)
        XCTAssertEqual(file.size, 42)
        XCTAssertEqual(file.currentVersion, 3)
        XCTAssertTrue(file.linked)
        XCTAssertEqual(file.enforcement, "touchid")
        XCTAssertEqual(file.environmentIDs, ["fixture-development"])
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
            id: "fixture-secret", enforcement: "allow",
            environmentIDs: ["fixture-development", "fixture-staging"], metadata: .empty
        ).requestData(requestID: 731, encoder: encoder)
        let updateValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: update) as? [String: Any])
        let updateParams = try XCTUnwrap(updateValue["params"] as? [String: Any])
        XCTAssertEqual(updateValue["method"] as? String, "protected_file_metadata_update")
        XCTAssertEqual(updateParams["enforcement"] as? String, "allow")
        XCTAssertEqual(
            updateParams["environment_ids"] as? [String],
            ["fixture-development", "fixture-staging"])

        let contentsUpdate = try ControlCommand.protectedFileContentsUpdate(
            id: "fixture-secret", path: "/fixture/replacement.p12"
        ).requestData(requestID: 7311, encoder: encoder)
        let contentsUpdateValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: contentsUpdate) as? [String: Any])
        let contentsUpdateParams = try XCTUnwrap(
            contentsUpdateValue["params"] as? [String: Any])
        XCTAssertEqual(
            contentsUpdateValue["method"] as? String,
            "protected_file_contents_update")
        XCTAssertEqual(contentsUpdateParams["id"] as? String, "fixture-secret")
        XCTAssertEqual(contentsUpdateParams["path"] as? String, "/fixture/replacement.p12")
        XCTAssertEqual(contentsUpdateParams.count, 2)

        let configure = try ControlCommand.managedFileConfigure(
            id: "fixture-secret", projectID: "fixture-project",
            environmentID: "fixture-development"
        ).requestData(requestID: 732, encoder: encoder)
        let configureValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: configure) as? [String: Any])
        let configureParams = try XCTUnwrap(configureValue["params"] as? [String: Any])
        XCTAssertEqual(configureValue["method"] as? String, "managed_file_configure")
        XCTAssertEqual(configureParams["id"] as? String, "fixture-secret")
        XCTAssertEqual(configureParams["project_id"] as? String, "fixture-project")
        XCTAssertEqual(configureParams["environment_id"] as? String, "fixture-development")

        let restoreManaged = try ControlCommand.managedFileRestore("fixture-surface")
            .requestData(requestID: 733, encoder: encoder)
        let restoreManagedValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: restoreManaged) as? [String: Any])
        XCTAssertEqual(restoreManagedValue["method"] as? String, "managed_file_restore")
        XCTAssertEqual(
            (restoreManagedValue["params"] as? [String: Any])?["id"] as? String,
            "fixture-surface")

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

    func testProjectCheckoutRequestsAndDiscoveryMatchRustWireShape() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        let inventory = try ControlCommand.projectCheckoutInventory
            .requestData(requestID: 30, encoder: encoder)
        let inventoryValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: inventory) as? [String: Any])
        XCTAssertEqual(inventoryValue["method"] as? String, "project_checkout_inventory")
        XCTAssertNil(inventoryValue["params"])

        let discover = try ControlCommand.projectCheckoutDiscover(projectID: "fixture-project")
            .requestData(requestID: 31, encoder: encoder)
        let discoverValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: discover) as? [String: Any])
        XCTAssertEqual(discoverValue["method"] as? String, "project_checkout_discover")
        XCTAssertEqual(
            (discoverValue["params"] as? [String: Any])?["project_id"] as? String,
            "fixture-project")

        let checkout = CatalogProjectCheckout(
            id: "fixture-worktree", projectID: "fixture-project",
            path: "/tmp/fixture-worktree", environmentID: "fixture-development",
            kind: .worktree, gitCommonDir: "/tmp/fixture/.git")
        let upsert = try ControlCommand.projectCheckoutUpsert(checkout)
            .requestData(requestID: 32, encoder: encoder)
        let upsertValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: upsert) as? [String: Any])
        let encodedCheckout = try XCTUnwrap(
            (upsertValue["params"] as? [String: Any])?["checkout"] as? [String: Any])
        XCTAssertEqual(upsertValue["method"] as? String, "project_checkout_upsert")
        XCTAssertEqual(encodedCheckout["environment_id"] as? String, "fixture-development")
        XCTAssertEqual(encodedCheckout["kind"] as? String, "worktree")

        let repair = try ControlCommand.managedLinkRepair(
            path: "/tmp/fixture-worktree/.envrc"
        ).requestData(requestID: 33, encoder: encoder)
        let repairValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: repair) as? [String: Any])
        XCTAssertEqual(
            repairValue["method"] as? String,
            "managed_link_repair")
        XCTAssertEqual(
            (repairValue["params"] as? [String: Any])?["path"] as? String,
            "/tmp/fixture-worktree/.envrc")

        let response = Data(
            #"{"request_id":31,"status":"ok","result":{"type":"project_checkout_discovery","value":{"project_id":"fixture-project","common_dir":"/tmp/fixture/.git","checkouts":[{"path":"/tmp/fixture","git_primary":true,"managed_checkout_id":"fixture-project","link_issues":[]},{"path":"/tmp/fixture-worktree","git_primary":false,"managed_checkout_id":"fixture-worktree","link_issues":["/tmp/fixture-worktree/.envrc"]}]}}}"#.utf8)
        let decoded = try JSONDecoder().decode(
            ControlResponseEnvelope<ProjectCheckoutDiscovery>.self, from: response)
        let result = try XCTUnwrap(decoded.result?.value)
        XCTAssertEqual(result.projectID, "fixture-project")
        XCTAssertTrue(result.checkouts.first?.gitPrimary == true)
        XCTAssertEqual(result.checkouts.first?.linkIssues, [])
        XCTAssertEqual(result.checkouts.last?.managedCheckoutID, "fixture-worktree")
        XCTAssertEqual(
            result.checkouts.last?.linkIssues,
            ["/tmp/fixture-worktree/.envrc"])
        XCTAssertTrue(result.checkouts.last?.needsAttention == true)

        let inventoryResponse = Data(
            #"{"request_id":30,"status":"ok","result":{"type":"project_checkout_inventory","value":{"revision":4,"projects":[{"project_id":"fixture-project","common_dir":"/tmp/fixture/.git","checkouts":[]}]}}}"#.utf8)
        let decodedInventory = try JSONDecoder().decode(
            ControlResponseEnvelope<ProjectCheckoutInventory>.self, from: inventoryResponse)
        let inventoryResult = try XCTUnwrap(decodedInventory.result?.value)
        XCTAssertEqual(inventoryResult.revision, 4)
        XCTAssertEqual(inventoryResult.projects.first?.projectID, "fixture-project")

        let remove = try ControlCommand.projectCheckoutRemove(id: "fixture-worktree")
            .requestData(requestID: 34, encoder: encoder)
        let removeValue = try XCTUnwrap(
            JSONSerialization.jsonObject(with: remove) as? [String: Any])
        XCTAssertEqual(removeValue["method"] as? String, "project_checkout_remove")
        XCTAssertEqual(
            (removeValue["params"] as? [String: Any])?["id"] as? String,
            "fixture-worktree")
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
            #"{"projects":[],"checkouts":[{"id":"fixture-worktree","project_id":"fixture-project","path":"/tmp/fixture-worktree","environment_id":"fixture-development","kind":"worktree","git_common_dir":"/tmp/fixture/.git"}],"environments":[{"id":"fixture-development","project_id":"fixture-project","name":"Development","position":0}],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-dotenv","environment_id":"fixture-development","name":".env","kind":"dotenv_file","path":"/tmp/fixture/.env","input":{"type":"bindings","binding_ids":[]},"enforcement":"allow","position":0}],"managed_links":[{"path":"/tmp/fixture/.env","status":"replaced"}]}"#.utf8)
        let decoder = JSONDecoder()

        let snapshot = try decoder.decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.environments.first?.projectID, "fixture-project")
        XCTAssertEqual(snapshot.checkouts.first?.projectID, "fixture-project")
        XCTAssertEqual(snapshot.checkouts.first?.environmentID, "fixture-development")
        XCTAssertEqual(snapshot.checkouts.first?.kind, .worktree)
        XCTAssertEqual(snapshot.surfaces.first?.environmentID, "fixture-development")
        XCTAssertEqual(snapshot.surfaces.first?.enforcement, "allow")
        XCTAssertEqual(snapshot.managedLinks.first?.path, "/tmp/fixture/.env")
        XCTAssertEqual(snapshot.managedLinks.first?.status, .replaced)
    }

    func testDecodesDirectEnvFileSurfaceFromRustSnapshot() throws {
        let data = Data(
            #"{"projects":[],"environments":[],"resources":[],"bindings":[],"surfaces":[{"id":"fixture-direct","environment_id":"fixture-development","name":".env.local","kind":"env_file_direct","path":"/tmp/fixture/.env.local","input":{"type":"resource","resource_id":"fixture-env-file"},"enforcement":"touchid","position":1}]}"#.utf8)
        let snapshot = try JSONDecoder().decode(CatalogSnapshot.self, from: data)

        XCTAssertEqual(snapshot.surfaces.first?.kind, "env_file_direct")
        XCTAssertEqual(snapshot.surfaces.first?.input.resourceID, "fixture-env-file")
        XCTAssertEqual(snapshot.surfaces.first?.enforcement, "touchid")
    }

    func testSshAgentSurfaceRouteMatchesRustWireShape() throws {
        let surface = CatalogSurface(
            id: "fixture-agent", environmentID: "fixture-development", name: "agent.sock",
            kind: "unix_socket", path: "/tmp/fixture/agent.sock",
            input: .sshAgent(
                ["fixture-binding"],
                route: CatalogSshRoute(
                    hostPatterns: ["ec2-*", "bastion"], hostname: nil, user: "ubuntu",
                    port: 2222, forwardAgent: true)),
            position: 2)
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try ControlCommand.surfaceUpsert(surface)
            .requestData(requestID: 81, encoder: encoder)
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let encodedSurface = try XCTUnwrap(
            (value["params"] as? [String: Any])?["surface"] as? [String: Any])
        let input = try XCTUnwrap(encodedSurface["input"] as? [String: Any])
        let route = try XCTUnwrap(input["route"] as? [String: Any])

        XCTAssertEqual(input["type"] as? String, "ssh_agent")
        XCTAssertEqual(input["binding_ids"] as? [String], ["fixture-binding"])
        XCTAssertEqual(route["host_patterns"] as? [String], ["ec2-*", "bastion"])
        XCTAssertEqual(route["user"] as? String, "ubuntu")
        XCTAssertEqual(route["port"] as? UInt16, 2222)
        XCTAssertEqual(route["forward_agent"] as? Bool, true)
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
