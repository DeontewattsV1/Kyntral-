// SPDX-License-Identifier: BUSL-1.1

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var deviceID = "Loading local identity…"
    @State private var scopeIdText = ""
    @State private var endpointText = ""
    @State private var destinationBookmark: Data?
    @State private var destinationName = "Not selected"
    @State private var standingGrantAllowed = false
    @State private var showingFolderPicker = false
    @State private var statusMessage = "KYN-W01 is not configured."
    @State private var apiBaseURLText = ""
    @State private var apiAccessToken = ""
    @State private var apiStatusMessage = "This device is not linked through the User API."
    @State private var apiBusy = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Device authority") {
                    Label(
                        "Private keys remain on this device",
                        systemImage: "lock.shield"
                    )
                    Text(deviceID)
                        .font(.footnote.monospaced())
                        .textSelection(.enabled)
                }

                Section("Personal-device Shortcut") {
                    Link(
                        "Install Kyntral Shortcut",
                        destination: URL(
                            string: "https://www.icloud.com/shortcuts/effa6cac2e9b4702bed9128a8749e1f8"
                        )!
                    )

                    Text(
                        "Install the Shortcut on this device, then pair the device and configure KYN-W01 in Kyntral. Installing the Shortcut alone does not grant device authority."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }

                Section("Personal Device API") {
                    TextField(
                        "Kyntral API base URL",
                        text: $apiBaseURLText
                    )
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()

                    SecureField(
                        "OAuth access token",
                        text: $apiAccessToken
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    Text(
                        "The OAuth token stays in this app session and is never stored in the shared Shortcut. Pairing separately proves possession of this device's signing key."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                    HStack {
                        Button("Pair this device") {
                            Task { await pairDevice() }
                        }

                        Button("Check") {
                            Task { await checkDevice() }
                        }

                        Button("Run next") {
                            Task { await runNextAction() }
                        }
                    }
                    .disabled(apiBusy || apiBaseURLText.isEmpty || apiAccessToken.isEmpty)

                    Button("Revoke this device", role: .destructive) {
                        Task { await revokeDevice() }
                    }
                    .disabled(apiBusy || apiBaseURLText.isEmpty || apiAccessToken.isEmpty)

                    Text(apiStatusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("KYN-W01 Media Intake") {
                    TextField(
                        "Kyntral Scope ID",
                        text: $scopeIdText
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    TextField(
                        "Authorized Cobalt-compatible HTTPS endpoint",
                        text: $endpointText
                    )
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()

                    Button("Choose iCloud / Files destination") {
                        showingFolderPicker = true
                    }

                    LabeledContent("Destination", value: destinationName)

                    Toggle(
                        "Standing grant for this exact workflow",
                        isOn: $standingGrantAllowed
                    )

                    Text(
                        "This grant applies only to wf_media_intake and workflow.execute. It does not authorize arbitrary Shortcuts, URLs, or device actions."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                    Button("Save local workflow") {
                        Task { await saveWorkflow() }
                    }
                    .disabled(
                        destinationBookmark == nil ||
                        endpointText.isEmpty ||
                        scopeIdText.isEmpty
                    )

                    Text(statusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Release invariant") {
                    Text("AI proposal ≠ authorization ≠ execution ≠ verification")
                    Text(
                        "Kyntral Cloud should not need user content to authorize device work."
                    )
                }
            }
            .navigationTitle("Kyntral")
            .fileImporter(
                isPresented: $showingFolderPicker,
                allowedContentTypes: [.folder],
                allowsMultipleSelection: false
            ) { result in
                handleFolderSelection(result)
            }
            .task {
                await loadLocalState()
            }
        }
    }

    private func loadLocalState() async {
        do {
            deviceID = try await DeviceKeyManager.shared.identity().deviceId
            let initial = await KyntralRuntime.shared.workflowState(
                id: "wf_media_intake"
            )
            if let workflow = initial.workflow {
                scopeIdText = workflow.scopeId ?? ""
                endpointText = workflow.resolverEndpoint?.absoluteString ?? ""
                destinationBookmark = workflow.destinationBookmark
                let scoped = await KyntralRuntime.shared.workflowState(
                    id: "wf_media_intake",
                    scopeId: workflow.scopeId
                )
                standingGrantAllowed = scoped.decision == .allowed
                destinationName = workflow.destinationBookmark == nil
                    ? "Not selected"
                    : "Previously selected folder"
                statusMessage =
                    "Saved locally. Authorization: \(scoped.decision.rawValue)."
            }
        } catch {
            deviceID = "Local device identity unavailable"
            statusMessage = String(describing: error)
        }
    }

    private func handleFolderSelection(
        _ result: Result<[URL], Error>
    ) {
        do {
            guard let url = try result.get().first else { return }
            let started = url.startAccessingSecurityScopedResource()
            defer {
                if started { url.stopAccessingSecurityScopedResource() }
            }
            destinationBookmark = try url.bookmarkData(
                options: [],
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
            destinationName = url.lastPathComponent
            statusMessage = "Destination selected locally."
        } catch {
            statusMessage = String(describing: error)
        }
    }

    private func apiBaseURL() throws -> URL {
        guard let url = URL(string: apiBaseURLText),
              url.scheme?.lowercased() == "https",
              url.host != nil,
              url.user == nil,
              url.password == nil else {
            throw PairingClientError.invalidServiceURL
        }
        return url
    }

    private func pairDevice() async {
        apiBusy = true
        defer { apiBusy = false }

        do {
            let client = try KyntralPairingClient(
                serviceBaseURL: apiBaseURL()
            )
            let completion = try await client.pair(
                accessToken: apiAccessToken
            )
            apiStatusMessage =
                "Paired \(completion.deviceId). Server action key pinned locally."
        } catch {
            apiStatusMessage = "Pairing failed: \(String(describing: error))"
        }
    }

    private func checkDevice() async {
        apiBusy = true
        defer { apiBusy = false }

        do {
            let identity = try await DeviceKeyManager.shared.identity()
            let client = try KyntralPairingClient(
                serviceBaseURL: apiBaseURL()
            )
            let status = try await client.status(
                deviceId: identity.deviceId,
                accessToken: apiAccessToken
            )
            apiStatusMessage =
                "Device \(status.deviceId): \(status.state)."
        } catch {
            apiStatusMessage = "Status check failed: \(String(describing: error))"
        }
    }

    private func runNextAction() async {
        apiBusy = true
        defer { apiBusy = false }

        do {
            let client = try DeviceExecutionClient(
                serviceBaseURL: apiBaseURL()
            )
            let result = try await client.processNext(
                accessToken: apiAccessToken
            )
            switch result {
            case .idle:
                apiStatusMessage = "No authorized action is waiting."
            case .receiptUploaded(let actionId):
                apiStatusMessage =
                    "Recovered and uploaded the verified receipt for \(actionId)."
            case .executed(let actionId, let outcome):
                apiStatusMessage =
                    "Executed \(actionId) locally. Outcome: \(outcome)."
            }
        } catch {
            apiStatusMessage = "Execution cycle failed: \(String(describing: error))"
        }
    }

    private func revokeDevice() async {
        apiBusy = true
        defer { apiBusy = false }

        do {
            let identity = try await DeviceKeyManager.shared.identity()
            let client = try KyntralPairingClient(
                serviceBaseURL: apiBaseURL()
            )
            let result = try await client.revoke(
                deviceId: identity.deviceId,
                accessToken: apiAccessToken
            )
            apiStatusMessage =
                "Device \(result.deviceId): \(result.state)."
        } catch {
            apiStatusMessage = "Revocation failed: \(String(describing: error))"
        }
    }

    private func saveWorkflow() async {
        guard let endpoint = URL(string: endpointText),
              let destinationBookmark else {
            statusMessage = "Enter a valid HTTPS endpoint and choose a destination."
            return
        }

        do {
            try await KyntralRuntime.shared.configureMediaIntake(
                scopeId: scopeIdText,
                endpoint: endpoint,
                destinationBookmark: destinationBookmark,
                standingGrantAllowed: standingGrantAllowed
            )
            let state = await KyntralRuntime.shared.workflowState(
                id: "wf_media_intake",
                scopeId: scopeIdText
            )
            statusMessage = "Saved locally. Authorization: \(state.decision.rawValue)."
        } catch {
            statusMessage = String(describing: error)
        }
    }
}
