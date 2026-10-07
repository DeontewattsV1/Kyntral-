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
            let state = await KyntralRuntime.shared.workflowState(
                id: "wf_media_intake",
                scopeId: scopeIdText.isEmpty ? nil : scopeIdText
            )
            if let workflow = state.workflow {
                scopeIdText = workflow.scopeId ?? ""
                endpointText = workflow.resolverEndpoint?.absoluteString ?? ""
                destinationBookmark = workflow.destinationBookmark
                standingGrantAllowed = state.decision == .allowed
                destinationName = workflow.destinationBookmark == nil
                    ? "Not selected"
                    : "Previously selected folder"
                statusMessage = "Saved locally. Authorization: \(state.decision.rawValue)."
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
                id: "wf_media_intake"
            )
            statusMessage = "Saved locally. Authorization: \(state.decision.rawValue)."
        } catch {
            statusMessage = String(describing: error)
        }
    }
}
