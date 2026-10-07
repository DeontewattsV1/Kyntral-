// SPDX-License-Identifier: BUSL-1.1

import SwiftUI

struct ContentView: View {
    @State private var deviceID = "Loading local identity…"

    var body: some View {
        NavigationStack {
            List {
                Section("Device authority") {
                    Label("Private keys remain on this device", systemImage: "lock.shield")
                    Text(deviceID).font(.footnote.monospaced()).textSelection(.enabled)
                }
                Section("Release invariant") {
                    Text("AI proposal ≠ authorization ≠ execution ≠ verification")
                    Text("Kyntral Cloud should not need user content to authorize device work.")
                }
            }
            .navigationTitle("Kyntral")
            .task {
                do {
                    deviceID = try await DeviceKeyManager.shared.identity().deviceId
                } catch {
                    deviceID = "Local device identity unavailable"
                }
            }
        }
    }
}
