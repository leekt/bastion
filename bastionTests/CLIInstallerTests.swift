import Foundation
import ServiceManagement
import Testing
@testable import bastion

@Suite("CLI Installer")
struct CLIInstallerTests {

    @Test("App bundle resolves bundled CLI path")
    func appBundleCLIPath() throws {
        let appBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app")

        let cliURL = try #require(CLIInstaller.bundledCLIExecutableURL(for: appBundleURL))

        #expect(cliURL.path == "/Users/test/Applications/Bastion.app/Contents/MacOS/bastion-cli")
    }

    @Test("Helper bundle resolves parent app CLI path")
    func helperBundleCLIPath() throws {
        let helperBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app/Contents/Helpers/bastion-helper.app")

        let cliURL = try #require(CLIInstaller.bundledCLIExecutableURL(for: helperBundleURL))
        let hostAppURL = try #require(CLIInstaller.hostAppBundleURL(forHelperBundle: helperBundleURL))

        #expect(hostAppURL.path == "/Users/test/Applications/Bastion.app")
        #expect(cliURL.path == "/Users/test/Applications/Bastion.app/Contents/MacOS/bastion-cli")
    }

    @Test("Non-helper nested bundle does not resolve host app")
    func nestedNonHelperBundleDoesNotResolve() {
        let nestedBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app/Contents/Helpers/not-bastion-helper.app")

        #expect(CLIInstaller.hostAppBundleURL(forHelperBundle: nestedBundleURL) == nil)
    }

    @Test("CLI symlink installer atomically creates and recognizes installed link")
    func cliSymlinkInstallerCreatesAndRecognizesInstalledLink() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let appBundleURL = dir.appendingPathComponent("Bastion.app", isDirectory: true)
        let cliURL = appBundleURL.appendingPathComponent("Contents/MacOS/bastion-cli")
        try FileManager.default.createDirectory(
            at: cliURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("cli".utf8).write(to: cliURL)
        let symlinkPath = dir.appendingPathComponent("bin/bastion").path

        let outcome = CLIInstaller.installCLISymlink(
            symlinkPath: symlinkPath,
            bundleURL: appBundleURL
        )

        #expect(outcome == .installed)
        #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: symlinkPath)) == cliURL.path)
        #expect(CLIInstaller.installCLISymlink(symlinkPath: symlinkPath, bundleURL: appBundleURL) == .alreadyInstalled)
    }

    @Test("CLI symlink installer skips when bundled CLI is missing")
    func cliSymlinkInstallerSkipsMissingBundledCLI() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let appBundleURL = dir.appendingPathComponent("Bastion.app", isDirectory: true)
        let symlinkPath = dir.appendingPathComponent("bin/bastion").path

        #expect(CLIInstaller.installCLISymlink(symlinkPath: symlinkPath, bundleURL: appBundleURL) == .skippedMissingBundledCLI)
        #expect(FileManager.default.fileExists(atPath: symlinkPath) == false)
    }

    @Test("CLI symlink installer reports failed atomic replacement and removes temp link")
    func cliSymlinkInstallerReportsFailedAtomicReplacement() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let appBundleURL = dir.appendingPathComponent("Bastion.app", isDirectory: true)
        let cliURL = appBundleURL.appendingPathComponent("Contents/MacOS/bastion-cli")
        try FileManager.default.createDirectory(
            at: cliURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("cli".utf8).write(to: cliURL)
        let symlinkURL = dir.appendingPathComponent("bin/bastion", isDirectory: true)
        try FileManager.default.createDirectory(at: symlinkURL, withIntermediateDirectories: true)
        let tmpPath = symlinkURL.path + ".tmp.\(ProcessInfo.processInfo.processIdentifier)"

        let outcome = CLIInstaller.installCLISymlink(
            symlinkPath: symlinkURL.path,
            bundleURL: appBundleURL
        )

        guard case .failed(let reason) = outcome else {
            Issue.record("Expected failed symlink install, got \(outcome)")
            return
        }
        #expect(reason.contains("Could not atomically install CLI symlink"))
        #expect(FileManager.default.fileExists(atPath: tmpPath) == false)
    }

    @Test("Service lock rejects a second owner")
    func serviceLockRejectsSecondOwner() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let lockURL = dir.appendingPathComponent("Bastion/service.lock")

        let first = BastionServiceLock(lockURL: lockURL)
        let second = BastionServiceLock(lockURL: lockURL)

        #expect(first.acquire() == true)
        #expect(second.acquire() == false)

        first.release()
        #expect(second.acquire() == true)
    }

    @Test("Service lock creates parent directory")
    func serviceLockCreatesParentDirectory() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let lockURL = dir.appendingPathComponent("nested/Bastion/service.lock")
        let lock = BastionServiceLock(lockURL: lockURL)

        #expect(lock.acquire() == true)
        #expect(FileManager.default.fileExists(atPath: lockURL.path) == true)
    }

    @Test("Notification click route opens locally only in service process")
    func notificationClickRouteUsesServiceBoundary() {
        #expect(ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: true) == .openInCurrentProcess(.auditHistory))
        #expect(ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: false) == .requestServiceOpen(.auditHistory))
    }

    @Test("Relay launch route always requests the registered service")
    func relayLaunchRouteRequestsService() {
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .settings) == .requestServiceOpen(.settings))
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .auditHistory) == .requestServiceOpen(.auditHistory))
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .diagnostics) == .requestServiceOpen(.diagnostics))
    }

    @Test("Launch mode resolves service only for LaunchAgent service process")
    func launchModeUsesLaunchAgentServiceBoundary() {
        #expect(BastionLaunchController.resolveLaunchMode(isRunningAsLaunchAgentService: true) == .service)
        #expect(BastionLaunchController.resolveLaunchMode(isRunningAsLaunchAgentService: false) == .relay)
    }

    @MainActor
    @Test("App launch sequence starts service runtime after storage warmup")
    func appLaunchSequenceStartsServiceRuntimeAfterStorageWarmup() {
        let recorder = LaunchSequenceRecorder()
        let mode = BastionAppLauncher.launch(
            serviceRuntime: BastionServiceRuntime(xpcServer: .shared, ruleEngine: .shared, serviceLock: nil),
            relayRuntime: BastionRelayRuntime(),
            menuBarManager: MenuBarManager(),
            actions: launchActions(mode: .service, recorder: recorder)
        )

        #expect(mode == .service)
        #expect(recorder.events == [
            "migrate_keychain",
            "install_cli",
            "register_and_exit_if_requested",
            "resolve_launch_mode",
            "should_exit_for_user_shutdown",
            "warm_session_store",
            "start_service_runtime",
            "start_rpc_monitor",
            "start_release_update_monitor"
        ])
    }

    @MainActor
    @Test("App launch sequence starts relay runtime for non-service launches")
    func appLaunchSequenceStartsRelayRuntimeForNonServiceLaunches() {
        let recorder = LaunchSequenceRecorder()
        let mode = BastionAppLauncher.launch(
            serviceRuntime: BastionServiceRuntime(xpcServer: .shared, ruleEngine: .shared, serviceLock: nil),
            relayRuntime: BastionRelayRuntime(),
            menuBarManager: MenuBarManager(),
            actions: launchActions(mode: .relay, recorder: recorder)
        )

        #expect(mode == .relay)
        #expect(recorder.events == [
            "migrate_keychain",
            "install_cli",
            "register_and_exit_if_requested",
            "resolve_launch_mode",
            "should_exit_for_user_shutdown",
            "clear_user_shutdown_marker",
            "warm_session_store",
            "start_relay_runtime",
            "start_rpc_monitor",
            "start_release_update_monitor"
        ])
    }

    @MainActor
    @Test("Launchd relaunch after menu quit exits before service startup")
    func serviceRelaunchAfterUserQuitExitsBeforeServiceStartup() {
        let recorder = LaunchSequenceRecorder()
        let mode = BastionAppLauncher.launch(
            serviceRuntime: BastionServiceRuntime(xpcServer: .shared, ruleEngine: .shared, serviceLock: nil),
            relayRuntime: BastionRelayRuntime(),
            menuBarManager: MenuBarManager(),
            actions: BastionAppLauncher.Actions(
                migrateLegacyKeychainItems: { recorder.record("migrate_keychain") },
                installCLIIfNeeded: { recorder.record("install_cli") },
                registerAndExitIfRequested: { recorder.record("register_and_exit_if_requested") },
                resolveLaunchMode: {
                    recorder.record("resolve_launch_mode")
                    return .service
                },
                shouldExitForUserRequestedShutdown: { mode in
                    recorder.record("should_exit_for_user_shutdown:\(mode)")
                    return true
                },
                stopRelaunchedServiceForUserRequestedShutdown: {
                    recorder.record("stop_relaunched_service")
                },
                clearUserRequestedShutdownForInteractiveLaunch: { _ in
                    recorder.record("clear_user_shutdown_marker")
                },
                warmSessionStore: { recorder.record("warm_session_store") },
                startServiceRuntime: { _, _ in recorder.record("start_service_runtime") },
                startRelayRuntime: { _ in recorder.record("start_relay_runtime") },
                startRPCHealthMonitoring: { recorder.record("start_rpc_monitor") },
                startReleaseUpdateMonitor: { recorder.record("start_release_update_monitor") }
            )
        )

        #expect(mode == .service)
        #expect(recorder.events == [
            "migrate_keychain",
            "install_cli",
            "register_and_exit_if_requested",
            "resolve_launch_mode",
            "should_exit_for_user_shutdown:service",
            "stop_relaunched_service"
        ])
    }

    @Test("Relay handoff does not terminate when grace sleep is cancelled")
    func relayHandoffSkipsTerminationWhenGraceSleepIsCancelled() async {
        let recorder = RelayTerminationRecorder()

        let shouldTerminate = await BastionRelayRuntime.shouldTerminateAfterSuccessfulHandoff(
            sleep: { delay in
                try await recorder.sleepAndCancel(delay)
            }
        )

        #expect(shouldTerminate == false)
        #expect(await recorder.delays == [BastionRelayRuntime.successfulHandoffTerminationDelay])
    }

    @MainActor
    @Test("Service runtime configures dependencies before accepting XPC")
    func serviceRuntimeConfiguresDependenciesBeforeAcceptingXPC() {
        let recorder = LaunchSequenceRecorder()
        let lockURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("Bastion/service.lock")
        defer {
            try? FileManager.default.removeItem(at: lockURL.deletingLastPathComponent().deletingLastPathComponent())
        }

        let runtime = BastionServiceRuntime(
            xpcServer: .shared,
            ruleEngine: .shared,
            serviceLock: BastionServiceLock(lockURL: lockURL),
            actions: BastionServiceRuntime.Actions(
                loadConfigOnStartup: { _ in recorder.record("load_config") },
                warmSessionStore: { recorder.record("warm_session_store") },
                configureNotifications: { recorder.record("configure_notifications") },
                startMenuBarObserving: { _ in recorder.record("start_menu_bar_observing") },
                startXPCServer: { _ in recorder.record("start_xpc_server") },
                warmSecureEnclaveKey: { recorder.record("warm_secure_enclave_key") }
            )
        )

        runtime.start(menuBarManager: MenuBarManager())

        #expect(recorder.events == [
            "load_config",
            "warm_session_store",
            "configure_notifications",
            "start_menu_bar_observing",
            "start_xpc_server",
            "warm_secure_enclave_key"
        ])
    }

    @Test("Service registration is attempted only by stable relay app launches")
    func serviceRegistrationDecisionUsesRuntimeBoundary() {
        #expect(ServiceRegistration.shouldAttemptAutoRegistration(
            isRunningAsLaunchAgentService: false,
            isStableInstalledBundleLocation: true
        ) == true)
        #expect(ServiceRegistration.shouldAttemptAutoRegistration(
            isRunningAsLaunchAgentService: true,
            isStableInstalledBundleLocation: true
        ) == false)
        #expect(ServiceRegistration.shouldAttemptAutoRegistration(
            isRunningAsLaunchAgentService: false,
            isStableInstalledBundleLocation: false
        ) == false)
    }

    @Test("Service registration status strings are stable")
    func serviceRegistrationStatusStringsAreStable() {
        #expect(ServiceRegistration.statusDescription(for: .notRegistered) == "not_registered")
        #expect(ServiceRegistration.statusDescription(for: .enabled) == "enabled")
        #expect(ServiceRegistration.statusDescription(for: .requiresApproval) == "requires_approval")
        #expect(ServiceRegistration.statusDescription(for: .notFound) == "not_found")
    }

    @Test("Forced service registration refreshes enabled jobs and surfaces unregister failures")
    func forcedServiceRegistrationRefreshesEnabledJobs() throws {
        final class DriverRecorder {
            var statuses: [SMAppService.Status]
            var events: [String] = []
            var unregisterError: Error?

            init(statuses: [SMAppService.Status], unregisterError: Error? = nil) {
                self.statuses = statuses
                self.unregisterError = unregisterError
            }

            func driver() -> ServiceRegistration.RegistrationDriver {
                ServiceRegistration.RegistrationDriver(
                    currentStatus: {
                        self.events.append("status")
                        if self.statuses.count > 1 {
                            return self.statuses.removeFirst()
                        }
                        return self.statuses.first ?? .notRegistered
                    },
                    register: {
                        self.events.append("register")
                    },
                    unregister: {
                        self.events.append("unregister")
                        if let unregisterError = self.unregisterError {
                            throw unregisterError
                        }
                    }
                )
            }
        }
        struct RefreshFailure: LocalizedError {
            var errorDescription: String? { "could not remove old launch agent" }
        }

        #expect(ServiceRegistration.shouldRefreshRegistrationBeforeRegister(status: .enabled) == true)
        #expect(ServiceRegistration.shouldRefreshRegistrationBeforeRegister(status: .notRegistered) == false)
        #expect(ServiceRegistration.shouldRefreshRegistrationBeforeRegister(status: .requiresApproval) == false)
        #expect(ServiceRegistration.shouldRefreshRegistrationBeforeRegister(status: .notFound) == false)

        let successRecorder = DriverRecorder(statuses: [.enabled, .notRegistered, .enabled])
        #expect(try ServiceRegistration.register(forceRefresh: true, driver: successRecorder.driver()) == .enabled)
        #expect(successRecorder.events == ["status", "unregister", "status", "register", "status"])

        let failureRecorder = DriverRecorder(statuses: [.enabled], unregisterError: RefreshFailure())
        do {
            _ = try ServiceRegistration.register(forceRefresh: true, driver: failureRecorder.driver())
            Issue.record("Expected forced registration refresh failure to throw")
        } catch {
            #expect(error.localizedDescription == "could not remove old launch agent")
        }
        #expect(failureRecorder.events == ["status", "unregister"])
    }

    @Test("Service auto-registration diagnostics are actionable")
    func serviceAutoRegistrationDiagnosticsAreActionable() {
        struct RegistrationFailure: LocalizedError {
            var errorDescription: String? { "missing launch agent approval" }
        }

        #expect(ServiceRegistration.autoRegistrationSuccessMessage(status: .enabled) == "Bastion background service auto-registration completed with status enabled.")
        #expect(ServiceRegistration.autoRegistrationFailureMessage(RegistrationFailure()) == "Bastion background service auto-registration failed: missing launch agent approval")

        let success = ServiceRegistration.autoRegistrationDiagnosticContext(
            status: .enabled,
            isRunningAsLaunchAgentService: false,
            isStableInstalledBundleLocation: true
        )
        #expect(success["launchAgentLabel"] == "com.bastion.xpc")
        #expect(success["launchAgentDomain"] == ServiceRegistration.launchAgentDomain)
        #expect(success["launchAgentPlistName"] == "com.bastion.xpc.plist")
        #expect(success["isRunningAsLaunchAgentService"] == "false")
        #expect(success["isStableInstalledBundleLocation"] == "true")
        #expect(success["serviceRegistrationStatus"] == "enabled")
        #expect(success["error"] == nil)

        let failure = ServiceRegistration.autoRegistrationDiagnosticContext(
            error: RegistrationFailure(),
            isRunningAsLaunchAgentService: false,
            isStableInstalledBundleLocation: true
        )
        #expect(failure["launchAgentLabel"] == "com.bastion.xpc")
        #expect(failure["launchAgentDomain"] == ServiceRegistration.launchAgentDomain)
        #expect(failure["launchAgentPlistName"] == "com.bastion.xpc.plist")
        #expect(failure["isRunningAsLaunchAgentService"] == "false")
        #expect(failure["isStableInstalledBundleLocation"] == "true")
        #expect(failure["error"] == "missing launch agent approval")
        #expect(failure["serviceRegistrationStatus"] == nil)
    }

    @MainActor
    @Test("Menu quit unregisters and unloads enabled background service jobs")
    func menuQuitUnregistersAndUnloadsEnabledBackgroundServiceJobs() throws {
        #expect(ServiceRegistration.shouldUnregisterBeforeUserQuit(status: .enabled) == true)
        #expect(ServiceRegistration.shouldUnregisterBeforeUserQuit(status: .notRegistered) == false)
        #expect(ServiceRegistration.shouldUnregisterBeforeUserQuit(status: .requiresApproval) == false)
        #expect(ServiceRegistration.shouldUnregisterBeforeUserQuit(status: .notFound) == false)
        #expect(ServiceRegistration.shouldCheckLaunchctlBeforeUserQuit(
            statusBeforeQuit: .enabled,
            isRunningAsLaunchAgentService: false
        ) == true)
        #expect(ServiceRegistration.shouldCheckLaunchctlBeforeUserQuit(
            statusBeforeQuit: .notRegistered,
            isRunningAsLaunchAgentService: true
        ) == true)
        #expect(ServiceRegistration.shouldCheckLaunchctlBeforeUserQuit(
            statusBeforeQuit: .notRegistered,
            isRunningAsLaunchAgentService: false
        ) == false)
        #expect(ServiceRegistration.shouldExitServiceLaunchForUserShutdown(
            isRunningAsLaunchAgentService: true,
            userRequestedShutdown: true
        ) == true)
        #expect(ServiceRegistration.shouldExitServiceLaunchForUserShutdown(
            isRunningAsLaunchAgentService: false,
            userRequestedShutdown: true
        ) == false)
        #expect(ServiceRegistration.shouldExitServiceLaunchForUserShutdown(
            isRunningAsLaunchAgentService: true,
            userRequestedShutdown: false
        ) == false)
        #expect(BastionUserQuitController.shouldAllowImmediateTermination(
            isRunningAsLaunchAgentService: true,
            userRequestedShutdown: false
        ) == false)
        #expect(BastionUserQuitController.shouldAllowImmediateTermination(
            isRunningAsLaunchAgentService: true,
            userRequestedShutdown: true
        ) == true)
        #expect(BastionUserQuitController.shouldAllowImmediateTermination(
            isRunningAsLaunchAgentService: false,
            userRequestedShutdown: false
        ) == true)

        let suiteName = "ServiceRegistrationShutdown-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        #expect(ServiceRegistration.hasUserRequestedShutdown(defaults: defaults) == false)
        ServiceRegistration.recordUserRequestedShutdown(defaults: defaults)
        #expect(ServiceRegistration.hasUserRequestedShutdown(defaults: defaults) == true)
        ServiceRegistration.clearUserRequestedShutdown(defaults: defaults)
        #expect(ServiceRegistration.hasUserRequestedShutdown(defaults: defaults) == false)

        var enabledCommands: [String] = []
        var enabledStatuses: [SMAppService.Status] = [.enabled, .notRegistered, .notRegistered]
        let enabledStatus = try ServiceRegistration.unregisterForUserQuit(
            isRunningAsLaunchAgentService: false,
            driver: ServiceRegistration.UserQuitDriver(
                currentStatus: { enabledStatuses.removeFirst() },
                unregister: { enabledCommands.append("unregister") },
                isLaunchAgentLoaded: { domain in
                    enabledCommands.append("print \(domain)")
                    return true
                },
                bootoutLaunchAgent: { domain in
                    enabledCommands.append("bootout \(domain)")
                }
            )
        )
        #expect(enabledStatus == .notRegistered)
        #expect(enabledCommands == [
            "unregister",
            "print \(ServiceRegistration.launchAgentDomain)",
            "bootout \(ServiceRegistration.launchAgentDomain)",
        ])

        var serviceCommands: [String] = []
        var serviceStatuses: [SMAppService.Status] = [.notRegistered, .notRegistered]
        _ = try ServiceRegistration.unregisterForUserQuit(
            isRunningAsLaunchAgentService: true,
            driver: ServiceRegistration.UserQuitDriver(
                currentStatus: { serviceStatuses.removeFirst() },
                unregister: { serviceCommands.append("unregister") },
                isLaunchAgentLoaded: { domain in
                    serviceCommands.append("print \(domain)")
                    return true
                },
                bootoutLaunchAgent: { domain in
                    serviceCommands.append("bootout \(domain)")
                }
            )
        )
        #expect(serviceCommands == [
            "print \(ServiceRegistration.launchAgentDomain)",
            "bootout \(ServiceRegistration.launchAgentDomain)",
        ])

        var relayCommands: [String] = []
        var relayStatuses: [SMAppService.Status] = [.notRegistered, .notRegistered]
        _ = try ServiceRegistration.unregisterForUserQuit(
            isRunningAsLaunchAgentService: false,
            driver: ServiceRegistration.UserQuitDriver(
                currentStatus: { relayStatuses.removeFirst() },
                unregister: { relayCommands.append("unregister") },
                isLaunchAgentLoaded: { domain in
                    relayCommands.append("print \(domain)")
                    return true
                },
                bootoutLaunchAgent: { domain in
                    relayCommands.append("bootout \(domain)")
                }
            )
        )
        #expect(relayCommands.isEmpty)

        struct QuitFailure: LocalizedError {
            var errorDescription: String? { "owner approval required" }
        }

        let message = ServiceRegistration.userQuitFailureMessage(QuitFailure())
        #expect(message.contains("Quit failed: owner approval required."))
        #expect(message.contains("launchctl bootout \(ServiceRegistration.launchAgentDomain)"))
        #expect(message.contains("System Settings > General > Login Items & Extensions"))

        var terminationEvents: [String] = []
        let interceptedReply = BastionUserQuitController.applicationShouldTerminate(
            actions: BastionUserQuitController.Actions(
                isRunningAsLaunchAgentService: { true },
                hasUserRequestedShutdown: { false },
                recordUserRequestedShutdown: { terminationEvents.append("record_shutdown_marker") },
                clearUserRequestedShutdown: { terminationEvents.append("clear_shutdown_marker") },
                statusDescription: {
                    terminationEvents.append("status_before")
                    return "enabled"
                },
                unregisterForUserQuit: {
                    terminationEvents.append("unregister_and_bootout")
                    return "not_registered"
                },
                recordQuitRequested: { before, after in
                    terminationEvents.append("diagnostic \(before)->\(after)")
                },
                recordQuitFailed: { message in
                    terminationEvents.append("failure \(message)")
                },
                terminateApplication: {
                    terminationEvents.append("terminate")
                }
            )
        )
        #expect(interceptedReply == .terminateCancel)
        #expect(terminationEvents == [
            "record_shutdown_marker",
            "status_before",
            "unregister_and_bootout",
            "diagnostic enabled->not_registered",
            "terminate",
        ])

        var allowedEvents: [String] = []
        let allowedReply = BastionUserQuitController.applicationShouldTerminate(
            actions: BastionUserQuitController.Actions(
                isRunningAsLaunchAgentService: { true },
                hasUserRequestedShutdown: { true },
                recordUserRequestedShutdown: { allowedEvents.append("record_shutdown_marker") },
                clearUserRequestedShutdown: { allowedEvents.append("clear_shutdown_marker") },
                statusDescription: {
                    allowedEvents.append("status_before")
                    return "enabled"
                },
                unregisterForUserQuit: {
                    allowedEvents.append("unregister_and_bootout")
                    return "not_registered"
                },
                recordQuitRequested: { before, after in
                    allowedEvents.append("diagnostic \(before)->\(after)")
                },
                recordQuitFailed: { message in
                    allowedEvents.append("failure \(message)")
                },
                terminateApplication: {
                    allowedEvents.append("terminate")
                }
            )
        )
        #expect(allowedReply == .terminateNow)
        #expect(allowedEvents.isEmpty)
    }

    @Test("Menu bar icon flash reset stops when delay is cancelled")
    func menuBarIconFlashResetStopsWhenDelayIsCancelled() async {
        let recorder = MenuBarDelayRecorder()

        let shouldReset = await MenuBarIconTiming.shouldResetFlashAfterDelay(
            sleep: { duration in
                await recorder.record(duration)
                throw CancellationError()
            }
        )

        #expect(shouldReset == false)
        #expect(await recorder.snapshot() == [MenuBarIconTiming.flashDuration])
    }

    @Test("Menu bar observation loop stops when delay is cancelled")
    func menuBarObservationLoopStopsWhenDelayIsCancelled() async {
        let recorder = MenuBarDelayRecorder()

        let shouldContinue = await MenuBarIconTiming.shouldContinueObservationAfterDelay(
            sleep: { duration in
                await recorder.record(duration)
                throw CancellationError()
            }
        )

        #expect(shouldContinue == false)
        #expect(await recorder.snapshot() == [MenuBarIconTiming.observationInterval])
    }

    @MainActor
    private func launchActions(
        mode: BastionLaunchMode,
        recorder: LaunchSequenceRecorder
    ) -> BastionAppLauncher.Actions {
        BastionAppLauncher.Actions(
            migrateLegacyKeychainItems: { recorder.record("migrate_keychain") },
            installCLIIfNeeded: { recorder.record("install_cli") },
            registerAndExitIfRequested: { recorder.record("register_and_exit_if_requested") },
            resolveLaunchMode: {
                recorder.record("resolve_launch_mode")
                return mode
            },
            shouldExitForUserRequestedShutdown: { _ in
                recorder.record("should_exit_for_user_shutdown")
                return false
            },
            stopRelaunchedServiceForUserRequestedShutdown: {
                recorder.record("stop_relaunched_service")
            },
            clearUserRequestedShutdownForInteractiveLaunch: { mode in
                if mode == .relay {
                    recorder.record("clear_user_shutdown_marker")
                }
            },
            warmSessionStore: { recorder.record("warm_session_store") },
            startServiceRuntime: { _, _ in recorder.record("start_service_runtime") },
            startRelayRuntime: { _ in recorder.record("start_relay_runtime") },
            startRPCHealthMonitoring: { recorder.record("start_rpc_monitor") },
            startReleaseUpdateMonitor: { recorder.record("start_release_update_monitor") }
        )
    }
}

@MainActor
private final class LaunchSequenceRecorder {
    private(set) var events: [String] = []

    func record(_ event: String) {
        events.append(event)
    }
}

private actor RelayTerminationRecorder {
    private(set) var delays: [Duration] = []

    func sleepAndCancel(_ delay: Duration) throws {
        delays.append(delay)
        throw CancellationError()
    }
}

private actor MenuBarDelayRecorder {
    private var durations: [Duration] = []

    func record(_ duration: Duration) {
        durations.append(duration)
    }

    func snapshot() -> [Duration] {
        durations
    }
}
