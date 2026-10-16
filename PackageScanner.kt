package com.example.appriskauditor

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.graphics.drawable.Drawable
import android.os.Build
import android.provider.Settings
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * Shared Data Models for PS-01: On-Device App Risk Auditor
 * Member 1 (Scanner Lead) shares these models with Member 2 (Scoring), Member 3 (UI), & Member 4 (Monitor).
 */
enum class RiskBand(val label: String) {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical")
}

enum class PermCategory(val displayName: String, val baseWeight: Int) {
    SPECIAL_ACCESS("Special access", 35),
    SMS("SMS", 20),
    CONTACTS_CALL_LOGS("Contacts and call logs", 15),
    CAMERA_MIC("Camera and microphone", 12),
    LOCATION("Location", 10),
    PHONE_IDENTITY("Phone and identity", 8),
    STORAGE_MEDIA("Storage and media", 8),
    BACKGROUND_PERSISTENCE("Background and persistence", 8),
    NETWORK("Network", 5)
}

data class PermissionItem(
    val name: String,
    val shortName: String,
    val isGranted: Boolean,
    val protectionLevel: String, // "normal", "dangerous", "signature", "special"
    val category: PermCategory?
)

/**
 * Stretch Goal 11 & 12: SHA-256 Hash Lookup & Static Manifest Checks
 */
data class StaticManifestAudit(
    val apkPath: String?,
    val apkSha256: String,
    val isKnownThreatHash: Boolean,
    val threatIntelLabel: String?,
    val isDebuggable: Boolean,
    val usesCleartextTraffic: Boolean,
    val exportedActivitiesCount: Int,
    val exportedServicesCount: Int,
    val exportedReceiversCount: Int,
    val exportedProvidersCount: Int
) {
    val totalExportedComponents: Int
        get() = exportedActivitiesCount + exportedServicesCount + exportedReceiversCount + exportedProvidersCount
}

/**
 * Complete Scanned Record for an Installed App (Must-Haves 01–04 + Should-Have 08 + Stretch 11–12)
 */
data class AppAuditRecord(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val appIcon: Drawable?,
    val appCategoryLabel: String, // Used by Member 2 for Should-Have 08 (Context Mismatch)
    val isSystemApp: Boolean,
    val installDateMs: Long,
    val lastUpdateMs: Long,
    val installerSource: String?, // e.g., "com.android.vending" (Play Store) or null (Sideloaded)
    val installerDisplayName: String,
    val isSideloaded: Boolean,
    val targetSdk: Int,
    val permissions: List<PermissionItem>,
    val specialAccessGranted: List<String>, // Active/Declared Accessibility, Device Admin, Notification Listener, Overlay, Install Packages, Usage Stats
    val staticAudit: StaticManifestAudit,
    // Populated by Member 2's RiskScoringEngine (defaults provided so Member 1 & 3 can test immediately)
    val riskScore: Int = 0,
    val mlRiskScore: Int = 0,
    val riskBand: RiskBand = RiskBand.LOW,
    val plainLanguageReasons: List<String> = emptyList()
)

/**
 * Member 1 Module: On-Device Package, Permission, Special Access & Static Manifest Scanner
 * Works 100% offline with zero root and zero ADB required.
 */
object PackageScanner {

    private val TRUSTED_INSTALLERS = mapOf(
        "com.android.vending" to "Google Play Store",
        "com.google.android.feedback" to "Google Play Store",
        "com.sec.android.app.samsungapps" to "Samsung Galaxy Store",
        "com.amazon.venezia" to "Amazon Appstore"
    )

    // Local offline test threat-intel hashes for Stretch Goal 11 demo + optional hash lookup support
    private val KNOWN_SUSPICIOUS_SHA256 = mapOf(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" to "Suspicious Test Sample (Empty Hash)"
    )

    /**
     * Master entry point: Scans all installed packages on the device.
     * @param context Android application or activity context
     * @param includeSystemApps Toggle for Must-Have 01 (User-installed vs System apps)
     * @param computeSha256 Toggle for Stretch Goal 11 (SHA-256 base APK hashing)
     */
    @Suppress("DEPRECATION")
    fun scanInstalledApps(
        context: Context,
        includeSystemApps: Boolean = false,
        computeSha256: Boolean = false
    ): List<AppAuditRecord> {
        val pm = context.packageManager

        // Pre-fetch device-wide active Special Access services once for speed (Must-Have 04)
        val enabledAccessibilityServices = getEnabledAccessibilityPackages(context)
        val enabledNotificationListeners = getEnabledNotificationListenerPackages(context)
        val activeDeviceAdmins = getActiveDeviceAdminPackages(context)

        val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS

        val installedPackages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getInstalledPackages(flags)
        }

        val results = mutableListOf<AppAuditRecord>()

        for (pkgInfo in installedPackages) {
            val pkgName = pkgInfo.packageName
            if (pkgName == context.packageName) continue

            val record = buildAuditRecordForPackage(
                context = context,
                pm = pm,
                pkgInfo = pkgInfo,
                includeSystemApps = includeSystemApps,
                computeSha256 = computeSha256,
                enabledAccessibilityServices = enabledAccessibilityServices,
                enabledNotificationListeners = enabledNotificationListeners,
                activeDeviceAdmins = activeDeviceAdmins
            )
            if (record != null) {
                results.add(record)
            }
        }

        return results
    }

    /**
     * Helper for Member 4 (Should-Have 09 & 10: Install Monitoring & Permission Diff):
     * Scans a single newly installed or updated package immediately when BroadcastReceiver fires.
     */
    @Suppress("DEPRECATION")
    fun scanSinglePackage(
        context: Context,
        packageName: String,
        computeSha256: Boolean = true
    ): AppAuditRecord? {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS

        val pkgInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                pm.getPackageInfo(packageName, flags)
            }
        } catch (e: Exception) {
            return null
        }

        return buildAuditRecordForPackage(
            context = context,
            pm = pm,
            pkgInfo = pkgInfo,
            includeSystemApps = true,
            computeSha256 = computeSha256,
            enabledAccessibilityServices = getEnabledAccessibilityPackages(context),
            enabledNotificationListeners = getEnabledNotificationListenerPackages(context),
            activeDeviceAdmins = getActiveDeviceAdminPackages(context)
        )
    }

    /**
     * Helper for Member 3 (Must-Have 03: Device-wide summary across the 9 categories):
     * Returns a map of each PermCategory to the number of scanned apps holding granted access in that category.
     */
    fun getDeviceWideCategorySummary(records: List<AppAuditRecord>): Map<PermCategory, Int> {
        val summary = PermCategory.values().associateWith { 0 }.toMutableMap()
        for (app in records) {
            val grantedCategories = app.permissions
                .filter { it.isGranted && it.category != null }
                .mapNotNull { it.category }
                .toMutableSet()

            if (app.specialAccessGranted.any { it.contains("ENABLED") || it.contains("ACTIVE") || it.contains("GRANTED") }) {
                grantedCategories.add(PermCategory.SPECIAL_ACCESS)
            }

            for (cat in grantedCategories) {
                summary[cat] = (summary[cat] ?: 0) + 1
            }
        }
        return summary
    }

    private fun buildAuditRecordForPackage(
        context: Context,
        pm: PackageManager,
        pkgInfo: PackageInfo,
        includeSystemApps: Boolean,
        computeSha256: Boolean,
        enabledAccessibilityServices: Set<String>,
        enabledNotificationListeners: Set<String>,
        activeDeviceAdmins: Set<String>
    ): AppAuditRecord? {
        val appInfo = pkgInfo.applicationInfo ?: return null
        val pkgName = pkgInfo.packageName

        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

        if (!includeSystemApps && isSystem) return null

        val appName = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            pkgName
        }

        val appIcon = try {
            pm.getApplicationIcon(appInfo)
        } catch (e: Exception) {
            null
        }

        val appCategoryLabel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ApplicationInfo.getCategoryTitle(context, appInfo.category)?.toString() ?: "Uncategorized / Utility"
        } else {
            "Uncategorized / Utility"
        }

        val versionName = pkgInfo.versionName ?: "1.0"
        val installer = getInstallerPackageNameCompat(pm, pkgName)
        val isSideloaded = !isSystem && (installer == null || installer !in TRUSTED_INSTALLERS)
        val installerDisplayName = when {
            isSystem -> "System Pre-installed"
            installer != null && installer in TRUSTED_INSTALLERS -> TRUSTED_INSTALLERS[installer]!!
            installer != null -> "Sideloaded ($installer)"
            else -> "Sideloaded / Unknown APK"
        }

        // 1. Detect Active & Declared Special Access (Must-Have 04)
        val specialAccess = detectSpecialAccess(
            context = context,
            pkgInfo = pkgInfo,
            appInfo = appInfo,
            enabledAccessibility = enabledAccessibilityServices,
            enabledNotificationListeners = enabledNotificationListeners,
            activeDeviceAdmins = activeDeviceAdmins
        )

        // 2. Extract Declared vs Granted Permissions + Service/Receiver Special Bindings (Must-Have 02)
        val extractedPermissions = extractPermissions(
            pm = pm,
            pkgInfo = pkgInfo,
            enabledAccessibility = enabledAccessibilityServices,
            enabledNotificationListeners = enabledNotificationListeners,
            activeDeviceAdmins = activeDeviceAdmins,
            specialAccessList = specialAccess
        )

        // 3. Static Manifest & APK Hash Inspection (Stretch Goals 11 & 12)
        val staticAudit = inspectStaticManifestAndHash(
            pkgInfo = pkgInfo,
            appInfo = appInfo,
            computeSha256 = computeSha256
        )

        return AppAuditRecord(
            appName = appName,
            packageName = pkgName,
            versionName = versionName,
            appIcon = appIcon,
            appCategoryLabel = appCategoryLabel,
            isSystemApp = isSystem,
            installDateMs = pkgInfo.firstInstallTime,
            lastUpdateMs = pkgInfo.lastUpdateTime,
            installerSource = installer,
            installerDisplayName = installerDisplayName,
            isSideloaded = isSideloaded,
            targetSdk = appInfo.targetSdkVersion,
            permissions = extractedPermissions,
            specialAccessGranted = specialAccess,
            staticAudit = staticAudit
        )
    }

    /**
     * Extracts every requested permission AND component-bound special permissions
     * (like BIND_ACCESSIBILITY_SERVICE, BIND_DEVICE_ADMIN, BIND_NOTIFICATION_LISTENER_SERVICE,
     * which Android apps declare on <service> or <receiver> tags rather than <uses-permission>).
     */
    private fun extractPermissions(
        pm: PackageManager,
        pkgInfo: PackageInfo,
        enabledAccessibility: Set<String>,
        enabledNotificationListeners: Set<String>,
        activeDeviceAdmins: Set<String>,
        specialAccessList: List<String>
    ): List<PermissionItem> {
        val list = mutableListOf<PermissionItem>()
        val seenPermissions = mutableSetOf<String>()
        val pkgName = pkgInfo.packageName

        val requestedNames = pkgInfo.requestedPermissions ?: emptyArray()
        val requestedFlags = pkgInfo.requestedPermissionsFlags ?: IntArray(requestedNames.size)

        for (i in requestedNames.indices) {
            val permName = requestedNames[i]
            seenPermissions.add(permName)

            val shortName = permName.substringAfterLast('.')
            val isGranted = when (shortName) {
                "SYSTEM_ALERT_WINDOW" -> specialAccessList.any { it.contains("Overlay (GRANTED)") }
                "REQUEST_INSTALL_PACKAGES" -> specialAccessList.any { it.contains("Install Unknown Apps (GRANTED)") }
                "PACKAGE_USAGE_STATS" -> specialAccessList.any { it.contains("Usage Access (GRANTED)") }
                "MANAGE_EXTERNAL_STORAGE" -> specialAccessList.any { it.contains("All Files Storage Access (GRANTED)") }
                else -> (requestedFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            }

            val protectionLevel = resolveProtectionLevel(pm, permName)
            val category = mapPermissionToCategory(permName)

            list.add(
                PermissionItem(
                    name = permName,
                    shortName = shortName,
                    isGranted = isGranted,
                    protectionLevel = protectionLevel,
                    category = category
                )
            )
        }

        // Check <service> tags for Accessibility & Notification Listener bindings
        val hasAccessibilityService = pkgInfo.services?.any {
            it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        } == true || pkgName in enabledAccessibility

        if (hasAccessibilityService && "android.permission.BIND_ACCESSIBILITY_SERVICE" !in seenPermissions) {
            list.add(
                PermissionItem(
                    name = "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    shortName = "BIND_ACCESSIBILITY_SERVICE",
                    isGranted = pkgName in enabledAccessibility,
                    protectionLevel = "special",
                    category = PermCategory.SPECIAL_ACCESS
                )
            )
        }

        val hasNotificationListener = pkgInfo.services?.any {
            it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        } == true || pkgName in enabledNotificationListeners

        if (hasNotificationListener && "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" !in seenPermissions) {
            list.add(
                PermissionItem(
                    name = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                    shortName = "BIND_NOTIFICATION_LISTENER_SERVICE",
                    isGranted = pkgName in enabledNotificationListeners,
                    protectionLevel = "special",
                    category = PermCategory.SPECIAL_ACCESS
                )
            )
        }

        // Check <receiver> tags for Device Admin bindings
        val hasDeviceAdmin = pkgInfo.receivers?.any {
            it.permission == "android.permission.BIND_DEVICE_ADMIN"
        } == true || pkgName in activeDeviceAdmins

        if (hasDeviceAdmin && "android.permission.BIND_DEVICE_ADMIN" !in seenPermissions) {
            list.add(
                PermissionItem(
                    name = "android.permission.BIND_DEVICE_ADMIN",
                    shortName = "BIND_DEVICE_ADMIN",
                    isGranted = pkgName in activeDeviceAdmins,
                    protectionLevel = "special",
                    category = PermCategory.SPECIAL_ACCESS
                )
            )
        }

        return list
    }

    /**
     * Resolves Android PermissionInfo protectionLevel into the 4 PS-01 labels:
     * "normal", "dangerous", "signature", or "special".
     */
    @Suppress("DEPRECATION")
    private fun resolveProtectionLevel(pm: PackageManager, permName: String): String {
        if (permName.endsWith("SYSTEM_ALERT_WINDOW") ||
            permName.endsWith("REQUEST_INSTALL_PACKAGES") ||
            permName.endsWith("PACKAGE_USAGE_STATS") ||
            permName.endsWith("BIND_ACCESSIBILITY_SERVICE") ||
            permName.endsWith("BIND_NOTIFICATION_LISTENER_SERVICE") ||
            permName.endsWith("BIND_DEVICE_ADMIN") ||
            permName.endsWith("MANAGE_EXTERNAL_STORAGE")
        ) {
            return "special"
        }

        return try {
            val permInfo = pm.getPermissionInfo(permName, 0)
            val baseLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                permInfo.protection
            } else {
                permInfo.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE
            }
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                permInfo.protectionFlags
            } else {
                permInfo.protectionLevel and PermissionInfo.PROTECTION_MASK_FLAGS
            }

            when {
                (flags and PermissionInfo.PROTECTION_FLAG_APPOP) != 0 -> "special"
                baseLevel == PermissionInfo.PROTECTION_DANGEROUS -> "dangerous"
                baseLevel == PermissionInfo.PROTECTION_SIGNATURE ||
                        baseLevel == PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM -> "signature"
                else -> "normal"
            }
        } catch (e: PackageManager.NameNotFoundException) {
            "normal"
        }
    }

    /**
     * Maps raw Android permission strings into the 9 required categories from PS-01 Section 02.
     */
    fun mapPermissionToCategory(permName: String): PermCategory? {
        val short = permName.substringAfterLast('.')
        return when (short) {
            // 01 Special access
            "BIND_ACCESSIBILITY_SERVICE",
            "SYSTEM_ALERT_WINDOW",
            "BIND_DEVICE_ADMIN",
            "BIND_NOTIFICATION_LISTENER_SERVICE",
            "REQUEST_INSTALL_PACKAGES",
            "PACKAGE_USAGE_STATS",
            "LOADER_USAGE_STATS" -> PermCategory.SPECIAL_ACCESS

            // 02 SMS
            "READ_SMS",
            "RECEIVE_SMS",
            "SEND_SMS",
            "RECEIVE_MMS",
            "RECEIVE_WAP_PUSH" -> PermCategory.SMS

            // 03 Contacts and call logs
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "GET_ACCOUNTS",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "PROCESS_OUTGOING_CALLS" -> PermCategory.CONTACTS_CALL_LOGS

            // 04 Camera and microphone
            "CAMERA",
            "RECORD_AUDIO" -> PermCategory.CAMERA_MIC

            // 05 Location
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "ACCESS_BACKGROUND_LOCATION" -> PermCategory.LOCATION

            // 06 Phone and identity
            "READ_PHONE_STATE",
            "READ_PHONE_NUMBERS",
            "CALL_PHONE",
            "ANSWER_PHONE_CALLS",
            "USE_SIP" -> PermCategory.PHONE_IDENTITY

            // 07 Storage and media
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "MANAGE_EXTERNAL_STORAGE",
            "READ_MEDIA_IMAGES",
            "READ_MEDIA_VIDEO",
            "READ_MEDIA_AUDIO" -> PermCategory.STORAGE_MEDIA

            // 08 Background and persistence
            "RECEIVE_BOOT_COMPLETED",
            "FOREGROUND_SERVICE",
            "FOREGROUND_SERVICE_DATA_SYNC",
            "FOREGROUND_SERVICE_CAMERA",
            "FOREGROUND_SERVICE_MICROPHONE",
            "FOREGROUND_SERVICE_LOCATION",
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "WAKE_LOCK" -> PermCategory.BACKGROUND_PERSISTENCE

            // 09 Network
            "INTERNET",
            "ACCESS_NETWORK_STATE",
            "ACCESS_WIFI_STATE",
            "CHANGE_WIFI_STATE",
            "CHANGE_NETWORK_STATE" -> PermCategory.NETWORK

            else -> null
        }
    }

    /**
     * Must-Have 04: Detects Special Access granted or declared across both <uses-permission>
     * and <service>/<receiver> declarations.
     */
    private fun detectSpecialAccess(
        context: Context,
        pkgInfo: PackageInfo,
        appInfo: ApplicationInfo,
        enabledAccessibility: Set<String>,
        enabledNotificationListeners: Set<String>,
        activeDeviceAdmins: Set<String>
    ): List<String> {
        val pkgName = pkgInfo.packageName
        val detected = mutableListOf<String>()
        val requestedPerms = pkgInfo.requestedPermissions?.toSet() ?: emptySet()

        // 1. Accessibility Service (Enabled vs Declared in <service>)
        val declaresAccessibility = pkgInfo.services?.any {
            it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        } == true
        if (pkgName in enabledAccessibility) {
            detected.add("Accessibility Service (ENABLED)")
        } else if (declaresAccessibility) {
            detected.add("Accessibility Service (DECLARED)")
        }

        // 2. Device Admin (Active vs Declared in <receiver>)
        val declaresDeviceAdmin = pkgInfo.receivers?.any {
            it.permission == "android.permission.BIND_DEVICE_ADMIN"
        } == true
        if (pkgName in activeDeviceAdmins) {
            detected.add("Device Admin (ACTIVE)")
        } else if (declaresDeviceAdmin) {
            detected.add("Device Admin (DECLARED)")
        }

        // 3. Notification Listener (Enabled vs Declared in <service>)
        val declaresNotifListener = pkgInfo.services?.any {
            it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        } == true
        if (pkgName in enabledNotificationListeners) {
            detected.add("Notification Listener (ENABLED)")
        } else if (declaresNotifListener) {
            detected.add("Notification Listener (DECLARED)")
        }

        // 4. Screen Overlay (SYSTEM_ALERT_WINDOW)
        if ("android.permission.SYSTEM_ALERT_WINDOW" in requestedPerms) {
            val granted = checkAppOpGranted(context, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, appInfo.uid, pkgName)
            if (granted) {
                detected.add("Screen Overlay (GRANTED)")
            } else {
                detected.add("Screen Overlay (DECLARED)")
            }
        }

        // 5. Install Unknown Packages (REQUEST_INSTALL_PACKAGES)
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in requestedPerms) {
            val granted = checkAppOpGranted(context, "android:request_install_packages", appInfo.uid, pkgName)
            if (granted) {
                detected.add("Install Unknown Apps (GRANTED)")
            } else {
                detected.add("Install Unknown Apps (DECLARED)")
            }
        }

        // 6. Usage Stats (PACKAGE_USAGE_STATS)
        if ("android.permission.PACKAGE_USAGE_STATS" in requestedPerms) {
            val granted = checkAppOpGranted(context, AppOpsManager.OPSTR_GET_USAGE_STATS, appInfo.uid, pkgName)
            if (granted) {
                detected.add("Usage Access (GRANTED)")
            } else {
                detected.add("Usage Access (DECLARED)")
            }
        }

        // 7. All Files Access (MANAGE_EXTERNAL_STORAGE)
        if ("android.permission.MANAGE_EXTERNAL_STORAGE" in requestedPerms) {
            val granted = checkAppOpGranted(context, "android:manage_external_storage", appInfo.uid, pkgName)
            if (granted) {
                detected.add("All Files Storage Access (GRANTED)")
            }
        }

        return detected
    }

    @Suppress("DEPRECATION")
    private fun checkAppOpGranted(
        context: Context,
        opStr: String,
        uid: Int,
        pkgName: String
    ): Boolean {
        return try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(opStr, uid, pkgName)
            } else {
                appOps.checkOpNoThrow(opStr, uid, pkgName)
            }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (e: Exception) {
            false
        }
    }

    private fun getEnabledAccessibilityPackages(context: Context): Set<String> {
        return try {
            val settingValue = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return emptySet()
            settingValue.split(':')
                .mapNotNull { it.substringBefore('/').takeIf { pkg -> pkg.isNotBlank() } }
                .toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    private fun getEnabledNotificationListenerPackages(context: Context): Set<String> {
        return try {
            val settingValue = Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            ) ?: return emptySet()
            settingValue.split(':')
                .mapNotNull { it.substringBefore('/').takeIf { pkg -> pkg.isNotBlank() } }
                .toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    private fun getActiveDeviceAdminPackages(context: Context): Set<String> {
        return try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val activeAdmins = dpm.activeAdmins ?: return emptySet()
            activeAdmins.map { it.packageName }.toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    @Suppress("DEPRECATION")
    private fun getInstallerPackageNameCompat(pm: PackageManager, pkgName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                pm.getInstallerPackageName(pkgName)
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Stretch Goals 11 & 12:
     * - Inspects the static manifest flags (debuggable, cleartext traffic allowed, exported components)
     * - Computes or defers the SHA-256 hash of the base APK file
     */
    private fun inspectStaticManifestAndHash(
        pkgInfo: PackageInfo,
        appInfo: ApplicationInfo,
        computeSha256: Boolean
    ): StaticManifestAudit {
        val isDebuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val usesCleartext = (appInfo.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0

        val exportedActivities = pkgInfo.activities?.count { it.exported } ?: 0
        val exportedServices = pkgInfo.services?.count { it.exported } ?: 0
        val exportedReceivers = pkgInfo.receivers?.count { it.exported } ?: 0
        val exportedProviders = pkgInfo.providers?.count { it.exported } ?: 0

        val sha256 = if (computeSha256) {
            computeApkSha256(appInfo.sourceDir)
        } else {
            "Tap to compute SHA-256"
        }

        val threatLabel = KNOWN_SUSPICIOUS_SHA256[sha256]

        return StaticManifestAudit(
            apkPath = appInfo.sourceDir,
            apkSha256 = sha256,
            isKnownThreatHash = threatLabel != null,
            threatIntelLabel = threatLabel,
            isDebuggable = isDebuggable,
            usesCleartextTraffic = usesCleartext,
            exportedActivitiesCount = exportedActivities,
            exportedServicesCount = exportedServices,
            exportedReceiversCount = exportedReceivers,
            exportedProvidersCount = exportedProviders
        )
    }

    /**
     * Stretch Goal 11 helper: Computes the SHA-256 hash of the base APK on-device.
     */
    fun computeApkSha256(apkPath: String?): String {
        if (apkPath.isNullOrBlank()) return "Unavailable"
        return try {
            val file = File(apkPath)
            if (!file.exists() || !file.canRead()) return "Unavailable"
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(8192)
                var read: Int
                while (fis.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "Unavailable"
        }
    }
}

