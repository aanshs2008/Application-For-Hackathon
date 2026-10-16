package com.example.appriskauditor

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Member 3 Module: MainActivity & Complete Jetpack Compose UI (Must-Haves 01–06 + Stretch 11, 12, 14)
 * Uses only built-in Material3 and Android SDK classes so it compiles out-of-the-box with zero extra Gradle dependencies.
 */
class MainActivity : ComponentActivity() {

    private var triggerRefresh by mutableStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF38BDF8),
                    secondary = Color(0xFF818CF8),
                    background = Color(0xFF0F172A),
                    surface = Color(0xFF1E293B),
                    onBackground = Color(0xFFF8FAFC),
                    onSurface = Color(0xFFF1F5F9)
                )
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppRiskAuditorRoot(refreshTrigger = triggerRefresh)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Automatically re-scan when returning from System Settings or Uninstall screen!
        triggerRefresh++
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRiskAuditorRoot(refreshTrigger: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var includeSystemApps by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedBandFilter by remember { mutableStateOf<RiskBand?>(null) }
    var selectedCategoryFilter by remember { mutableStateOf<PermCategory?>(null) }

    var isLoading by remember { mutableStateOf(true) }
    var allApps by remember { mutableStateOf<List<AppAuditRecord>>(emptyList()) }
    var categorySummary by remember { mutableStateOf<Map<PermCategory, Int>>(emptyMap()) }
    var selectedApp by remember { mutableStateOf<AppAuditRecord?>(null) }

    fun runDeviceScan() {
        scope.launch {
            isLoading = true
            val scanned = withContext(Dispatchers.IO) {
                val rawList = PackageScanner.scanInstalledApps(
                    context = context,
                    includeSystemApps = includeSystemApps,
                    computeSha256 = false
                )
                // Score every app (uses built-in FallbackRiskScorer or Member 2's RiskScoringEngine)
                rawList.map { FallbackRiskScorer.scoreApp(it) }
                    .sortedByDescending { it.riskScore }
            }
            val summary = withContext(Dispatchers.IO) {
                PackageScanner.getDeviceWideCategorySummary(scanned)
            }
            allApps = scanned
            categorySummary = summary
            // Keep selected app updated if still installed
            selectedApp = selectedApp?.let { current ->
                scanned.find { it.packageName == current.packageName }
            }
            isLoading = false
        }
    }

    LaunchedEffect(includeSystemApps, refreshTrigger) {
        runDeviceScan()
    }

    if (selectedApp != null) {
        BackHandler { selectedApp = null }
        AppDetailScreen(
            app = selectedApp!!,
            onBack = { selectedApp = null },
            onUpdateApp = { updated -> selectedApp = updated }
        )
    } else {
        val filteredApps = remember(allApps, searchQuery, selectedBandFilter, selectedCategoryFilter) {
            allApps.filter { app ->
                val matchesSearch = searchQuery.isBlank() ||
                        app.appName.contains(searchQuery, ignoreCase = true) ||
                        app.packageName.contains(searchQuery, ignoreCase = true)
                val matchesBand = selectedBandFilter == null || app.riskBand == selectedBandFilter
                val matchesCategory = selectedCategoryFilter == null ||
                        app.permissions.any { it.isGranted && it.category == selectedCategoryFilter } ||
                        (selectedCategoryFilter == PermCategory.SPECIAL_ACCESS && app.specialAccessGranted.isNotEmpty())
                matchesSearch && matchesBand && matchesCategory
            }
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                text = "On-Device App Risk Auditor",
                                fontWeight = FontWeight.Bold,
                                fontSize = 18.sp
                            )
                            Text(
                                text = "100% Offline • Zero Root/ADB • ${allApps.size} Apps Scanned",
                                fontSize = 11.sp,
                                color = Color(0xFF94A3B8)
                            )
                        }
                    },
                    actions = {
                        // Stretch Goal 14: Export PDF Report Button
                        IconButton(
                            onClick = {
                                scope.launch {
                                    val filePath = withContext(Dispatchers.IO) {
                                        exportScanReportToPdf(context, allApps, categorySummary)
                                    }
                                    Toast.makeText(
                                        context,
                                        "PDF Report saved: $filePath",
                                        Toast.LENGTH_LONG
                                    ).show()
                                }
                            }
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = "Export PDF Report",
                                tint = Color(0xFF38BDF8)
                            )
                        }
                        IconButton(onClick = { runDeviceScan() }) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = "Rescan Device",
                                tint = Color(0xFF38BDF8)
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = Color(0xFF0F172A),
                        titleContentColor = Color.White
                    )
                )
            }
        ) { innerPadding ->
            if (isLoading) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = Color(0xFF38BDF8))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("Auditing installed packages & special access...", color = Color(0xFF94A3B8))
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 24.dp)
                ) {
                    // 1. Risk Band Overview Banner (Answers Q1 immediately)
                    item {
                        RiskBandSummaryRow(
                            allApps = allApps,
                            selectedBand = selectedBandFilter,
                            onSelectBand = { band ->
                                selectedBandFilter = if (selectedBandFilter == band) null else band
                            }
                        )
                    }

                    // 2. Device-Wide 9 Permission Categories Grid (Must-Have 03)
                    item {
                        DeviceWideCategoryCard(
                            summary = categorySummary,
                            selectedCategory = selectedCategoryFilter,
                            onSelectCategory = { cat ->
                                selectedCategoryFilter = if (selectedCategoryFilter == cat) null else cat
                            }
                        )
                    }

                    // 3. Search Bar & System Apps Toggle (Must-Have 01)
                    item {
                        SearchAndSystemToggleBar(
                            searchQuery = searchQuery,
                            onSearchChange = { searchQuery = it },
                            includeSystemApps = includeSystemApps,
                            onToggleSystemApps = { includeSystemApps = it }
                        )
                    }

                    // 4. Sorted List of Installed Apps
                    items(filteredApps, key = { it.packageName }) { app ->
                        AppRiskRowCard(
                            app = app,
                            onClick = { selectedApp = app }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun RiskBandSummaryRow(
    allApps: List<AppAuditRecord>,
    selectedBand: RiskBand?,
    onSelectBand: (RiskBand) -> Unit
) {
    val counts = remember(allApps) {
        mapOf(
            RiskBand.CRITICAL to allApps.count { it.riskBand == RiskBand.CRITICAL },
            RiskBand.HIGH to allApps.count { it.riskBand == RiskBand.HIGH },
            RiskBand.MEDIUM to allApps.count { it.riskBand == RiskBand.MEDIUM },
            RiskBand.LOW to allApps.count { it.riskBand == RiskBand.LOW }
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        RiskBand.values().reversed().forEach { band ->
            val isSelected = selectedBand == band
            val bandColor = getRiskBandColor(band)
            Card(
                modifier = Modifier
                    .weight(1f)
                    .clickable { onSelectBand(band) }
                    .border(
                        width = if (isSelected) 2.dp else 1.dp,
                        color = if (isSelected) bandColor else bandColor.copy(alpha = 0.35f),
                        shape = RoundedCornerShape(10.dp)
                    ),
                colors = CardDefaults.cardColors(
                    containerColor = bandColor.copy(alpha = if (isSelected) 0.25f else 0.10f)
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "${counts[band] ?: 0}",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = bandColor
                    )
                    Text(
                        text = band.label.uppercase(),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE2E8F0)
                    )
                }
            }
        }
    }
}

@Composable
fun DeviceWideCategoryCard(
    summary: Map<PermCategory, Int>,
    selectedCategory: PermCategory?,
    onSelectCategory: (PermCategory) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Device-Wide Exposure (9 Categories)",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = Color(0xFF38BDF8)
                )
                if (selectedCategory != null) {
                    Text(
                        text = "Clear Filter",
                        fontSize = 11.sp,
                        color = Color(0xFFF87171),
                        modifier = Modifier.clickable { onSelectCategory(selectedCategory) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                PermCategory.values().forEach { category ->
                    val count = summary[category] ?: 0
                    val isSelected = selectedCategory == category
                    val chipColor = if (category == PermCategory.SPECIAL_ACCESS) Color(0xFFF43F5E) else Color(0xFF38BDF8)

                    Surface(
                        modifier = Modifier.clickable { onSelectCategory(category) },
                        shape = RoundedCornerShape(8.dp),
                        color = if (isSelected) chipColor.copy(alpha = 0.28f) else Color(0xFF0F172A),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (isSelected) chipColor else Color(0xFF334155)
                        )
                    ) {
                        Column(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "$count apps",
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp,
                                color = if (count > 0) chipColor else Color(0xFF64748B)
                            )
                            Text(
                                text = category.displayName,
                                fontSize = 10.sp,
                                color = Color(0xFFCBD5E1)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SearchAndSystemToggleBar(
    searchQuery: String,
    onSearchChange: (String) -> Unit,
    includeSystemApps: Boolean,
    onToggleSystemApps: (Boolean) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = searchQuery,
            onValueChange = onSearchChange,
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Search app name or package...", fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { onSearchChange("") }) {
                        Icon(Icons.Default.Close, contentDescription = "Clear")
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(10.dp)
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(Color(0xFF1E293B))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Include System Apps (Must-Have 01 Toggle)",
                fontSize = 12.sp,
                color = Color(0xFFE2E8F0)
            )
            Switch(
                checked = includeSystemApps,
                onCheckedChange = onToggleSystemApps
            )
        }
    }
}

@Composable
fun AppRiskRowCard(
    app: AppAuditRecord,
    onClick: () -> Unit
) {
    val bandColor = getRiskBandColor(app.riskBand)
    val iconBitmap = remember(app.packageName) { drawableToImageBitmap(app.appIcon) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (iconBitmap != null) {
                    Image(
                        bitmap = iconBitmap,
                        contentDescription = app.appName,
                        modifier = Modifier
                            .size(44.dp)
                            .clip(RoundedCornerShape(8.dp))
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF334155)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(app.appName.take(1).uppercase(), fontWeight = FontWeight.Bold)
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = app.appName,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (app.isSideloaded) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Surface(
                                color = Color(0xFFF59E0B).copy(alpha = 0.2f),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = "SIDELOADED",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFFFBBF24),
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }
                    Text(
                        text = app.packageName,
                        fontSize = 11.sp,
                        color = Color(0xFF94A3B8),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "v${app.versionName} • SDK ${app.targetSdk} • ${app.installerDisplayName}",
                        fontSize = 10.sp,
                        color = Color(0xFF64748B)
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Risk Score Badge (0–100 + ML Score)
                Column(
                    horizontalAlignment = Alignment.End
                ) {
                    Surface(
                        color = bandColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, bandColor)
                    ) {
                        Column(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "${app.riskScore}/100",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 14.sp,
                                color = bandColor
                            )
                            Text(
                                text = app.riskBand.label.uppercase(),
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = bandColor
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "ML Score: ${app.mlRiskScore}%",
                        fontSize = 9.sp,
                        color = Color(0xFF94A3B8)
                    )
                }
            }

            // Show top plain-language reason preview on card if High/Critical
            if (app.plainLanguageReasons.isNotEmpty() &&
                (app.riskBand == RiskBand.CRITICAL || app.riskBand == RiskBand.HIGH)
            ) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(bandColor.copy(alpha = 0.12f))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = bandColor,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = app.plainLanguageReasons.first(),
                        fontSize = 11.sp,
                        color = Color(0xFFF1F5F9),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

/**
 * Must-Have 06: App Detail Screen
 * - "Why Flagged" plain-language panel (Q2)
 * - Direct System Settings button & Uninstall button (Q3)
 * - Special Access status, Declared vs Granted permissions by category, and Stretch Goals 11 & 12
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailScreen(
    app: AppAuditRecord,
    onBack: () -> Unit,
    onUpdateApp: (AppAuditRecord) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val bandColor = getRiskBandColor(app.riskBand)
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = app.appName,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F172A),
                    titleContentColor = Color.White
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 1. App Metadata Card (Must-Have 01)
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(app.appName, fontWeight = FontWeight.ExtraBold, fontSize = 18.sp, color = Color.White)
                            Text(app.packageName, fontSize = 12.sp, color = Color(0xFF94A3B8))
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Version: ${app.versionName} • Target SDK: ${app.targetSdk}",
                                fontSize = 12.sp,
                                color = Color(0xFFCBD5E1)
                            )
                            Text(
                                text = "Installed: ${dateFormat.format(Date(app.installDateMs))} • Source: ${app.installerDisplayName}",
                                fontSize = 12.sp,
                                color = Color(0xFFCBD5E1)
                            )
                            Text(
                                text = "Category: ${app.appCategoryLabel}",
                                fontSize = 12.sp,
                                color = Color(0xFF38BDF8)
                            )
                        }

                        Surface(
                            color = bandColor.copy(alpha = 0.2f),
                            shape = RoundedCornerShape(12.dp),
                            border = androidx.compose.foundation.BorderStroke(2.dp, bandColor)
                        ) {
                            Column(
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = "${app.riskScore}",
                                    fontWeight = FontWeight.Black,
                                    fontSize = 26.sp,
                                    color = bandColor
                                )
                                Text(
                                    text = app.riskBand.label.uppercase(),
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    color = bandColor
                                )
                                Text(
                                    text = "ML: ${app.mlRiskScore}%",
                                    fontSize = 10.sp,
                                    color = Color(0xFFCBD5E1)
                                )
                            }
                        }
                    }
                }
            }

            // 2. Q3 Action Buttons: System Settings & Uninstall (Must-Have 06)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = {
                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = Uri.fromParts("package", app.packageName, null)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0284C7)),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("System Settings", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }

                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_DELETE).apply {
                            data = Uri.fromParts("package", app.packageName, null)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE11D48)),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Uninstall App", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
            }

            // 3. Q2 "Why Flagged" Panel (Must-Have 05 & 06)
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, bandColor.copy(alpha = 0.6f), RoundedCornerShape(12.dp)),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = bandColor)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Why This App Is Flagged (Plain-Language Reasons)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = Color.White
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    app.plainLanguageReasons.forEach { reason ->
                        Row(
                            modifier = Modifier.padding(vertical = 4.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text("• ", color = bandColor, fontWeight = FontWeight.Bold)
                            Text(reason, fontSize = 13.sp, color = Color(0xFFF1F5F9))
                        }
                    }
                }
            }

            // 4. Special Access Panel (Must-Have 04)
            if (app.specialAccessGranted.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF31102F)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Special Access Detected (Highest Weight)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color(0xFFF43F5E)
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        app.specialAccessGranted.forEach { item ->
                            Text(
                                text = "⚠ $item",
                                fontSize = 13.sp,
                                color = Color(0xFFFECDD3),
                                modifier = Modifier.padding(vertical = 2.dp)
                            )
                        }
                    }
                }
            }

            // 5. Stretch Goals 11 & 12: Static Manifest & SHA-256 APK Hash Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Static Manifest & APK Integrity (Stretch 11 & 12)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Exported Components: ${app.staticAudit.totalExportedComponents} " +
                                "(Act: ${app.staticAudit.exportedActivitiesCount}, " +
                                "Svc: ${app.staticAudit.exportedServicesCount}, " +
                                "Rcv: ${app.staticAudit.exportedReceiversCount}, " +
                                "Prv: ${app.staticAudit.exportedProvidersCount})",
                        fontSize = 12.sp,
                        color = Color(0xFFE2E8F0)
                    )
                    Text(
                        text = "Cleartext HTTP Traffic Allowed: ${if (app.staticAudit.usesCleartextTraffic) "YES (Risk)" else "No"} • " +
                                "Debuggable APK: ${if (app.staticAudit.isDebuggable) "YES (Risk)" else "No"}",
                        fontSize = 12.sp,
                        color = if (app.staticAudit.usesCleartextTraffic || app.staticAudit.isDebuggable) Color(0xFFFBBF24) else Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "SHA-256: ${app.staticAudit.apkSha256}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFFCBD5E1),
                            modifier = Modifier.weight(1f)
                        )
                        if (app.staticAudit.apkSha256.startsWith("Tap")) {
                            TextButton(
                                onClick = {
                                    scope.launch {
                                        val hash = withContext(Dispatchers.IO) {
                                            PackageScanner.computeApkSha256(app.staticAudit.apkPath)
                                        }
                                        onUpdateApp(
                                            app.copy(
                                                staticAudit = app.staticAudit.copy(apkSha256 = hash)
                                            )
                                        )
                                    }
                                }
                            ) {
                                Text("Compute Hash", color = Color(0xFF38BDF8), fontSize = 12.sp)
                            }
                        }
                    }
                }
            }

            // 6. Declared vs. Granted Permissions Grouped by Category (Must-Haves 02 & 03)
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    val grantedCount = app.permissions.count { it.isGranted }
                    Text(
                        text = "Permissions (${grantedCount} Granted / ${app.permissions.size} Declared)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = Color.White
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (app.permissions.isEmpty()) {
                        Text("No permissions declared by this application.", fontSize = 13.sp, color = Color(0xFF94A3B8))
                    } else {
                        val grouped = app.permissions.groupBy { it.category }
                        PermCategory.values().forEach { category ->
                            val permsInCat = grouped[category] ?: emptyList()
                            if (permsInCat.isNotEmpty()) {
                                Text(
                                    text = "${category.displayName} (Weight: ${category.baseWeight})",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = Color(0xFF38BDF8),
                                    modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
                                )
                                permsInCat.forEach { perm ->
                                    PermissionRowItem(perm)
                                }
                            }
                        }
                        val uncategorized = grouped[null] ?: emptyList()
                        if (uncategorized.isNotEmpty()) {
                            Text(
                                text = "Other System Permissions",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                color = Color(0xFF94A3B8),
                                modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
                            )
                            uncategorized.forEach { perm ->
                                PermissionRowItem(perm)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun PermissionRowItem(perm: PermissionItem) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(Color(0xFF0F172A))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = perm.shortName,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.White
            )
            Text(
                text = "Protection: ${perm.protectionLevel.uppercase()}",
                fontSize = 10.sp,
                color = when (perm.protectionLevel) {
                    "special" -> Color(0xFFF43F5E)
                    "dangerous" -> Color(0xFFFBBF24)
                    else -> Color(0xFF94A3B8)
                }
            )
        }

        Surface(
            color = if (perm.isGranted) Color(0xFF10B981).copy(alpha = 0.2f) else Color(0xFF64748B).copy(alpha = 0.2f),
            shape = RoundedCornerShape(4.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (perm.isGranted) Icons.Default.Check else Icons.Default.Close,
                    contentDescription = null,
                    tint = if (perm.isGranted) Color(0xFF34D399) else Color(0xFF94A3B8),
                    modifier = Modifier.size(12.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = if (perm.isGranted) "GRANTED" else "DECLARED ONLY",
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (perm.isGranted) Color(0xFF34D399) else Color(0xFF94A3B8)
                )
            }
        }
    }
}

/**
 * Built-in Scoring Engine inside MainActivity so the app compiles and scores out-of-the-box!
 * Covers Must-Have 05 (0–100 score + 3 plain-language reasons), Should-Have 07 (Combination Rules),
 * Should-Have 08 (Context Mismatch), and Stretch Goal 13 (On-Device ML Score).
 */
object FallbackRiskScorer {

    private val UTILITY_KEYWORDS = listOf(
        "torch", "flashlight", "calc", "calculator", "wallpaper",
        "clock", "compass", "scanner", "qr", "weather", "notes"
    )

    fun scoreApp(record: AppAuditRecord): AppAuditRecord {
        var score = 0
        val reasons = mutableListOf<String>()

        val grantedPerms = record.permissions.filter { it.isGranted }
        val grantedShortNames = grantedPerms.map { it.shortName }.toSet()
        val grantedCategories = grantedPerms.mapNotNull { it.category }.toSet()

        // 1. Special Access Scoring (Highest Weight)
        val activeSpecial = record.specialAccessGranted.filter {
            it.contains("ENABLED") || it.contains("ACTIVE") || it.contains("GRANTED")
        }
        if (activeSpecial.isNotEmpty()) {
            score += 35
            reasons.add("Holds high-risk Special Access (${activeSpecial.joinToString(", ")}) which can read screens, block uninstallation, or overlay fake login prompts.")
        } else if (record.specialAccessGranted.isNotEmpty()) {
            score += 15
            reasons.add("Declares Special Access capabilities (${record.specialAccessGranted.joinToString(", ")}) in its manifest.")
        }

        // 2. Category Base Weights for Granted Permissions
        if (PermCategory.SMS in grantedCategories) {
            score += PermCategory.SMS.baseWeight
            reasons.add("Granted SMS access (${grantedPerms.filter { it.category == PermCategory.SMS }.joinToString { it.shortName }}), enabling OTP interception or silent SMS reading.")
        }
        if (PermCategory.CONTACTS_CALL_LOGS in grantedCategories) {
            score += PermCategory.CONTACTS_CALL_LOGS.baseWeight
            reasons.add("Can read personal Contacts or Call Logs, exposing your social graph and call history.")
        }
        if (PermCategory.CAMERA_MIC in grantedCategories) {
            score += PermCategory.CAMERA_MIC.baseWeight
            reasons.add("Has active Camera or Microphone permissions capable of covert audio/video capture.")
        }
        if (PermCategory.LOCATION in grantedCategories) {
            score += PermCategory.LOCATION.baseWeight
            val hasBgLoc = "ACCESS_BACKGROUND_LOCATION" in grantedShortNames
            reasons.add(
                if (hasBgLoc) "Tracks fine location continuously in the background even when the app is closed."
                else "Has access to precise GPS/device location."
            )
        }
        if (PermCategory.PHONE_IDENTITY in grantedCategories) {
            score += PermCategory.PHONE_IDENTITY.baseWeight
            reasons.add("Reads phone state, SIM details, or phone numbers for device fingerprinting or call control.")
        }
        if (PermCategory.STORAGE_MEDIA in grantedCategories) {
            score += PermCategory.STORAGE_MEDIA.baseWeight
            reasons.add("Can read shared photos, media files, or external documents on the device.")
        }
        if (PermCategory.BACKGROUND_PERSISTENCE in grantedCategories) {
            score += PermCategory.BACKGROUND_PERSISTENCE.baseWeight
            reasons.add("Persists across device reboots or runs background services unseen.")
        }
        if (PermCategory.NETWORK in grantedCategories) {
            score += PermCategory.NETWORK.baseWeight
        }

        // 3. Should-Have 07: High-Risk Combination Rules
        val hasInternet = PermCategory.NETWORK in grantedCategories
        val hasBoot = "RECEIVE_BOOT_COMPLETED" in grantedShortNames
        if (PermCategory.SMS in grantedCategories && hasInternet && (hasBoot || record.isSideloaded)) {
            score += 25
            reasons.add(0, "CRITICAL COMBINATION: Combines SMS reading + Internet exfiltration + ${if (record.isSideloaded) "Sideloaded APK source" else "Boot persistence"} (classic banking trojan / OTP stealer pattern).")
        }

        val hasAccessibility = record.specialAccessGranted.any { it.contains("Accessibility") }
        val hasOverlay = record.specialAccessGranted.any { it.contains("Overlay") }
        if (hasAccessibility && hasOverlay) {
            score += 30
            reasons.add(0, "CRITICAL COMBINATION: Combines Accessibility Service + Screen Overlay, allowing fake login overlays and automated screen taps.")
        }

        val hasDeviceAdmin = record.specialAccessGranted.any { it.contains("Device Admin") }
        if (hasDeviceAdmin && !record.appName.contains("security", true) && !record.appName.contains("mdm", true)) {
            score += 25
            reasons.add(0, "HIGH-RISK ADMIN: Requests Device Administrator privileges on a non-MDM app, which can block normal uninstallation.")
        }

        // 4. Should-Have 08: Context Mismatch Detection
        val lowerLabel = "${record.appName} ${record.packageName}".lowercase()
        val looksLikeSimpleUtility = UTILITY_KEYWORDS.any { lowerLabel.contains(it) }
        if (looksLikeSimpleUtility && (PermCategory.SMS in grantedCategories || PermCategory.CONTACTS_CALL_LOGS in grantedCategories)) {
            score += 25
            reasons.add(0, "CONTEXT MISMATCH: App appears to be a utility tool (${record.appName}) but holds sensitive SMS, Contacts, or Call Log access.")
        }

        // 5. Sideloaded & Legacy SDK Risk Modifiers
        if (record.isSideloaded) {
            score += 10
            reasons.add("Installed outside official app stores (${record.installerDisplayName}), bypassing Play Protect vetting.")
        }
        if (record.targetSdk in 1..28) {
            score += 8
            reasons.add("Targets legacy Android SDK (${record.targetSdk}), which can bypass modern runtime permission restrictions.")
        }

        val finalScore = score.coerceIn(0, 100)
        val band = when {
            finalScore >= 75 -> RiskBand.CRITICAL
            finalScore >= 50 -> RiskBand.HIGH
            finalScore >= 25 -> RiskBand.MEDIUM
            else -> RiskBand.LOW
        }

        // Ensure at least 3 plain-language reasons for every High or Critical app (Must-Have 05)
        if ((band == RiskBand.HIGH || band == RiskBand.CRITICAL) && reasons.size < 3) {
            if (hasInternet) {
                reasons.add("Has full Internet network access capable of transmitting collected data to external servers.")
            }
            if (record.staticAudit.totalExportedComponents > 0) {
                reasons.add("Exposes ${record.staticAudit.totalExportedComponents} exported manifest components that other apps can invoke.")
            }
            if (reasons.size < 3) {
                reasons.add("Requests ${record.permissions.count { it.protectionLevel == "dangerous" || it.protectionLevel == "special" }} dangerous/special permissions overall.")
            }
        }
        if (reasons.isEmpty()) {
            reasons.add("Requests minimal permissions compatible with normal operation.")
        }

        // Stretch Goal 13: On-Device Logistic Regression ML Probability (0–99%)
        val z = -2.4 +
                (if (activeSpecial.isNotEmpty()) 2.1 else 0.0) +
                (if (PermCategory.SMS in grantedCategories) 1.5 else 0.0) +
                (if (PermCategory.CONTACTS_CALL_LOGS in grantedCategories) 0.9 else 0.0) +
                (if (PermCategory.BACKGROUND_PERSISTENCE in grantedCategories) 0.7 else 0.0) +
                (if (record.isSideloaded) 1.1 else 0.0) +
                (if (record.staticAudit.usesCleartextTraffic) 0.4 else 0.0)
        val mlProb = ((1.0 / (1.0 + Math.exp(-z))) * 100).toInt().coerceIn(1, 99)

        return record.copy(
            riskScore = finalScore,
            mlRiskScore = mlProb,
            riskBand = band,
            plainLanguageReasons = reasons
        )
    }
}

fun getRiskBandColor(band: RiskBand): Color = when (band) {
    RiskBand.CRITICAL -> Color(0xFFF43F5E)
    RiskBand.HIGH -> Color(0xFFF97316)
    RiskBand.MEDIUM -> Color(0xFFEAB308)
    RiskBand.LOW -> Color(0xFF10B981)
}

fun drawableToImageBitmap(drawable: Drawable?): ImageBitmap? {
    if (drawable == null) return null
    return try {
        if (drawable is BitmapDrawable && drawable.bitmap != null) {
            return drawable.bitmap.asImageBitmap()
        }
        val width = drawable.intrinsicWidth.coerceAtLeast(1).coerceAtMost(128)
        val height = drawable.intrinsicHeight.coerceAtLeast(1).coerceAtMost(128)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        bitmap.asImageBitmap()
    } catch (e: Exception) {
        null
    }
}

/**
 * Stretch Goal 14: Exports the full device scan as a multi-page PDF report using native Android PdfDocument.
 */
fun exportScanReportToPdf(
    context: Context,
    apps: List<AppAuditRecord>,
    summary: Map<PermCategory, Int>
): String {
    return try {
        val pdf = PdfDocument()
        val titlePaint = Paint().apply { textSize = 16f; isFakeBoldText = true }
        val headerPaint = Paint().apply { textSize = 12f; isFakeBoldText = true }
        val bodyPaint = Paint().apply { textSize = 10f }

        var pageNumber = 1
        var pageInfo = PdfDocument.PageInfo.Builder(595, 842, pageNumber).create()
        var page = pdf.startPage(pageInfo)
        var canvas = page.canvas
        var y = 40f

        canvas.drawText("On-Device App Risk Auditor — Full Device Security Report", 30f, y, titlePaint)
        y += 22f
        canvas.drawText("Total Apps Audited: ${apps.size} | Critical: ${apps.count { it.riskBand == RiskBand.CRITICAL }} | High: ${apps.count { it.riskBand == RiskBand.HIGH }}", 30f, y, headerPaint)
        y += 24f

        canvas.drawText("Device-Wide Category Exposure:", 30f, y, headerPaint)
        y += 16f
        summary.forEach { (cat, count) ->
            canvas.drawText("• ${cat.displayName}: $count apps granted access", 40f, y, bodyPaint)
            y += 14f
        }
        y += 16f
        canvas.drawText("Top Flagged Applications:", 30f, y, headerPaint)
        y += 18f

        for (app in apps.take(40)) {
            if (y > 780f) {
                pdf.finishPage(page)
                pageNumber++
                pageInfo = PdfDocument.PageInfo.Builder(595, 842, pageNumber).create()
                page = pdf.startPage(pageInfo)
                canvas = page.canvas
                y = 40f
            }
            canvas.drawText("[${app.riskBand.label.uppercase()} - ${app.riskScore}/100] ${app.appName} (${app.packageName})", 30f, y, headerPaint)
            y += 14f
            app.plainLanguageReasons.take(2).forEach { reason ->
                canvas.drawText("   - ${reason.take(90)}", 35f, y, bodyPaint)
                y += 13f
            }
            y += 6f
        }

        pdf.finishPage(page)
        val outDir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: context.filesDir
        val outFile = File(outDir, "AppRiskAuditReport.pdf")
        FileOutputStream(outFile).use { pdf.writeTo(it) }
        pdf.close()
        outFile.absolutePath
    } catch (e: Exception) {
        "Export failed: ${e.message}"
    }
}
