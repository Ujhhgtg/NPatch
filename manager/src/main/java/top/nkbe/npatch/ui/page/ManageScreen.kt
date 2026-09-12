// Tabs and retained pager ported from WeKit ui/agent/settings/PromptsScreen.kt.
package top.nkbe.npatch.ui.page

import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.distinctUntilChanged
import nkbe.util.ShizukuApi
import top.nkbe.npatch.R
import top.nkbe.npatch.ui.component.NPatchScaffold
import top.nkbe.npatch.ui.component.NPatchTopAppBar
import top.nkbe.npatch.ui.component.SearchBar
import top.nkbe.npatch.ui.component.m3AppBarBlur
import top.nkbe.npatch.ui.component.m3AppBarColor
import top.nkbe.npatch.ui.component.m3BackdropLayer
import top.nkbe.npatch.ui.component.rememberMaterial3BlurBackdrop
import top.nkbe.npatch.ui.page.manage.AppManageBody
import top.nkbe.npatch.ui.page.manage.AppManageFab
import top.nkbe.npatch.ui.page.manage.ModuleManageBody
import top.nkbe.npatch.ui.viewmodel.manage.ModuleManageViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManageScreen(
    navigator: Navigator,
    modifier: Modifier = Modifier,
    selectedPage: Int = 0,
    onSelectedPageChange: (Int) -> Unit = {},
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    val tabTitles = listOf(stringResource(R.string.apps), stringResource(R.string.modules))
    val safeSelectedPage = selectedPage.coerceIn(tabTitles.indices)
    val pagerState = rememberPagerState(initialPage = safeSelectedPage, pageCount = { tabTitles.size })
    val onPageChanged by rememberUpdatedState(onSelectedPageChange)
    val controller = rememberMainPagerState(pagerState)
    var searchQuery by rememberSaveable { mutableStateOf("") }
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val moduleManageViewModel = viewModel<ModuleManageViewModel>()
    val backdrop = rememberMaterial3BlurBackdrop()
    val layoutDirection = LocalLayoutDirection.current
    val bottomInset = maxOf(contentPadding.calculateBottomPadding(), WindowInsets.ime.asPaddingValues().calculateBottomPadding())

    // Share InstallerX's navigation controller with Main: clicks and Home shortcuts only
    // submit destinations, and user swipes are reported once the pager settles.
    LaunchedEffect(safeSelectedPage) { controller.animateToPage(safeSelectedPage) }
    LaunchedEffect(pagerState, controller) {
        snapshotFlow { Triple(pagerState.settledPage, pagerState.isScrollInProgress, controller.isNavigating) }
            .distinctUntilChanged()
            .collect { (page, scrolling, navigating) ->
                if (!scrolling && !navigating) {
                    controller.syncPage()
                    onPageChanged(page)
                }
            }
    }
    LaunchedEffect(pagerState.settledPage, ShizukuApi.isReady, moduleManageViewModel.enabledActivationPackagesKey) {
        if (pagerState.settledPage == 1) {
            moduleManageViewModel.refreshScopedActivationState()
            if (ShizukuApi.isReady) moduleManageViewModel.refreshEnabledActivations()
        }
    }

    NPatchScaffold(
        modifier = modifier.fillMaxSize().nestedScroll(scrollBehavior.nestedScrollConnection),
        contentWindowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout).only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        topBar = {
            NPatchTopAppBar(
                modifier = Modifier.m3AppBarBlur(backdrop),
                color = backdrop.m3AppBarColor(),
                title = stringResource(R.string.screen_manage),
                scrollBehavior = scrollBehavior,
                bottomContent = {
                    SearchBar(
                        query = searchQuery,
                        onQueryChange = { searchQuery = it },
                        modifier = Modifier.windowInsetsPadding(WindowInsets.systemBars.union(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)).padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                    PrimaryTabRow(
                        selectedTabIndex = controller.selectedPage,
                        modifier = Modifier.windowInsetsPadding(WindowInsets.systemBars.union(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)).padding(horizontal = 12.dp).padding(bottom = 8.dp),
                        containerColor = Color.Transparent,
                    ) {
                        tabTitles.forEachIndexed { index, title ->
                            Tab(
                                selected = controller.selectedPage == index,
                                onClick = { onPageChanged(index) },
                                text = { Text(title) },
                            )
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            if (pagerState.settledPage == 0) {
                AppManageFab(navigator, Modifier.padding(bottom = bottomInset))
            }
        },
    ) { innerPadding ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.fillMaxSize().m3BackdropLayer(backdrop),
            beyondViewportPageCount = 1,
        ) { page ->
            val listPadding = PaddingValues(
                start = innerPadding.calculateStartPadding(layoutDirection) + 16.dp,
                end = innerPadding.calculateEndPadding(layoutDirection) + 16.dp,
                top = innerPadding.calculateTopPadding() + 8.dp,
                bottom = innerPadding.calculateBottomPadding() + bottomInset +
                    if (page == 0) 96.dp else 16.dp,
            )
            when (page) {
                0 -> AppManageBody(navigator, searchQuery, listPadding)
                1 -> ModuleManageBody(searchQuery, listPadding, moduleManageViewModel)
            }
        }
    }
}
