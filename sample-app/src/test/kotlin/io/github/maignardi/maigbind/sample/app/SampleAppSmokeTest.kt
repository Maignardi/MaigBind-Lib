package io.github.maignardi.maigbind.sample.app

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import io.github.maignardi.maigbind.android.BiometricCapability
import io.github.maignardi.maigbind.core.MaigBindResult
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SampleAppSmokeTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun rendersEnrollmentAndTransferControls() {
        composeRule.setContent {
            MaterialTheme {
                MaigBindDemoScreen(
                    biometricCapability = BiometricCapability.READY_STRONG,
                    hasEnrolledKey = { false },
                    getKeyId = { null },
                    onEnroll = { _, _, _, _ -> },
                    onTransfer = { _, _, _, _, _ -> },
                    onUnenroll = { MaigBindResult.Success(Unit) },
                )
            }
        }

        composeRule.onNodeWithText("MaigBind Security Demo").assertIsDisplayed()
        composeRule.onNodeWithText("Enroll Device").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("Sign & Execute Transfer").performScrollTo().assertIsDisplayed()
    }
}
