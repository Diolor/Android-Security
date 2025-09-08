package dio.security.ui

import android.content.ClipData
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.toClipEntry
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

@Composable
fun ClipboardText(
	modifier: Modifier = Modifier,
	header: String,
	textToDisplay: String,
	textToCopy: String = textToDisplay,
	bottomPadding: Dp = 16.dp
) {
	val localClipboard = LocalClipboard.current
	val scope = rememberCoroutineScope()

	Column(
		modifier = modifier
			.clickable {
				val clipData = ClipData.newPlainText(header, textToCopy)
				scope.launch {
					localClipboard.setClipEntry(clipData.toClipEntry())
				}
			}
	) {
		Text(
			text = header,
			style = MaterialTheme.typography.titleMedium,
			modifier = modifier
		)

		Text(
			text = textToDisplay,
			modifier = modifier
				.padding(bottom = bottomPadding)
				.fillMaxWidth()
		)
	}
}

@Preview(showBackground = true)
@Composable
fun ClipboardTextPreview() {
	ClipboardText(
		textToDisplay = "Example value",
		header = "Example header",
	)
}