package dio.security.ui

import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Composable
fun ClipboardText(
	textToDisplay: String,
	textToCopy: String = textToDisplay,
	feedbackMessage: String? = null,
	modifier: Modifier = Modifier.Companion,
	bottomPadding: Dp = 16.dp
) {
	val clipboardManager = LocalClipboardManager.current
	val context = LocalContext.current
	Text(
		text = textToDisplay,
		modifier = modifier
			.padding(bottom = bottomPadding)
			.fillMaxWidth()
			.clickable {
				clipboardManager.setText(AnnotatedString(textToCopy))

				feedbackMessage?.let {
					Toast
						.makeText(context, it, Toast.LENGTH_SHORT)
						.show()
				}
			},
	)
}