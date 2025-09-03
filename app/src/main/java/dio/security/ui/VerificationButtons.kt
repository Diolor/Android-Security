package dio.security.ui

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import dio.security.ui.theme.SecurityTheme

@Composable
fun VerificationButtons(modifier: Modifier = Modifier) {
	val context = LocalContext.current
	Row(
		modifier = modifier
			.fillMaxWidth()
			.padding(bottom = 16.dp)
			.height(IntrinsicSize.Min),
		horizontalArrangement = Arrangement.spacedBy(8.dp),
		verticalAlignment = Alignment.CenterVertically
	) {
		Button(
			onClick = {
				val url = "https://emn178.github.io/online-tools/ecdsa/verify/".toUri()
				context.startActivity(Intent(Intent.ACTION_VIEW, url))
			},
			modifier = modifier
				.weight(1f)
				.fillMaxHeight()
		) {
			Text(
				"Open EMN178 Verifier",
				modifier = modifier
					.fillMaxHeight()
					.wrapContentHeight(align = Alignment.CenterVertically)
			)
		}

		Button(
			onClick = {
				val url = "https://jwt.io/#debugger-io".toUri()
				context.startActivity(Intent(Intent.ACTION_VIEW, url))
			},
			modifier = modifier
				.weight(1f)
				.fillMaxHeight()
		) {
			Text(
				"Open JWT.io",
				modifier = modifier
					.fillMaxHeight()
					.wrapContentHeight(align = Alignment.CenterVertically)
			)
		}
	}
}

@Preview
@Composable
fun VerificationButtonsPreview() {
	SecurityTheme {
		VerificationButtons()
	}
}