package dio.security.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

/**
 * A section that displays signing information including cleartext, public key, digest, JWT, and verification status.
 */
@Composable
fun SigningSection(
	modifier: Modifier = Modifier,
	clearText: String,
	publicSignature: String,
	digestText: String,
	jwt: String,
	verified: Boolean,
) {
	Column(modifier = modifier) {
		Text(
			text = "Signing",
			style = MaterialTheme.typography.headlineMedium,
			modifier = Modifier.Companion.padding(vertical = 16.dp)
		)
		ClipboardText(
			header = "Cleartext",
			textToDisplay = clearText,
			textToCopy = clearText
		)
		ClipboardText(
			header = "Public key",
			textToDisplay = "${publicSignature.take(100)} [...]",
			textToCopy = publicSignature
		)
		ClipboardText(
			header = "Digest",
			textToDisplay = digestText,
			textToCopy = digestText
		)
		ClipboardText(
			header = "JWT",
			textToDisplay = jwt,
			textToCopy = jwt
		)
		Text(
			text = "Verified digest successfully against public key: $verified",
			modifier = Modifier.Companion.padding(bottom = 16.dp)
		)
	}
}

@Preview(showBackground = true)
@Composable
fun SigningSectionPreview() {
	SigningSection(
		clearText = "Sample clear text",
		publicSignature = "SamplePublicKey1234567890SamplePublicKey1234567890SamplePublicKey1234567890SamplePublicKey1234567890",
		digestText = "SampleDigest1234567890",
		jwt = "SampleJWTToken1234567890",
		verified = true
	)
}
