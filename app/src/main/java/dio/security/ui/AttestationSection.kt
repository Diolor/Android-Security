package dio.security.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dio.security.crypto.attestation.AttestationApplicationId
import dio.security.crypto.attestation.AttestationDetails
import dio.security.crypto.attestation.AttestationPackageInfo
import dio.security.crypto.attestation.RootOfTrust
import dio.security.ui.theme.SecurityTheme

/**
 * A section that displays key attestation information.
 */
@Composable
fun AttestationSection(
	challengeText: String,
	attestationPemChain: Set<String>,
	attestationDetails: AttestationDetails,
	appSignaturesSha256: Set<String>
) {
	val attestationChallengeMatches = attestationDetails.attestationChallenge == challengeText
	val appSigningCertificates = attestationDetails.getAppSigningCertificates()
	val matchesSignature = appSignaturesSha256.union(appSigningCertificates).isNotEmpty()

	Column {
		Text(
			text = "Key Attestation",
			style = MaterialTheme.typography.headlineMedium,
			modifier = Modifier.Companion.padding(vertical = 16.dp)
		)

		ClipboardText(
			header = "Attestation challenge (base64)",
			textToDisplay = "(Random generated but it should normally come from BE)\n$challengeText",
			textToCopy = challengeText
		)
		ClipboardText(
			header = "Attestation Certificate chain\n(PEM, leaf -> root)",
			textToDisplay = attestationPemChain.joinToString(separator = "\n\n")
				.take(100) + "[...]",
			textToCopy = attestationPemChain.joinToString("\n\n")
		)

		HorizontalDivider()

		Text(
			text = "Certificate attestation details",
			style = MaterialTheme.typography.titleMedium,
			modifier = Modifier.Companion.padding(top = 16.dp)
		)
		Text(
			text = attestationDetails.toString(),
			modifier = Modifier.Companion.padding(bottom = 16.dp)
		)
		Text(
			text = "Attestation challenge verified in certificate:$attestationChallengeMatches",
			modifier = Modifier.Companion.padding(vertical = 16.dp)
		)

		Text(
			text = "Hex SHA-256 digest that the app was signed with",
			style = MaterialTheme.typography.titleMedium,
			modifier = Modifier.Companion.padding(top = 16.dp)
		)
		Text(
			text = appSigningCertificates.joinToString(separator = "\n"),
			modifier = Modifier.Companion.padding(bottom = 16.dp)
		)

		attestationDetails.getRootOfTrust().forEach { info ->
			Text(
				text = "Boot Hash",
				style = MaterialTheme.typography.titleMedium,
				modifier = Modifier.Companion.padding(top = 16.dp)
			)
			Text(text = info.verifiedBootHash)
			Text(
				text = "Device locked: ${info.deviceLocked}\nVerified boot state: ${info.verifiedBootState}",
				modifier = Modifier.Companion.padding(bottom = 16.dp)
			)
		}

		Text(
			text = "Attestation certificates match app signatures: $matchesSignature",
			modifier = Modifier.Companion.padding(bottom = 16.dp)
		)
	}
}

@Preview(showBackground = true, showSystemUi = false)
@Composable
fun AttestationSectionPreview() {
	SecurityTheme {

		AttestationSection(
			challengeText = "sample-challenge",
			attestationPemChain = setOf("pem1", "pem2"),
			attestationDetails = AttestationDetails(
				attestationVersion = 3,
				attestationSecurityLevel = "TrustedEnvironment",
				keymasterVersion = 41,
				keymasterSecurityLevel = "TrustedEnvironment",
				attestationChallenge = "challenge-base64==",
				softwareEnforced = emptyMap(),
				uniqueId = "unique-id-base64==",
				hardwareEnforced = mapOf(
					1 to AttestationApplicationId(
						packageInfos = listOf(
							AttestationPackageInfo(
								packageName = "com.example.app",
								version = 1
							)
						),
						signatureDigests = setOf("app-signature-base64==", "another-signature-base64==")
					),
					2 to RootOfTrust(
						verifiedBootHash = "00aa11bb22cc33dd44ee55ff66",
						verifiedBootKey = "base64key==",
						deviceLocked = true,
						verifiedBootState = "Verified"
					)
				)
			),
			appSignaturesSha256 = setOf("app-signature-base64==")
		)
	}
}
