package dio.security

import android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.DIGEST_SHA256
import android.security.keystore.KeyProperties.DIGEST_SHA384
import android.security.keystore.KeyProperties.DIGEST_SHA512
import android.security.keystore.KeyProperties.PURPOSE_SIGN
import android.security.keystore.KeyProperties.PURPOSE_VERIFY
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PSS
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.Button
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import dio.security.crypto.Algorithm
import dio.security.crypto.Jwt
import dio.security.crypto.DigestSize
import dio.security.crypto.SelectedAlgorithm
import dio.security.crypto.Signature.sign
import dio.security.crypto.Signature.verify
import dio.security.crypto.toBase64
import dio.security.crypto.toPublicSignature
import dio.security.ui.ClipboardText
import dio.security.ui.KeyAndAlgorithmDropdowns
import dio.security.ui.theme.SecurityTheme
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import dio.security.ui.VerificationButtons

class MainActivity : ComponentActivity() {

	/**
	 * Text to be signed and verified.
	 *
	 * This text is used to test the signing and verification process.
	 */
	private val textPlaceholder = "Random text to test the app"

	/**
	 * Name of the key to be used in the Android Keystore.
	 */
	private val keystoreName = "test_key"

	private val digestSizes = DigestSize.all

	private val algorithms = Algorithm.all

	private val keystore = KeyStore.getInstance("AndroidKeyStore").apply {
		load(null)
	}

	private fun hasStrongBox(): Boolean {
		return packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)
	}

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		enableEdgeToEdge()
		setContent {

			SecurityTheme {
				Scaffold(
					modifier = Modifier
						.fillMaxSize()
				) { innerPadding ->
					Box(
						modifier = Modifier
							.padding(innerPadding)
					) {
						Column(
							modifier = Modifier.padding(16.dp)
						) {
							Text(
								text = "StrongBox available in device: ${hasStrongBox()}",
								modifier = Modifier.padding(bottom = 8.dp),
							)

							// User input
							var clearText by remember { mutableStateOf(textPlaceholder) }
							var userSelectedAlgorithm by remember { mutableStateOf(algorithms.first()) }
							var userSelectedDigestSize by remember { mutableStateOf(digestSizes.first()) }

							// Generated values
							var selectedAlgorithm by remember(userSelectedAlgorithm, userSelectedDigestSize) {
								mutableStateOf(SelectedAlgorithm(userSelectedAlgorithm, userSelectedDigestSize))
							}
							var keyPair by remember(selectedAlgorithm) {
								mutableStateOf(generateRSACert(selectedAlgorithm))
							}
							// RSA & ECDSA be online tested with https://emn178.github.io/online-tools/ecdsa/verify/
							var signed by remember(selectedAlgorithm, keyPair.private, clearText) {
								mutableStateOf(
									sign(selectedAlgorithm, keyPair.private, clearText.toByteArray())
								)
							}
							// Can be online tested with https://jwt.io/#debugger-io
							var jwt by remember(selectedAlgorithm, keyPair.private, clearText) {
								mutableStateOf(
									Jwt.create(selectedAlgorithm, keyPair.private, clearText)
								)
							}
							var verified by remember(selectedAlgorithm, keyPair.public, signed) {
								mutableStateOf(
									verify(
										algorithm = selectedAlgorithm,
										publicKey = keyPair.public,
										signedData = signed,
										dataToVerify = clearText.toByteArray()
									)
								)
							}

							OutlinedTextField(
								value = clearText,
								onValueChange = { newText -> clearText = newText },
								label = { Text("Text to sign") },
								modifier = Modifier
									.fillMaxWidth()
									.padding(bottom = 8.dp)
							)

							KeyAndAlgorithmDropdowns(
								algorithms = algorithms,
								digestSizes = digestSizes,
								selectedDigestSize = userSelectedDigestSize,
								selectedAlgorithm = userSelectedAlgorithm,
								onSelectedKeySize = { userSelectedDigestSize = it },
								onSelectedAlgorithm = { userSelectedAlgorithm = it }
							)
							Text(
								text = "Algorithm: ${selectedAlgorithm.getJavaSignatureName()} (${selectedAlgorithm.getJwtName()})\n${selectedAlgorithm.extraInformation()}",
								modifier = Modifier.padding(vertical = 16.dp)
							)

							Column(
								modifier = Modifier
									.verticalScroll(rememberScrollState())
									.fillMaxSize()
							) {

								ClipboardText(
									textToDisplay = "Cleartext:\n$clearText",
									feedbackMessage = "Cleartext copied to clipboard",
									textToCopy = clearText
								)
								val publicSignature = keyPair.public.toPublicSignature()
								ClipboardText(
									textToDisplay = "Public key:\n$publicSignature",
									textToCopy = publicSignature
								)
								val digestText = remember(signed) { signed.toBase64() }
								ClipboardText(
									textToDisplay = "Digest:\n${digestText}",
									textToCopy = digestText
								)
								ClipboardText(
									textToDisplay = "JWT:\n$jwt",
									textToCopy = jwt
								)

								Text(
									text = "Verified digest successfully against public key: $verified",
									modifier = Modifier.padding(bottom = 16.dp),
								)

								VerificationButtons()
							}
						}
					}
				}
			}
		}
	}

	private fun generateRSACert(selectedAlgorithm: SelectedAlgorithm): KeyPair {
		val keyEntry = keystore.isKeyEntry(keystoreName)
		if (keyEntry) {
			keystore.deleteEntry(keystoreName)
		}

		val specs = KeyGenParameterSpec
			.Builder(
				keystoreName,
				PURPOSE_SIGN or PURPOSE_VERIFY
			)
			.setDigests(DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512)
			.setSignaturePaddings(SIGNATURE_PADDING_RSA_PSS, SIGNATURE_PADDING_RSA_PKCS1)
			.setAlgorithmParameterSpec(selectedAlgorithm.getAlgorithmParameterSpec())
			.build()

		return KeyPairGenerator
			.getInstance(selectedAlgorithm.algorithm.javaStandardName, keystore.provider.name)
			.run {
				initialize(specs)
				generateKeyPair()
			}
	}
}
