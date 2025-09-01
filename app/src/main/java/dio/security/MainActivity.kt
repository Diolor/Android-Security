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
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dio.security.crypto.Algorithm
import dio.security.crypto.Algorithm.*
import dio.security.crypto.Jwt
import dio.security.crypto.DigestSize
import dio.security.crypto.DigestSize.*
import dio.security.crypto.Signature.sign
import dio.security.crypto.Signature.verify
import dio.security.crypto.algorithmToJwtSignature
import dio.security.crypto.algorithmToJavaSignature
import dio.security.crypto.toBase64
import dio.security.crypto.toPublicSignature
import dio.security.ui.ClipboardText
import dio.security.ui.KeyAndAlgorithmDropdowns
import dio.security.ui.theme.SecurityTheme
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

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
						.padding(all = 16.dp)
				) { innerPadding ->
					Column(
						modifier = Modifier
							.padding(innerPadding)
					) {
						Text(
							text = "StrongBox available in device: ${hasStrongBox()}",
							modifier = Modifier.padding(bottom = 8.dp),
						)

						var clearText by remember { mutableStateOf(textPlaceholder) }
						var selectedAlgorithm by remember { mutableStateOf(algorithms.first()) }
						var selectedDigestSize by remember { mutableStateOf(digestSizes.first()) }

						var javaAlgorithm by remember(selectedDigestSize, selectedAlgorithm) {
							mutableStateOf(algorithmToJavaSignature(selectedDigestSize, selectedAlgorithm))
						}
						var jwtAlgorithm by remember(selectedDigestSize, selectedAlgorithm) {
							mutableStateOf(algorithmToJwtSignature(selectedDigestSize, selectedAlgorithm))
						}

						var keyPair by remember(selectedAlgorithm, selectedDigestSize) {
							mutableStateOf(generateRSACert(selectedAlgorithm, selectedDigestSize))
						}
						var signed by remember(javaAlgorithm, keyPair.private, clearText) {
							mutableStateOf(sign(javaAlgorithm, keyPair.private, clearText.toByteArray()))
						}
						var verified by remember(javaAlgorithm, keyPair.public, signed) {
							mutableStateOf(
								verify(
									algorithm = javaAlgorithm,
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
							digestSizes,
							selectedDigestSize = selectedDigestSize,
							algorithms = algorithms,
							selectedAlgorithm = selectedAlgorithm,
							onSelectedKeySize = { selectedDigestSize = it },
							onSelectedAlgorithm = { selectedAlgorithm = it }
						)
						Text(
							text = "Algorithm: $javaAlgorithm ($jwtAlgorithm)",
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
							var jwt by remember(
								selectedDigestSize,
								selectedAlgorithm,
								javaAlgorithm,
								keyPair.private,
								clearText
							) {
								mutableStateOf(
									Jwt.create(
										digestSize = selectedDigestSize,
										algorithm = selectedAlgorithm,
										javaAlgorithm = javaAlgorithm,
										privateKey = keyPair.private,
										textToSign = clearText
									)
								)
							}
							ClipboardText(
								textToDisplay = "JWT:\n$jwt",
								textToCopy = jwt
							)

							Text(
								text = "Verified digest successfully against public key: $verified",
								modifier = Modifier.padding(bottom = 16.dp),
							)
						}
					}
				}
			}
		}
	}

	private fun generateRSACert(
		algorithm: Algorithm,
		selectedDigestSize: DigestSize,
	): KeyPair {
		val keyEntry = keystore.isKeyEntry(keystoreName)
		if (keyEntry) {
			keystore.deleteEntry(keystoreName)
		}

		val algorithmKey = algorithm.javaFamily

		val parameterSpecs: AlgorithmParameterSpec = when (algorithm) {
			ECDSA -> {
				when (selectedDigestSize) {
					DigestSize256 -> ECGenParameterSpec("secp256r1")
					DigestSize384 -> ECGenParameterSpec("secp384r1")
					DigestSize512 -> ECGenParameterSpec("secp521r1")
				}
			}

			RSA, RSAPSS -> {
				when (selectedDigestSize) {
					DigestSize256 -> RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
					DigestSize384 -> RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
					DigestSize512 -> RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)
				}
			}
		}

		val specs = KeyGenParameterSpec
			.Builder(
				keystoreName,
				PURPOSE_SIGN or PURPOSE_VERIFY
			)
			.setDigests(DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512)
			.setSignaturePaddings(SIGNATURE_PADDING_RSA_PSS, SIGNATURE_PADDING_RSA_PKCS1)
			.setAlgorithmParameterSpec(parameterSpecs)
			.build()

		return KeyPairGenerator
			.getInstance(algorithmKey, keystore.provider.name)
			.run {
				initialize(specs)
				generateKeyPair()
			}
	}
}
