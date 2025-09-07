package dio.security

import android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.DIGEST_SHA256
import android.security.keystore.KeyProperties.DIGEST_SHA384
import android.security.keystore.KeyProperties.DIGEST_SHA512
import android.security.keystore.KeyProperties.PURPOSE_SIGN
import android.security.keystore.KeyProperties.PURPOSE_VERIFY
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PSS
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
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
import dio.security.crypto.DigestSize
import dio.security.crypto.Jwt
import dio.security.crypto.SelectedAlgorithm
import dio.security.crypto.Signature.sign
import dio.security.crypto.Signature.verify
import dio.security.crypto.attestation.convert
import dio.security.crypto.isHardwareBacked
import dio.security.crypto.toBase64
import dio.security.crypto.toPem
import dio.security.ui.ClipboardText
import dio.security.ui.KeyAndAlgorithmDropdowns
import dio.security.ui.VerificationButtons
import dio.security.ui.theme.SecurityTheme
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate

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
	private val keyName = "test_key"

	private val digestSizes = DigestSize.all

	private val algorithms = Algorithm.all

	private val keystore = KeyStore.getInstance("AndroidKeyStore").apply {
		load(null)
	}

	private var lastAttestationChallenge: ByteArray? = null

	private val hasStrongBox: Boolean by lazy {
		packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)
	}

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		enableEdgeToEdge()
		setContent {

//			getCheckAvailableKeystoreProviders()

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
								text = "StrongBox available in device: $hasStrongBox",
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
								mutableStateOf(generateAsymmetricCert(selectedAlgorithm))
							}
							// RSA & ECDSA digests can be online tested with https://emn178.github.io/online-tools/ecdsa/verify/
							var signed by remember(selectedAlgorithm, keyPair.private, clearText) {
								mutableStateOf(
									sign(selectedAlgorithm, keyPair.private, clearText.toByteArray())
								)
							}
							// JWT can be online tested with https://jwt.io/#debugger-io
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

							val hardwareBackedKey = remember(keyPair.private) {
								keyPair.private.isHardwareBacked(keystore.provider.name)
							}
							val publicSignature = keyPair.public.toPem()
							val digestText = remember(signed) { signed.toBase64() }

							val challengeText = remember(keyPair) {
								lastAttestationChallenge?.toBase64() ?: "N/A"
							}
							val attestationPem = remember(keyPair) { getAttestationChainPem() }

							val attestationDetails = remember {
								keystore.getCertificateChain(keyName)
									.filterIsInstance<X509Certificate>()
									.firstNotNullOf { it.convert() }
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
								text = "Algorithm: ${selectedAlgorithm.getJavaSignatureName()} (${selectedAlgorithm.getJwtName()})" +
										"\n${selectedAlgorithm.extraInformation()}"
										+ "\nKey is hardware backed: $hardwareBackedKey",
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
								ClipboardText(
									textToDisplay = "Public key:\n${publicSignature.take(100)} [...]",
									textToCopy = publicSignature
								)
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

								ClipboardText(
									textToDisplay = "Attestation challenge (base64)\n(Random generated but it should normally come from BE):\n$challengeText",
									textToCopy = challengeText
								)
								ClipboardText(
									textToDisplay = "Attestation chain root (PEM, leaf -> root):\n${
										attestationPem.joinToString(
											separator = "\n\n"
										).take(100)
									} [...]",
									textToCopy = attestationPem.joinToString("\n\n")
								)

								Text(
									text = "Attestation challenge verified in certificate:\n${attestationDetails.attestationChallenge == challengeText}",
									modifier = Modifier.padding(vertical = 16.dp)
								)

								Text(
									text = "Attestation details:\n${attestationDetails}",
									modifier = Modifier.padding(bottom = 16.dp)
								)

							}
						}
					}
				}
			}
		}
	}

	/**
	 * Lists all available security providers and their services in the current environment.
	 *
	 * This can be useful for debugging or understanding the cryptographic capabilities available
	 * in the environment.
	 */
	private fun getCheckAvailableKeystoreProviders() = Security.getProviders().forEach {
		println("Provider: ${it.name} - ${it.info}")
		it.services.forEach { service ->
			println("\t Service: ${service.type} - ${service.algorithm} - ${service.className} - ${service.provider}")
		}
	}

	private fun getAttestationChainPem(alias: String = keyName): List<String> {
		return keystore.getCertificateChain(alias)
			.map { it.toPem() }
	}

	private fun generateAsymmetricCert(selectedAlgorithm: SelectedAlgorithm): KeyPair {
		val keyEntry = keystore.isKeyEntry(keyName)
		if (keyEntry) {
			keystore.deleteEntry(keyName)
		}

		// Normally the challenge should come from the server to ensure the attestation is for this specific request
		val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }.also {
			lastAttestationChallenge = it
		}

		return try {
			generateKeyPairCert(selectedAlgorithm, challenge, devicePropertiesAttestationIncluded = true)
		} catch (_: ProviderException) {
			println("Failed to attest device properties, retrying without it.")
			generateKeyPairCert(selectedAlgorithm, challenge, devicePropertiesAttestationIncluded = false)
		}
	}

	private fun createKeyGenSpecs(
		selectedAlgorithm: SelectedAlgorithm,
		challenge: ByteArray,
		devicePropertiesAttestationIncluded: Boolean
	): KeyGenParameterSpec = KeyGenParameterSpec
		.Builder(
			keyName,
			PURPOSE_SIGN or PURPOSE_VERIFY
		)
		.setDigests(DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512)
		.setSignaturePaddings(SIGNATURE_PADDING_RSA_PSS, SIGNATURE_PADDING_RSA_PKCS1)
		.setAlgorithmParameterSpec(selectedAlgorithm.getAlgorithmParameterSpec())
		// Explicitly requesting StrongBox. If not => TEE path
		.setIsStrongBoxBacked(hasStrongBox)
		// Add an attestation challenge to verify in the certificate
		.setAttestationChallenge(challenge)
		.run {
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
				val included = if (devicePropertiesAttestationIncluded) "with" else "without"
				println("Key will be attested $included device properties.")
				// Try add device attestation, but it's not guaranteed to be available on all devices
				setDevicePropertiesAttestationIncluded(devicePropertiesAttestationIncluded)
			} else {
				this
			}
		}
		.build()

	private fun generateKeyPairCert(
		selectedAlgorithm: SelectedAlgorithm,
		challenge: ByteArray,
		devicePropertiesAttestationIncluded: Boolean
	): KeyPair {
		val specs = createKeyGenSpecs(selectedAlgorithm, challenge, devicePropertiesAttestationIncluded)

		return KeyPairGenerator
			.getInstance(
				selectedAlgorithm.algorithm.javaStandardName,
				keystore.provider.name
			)
			.run {
				initialize(specs)
				generateKeyPair()
			}
	}
}
