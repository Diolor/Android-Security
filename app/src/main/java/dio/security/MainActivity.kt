package dio.security

import android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
import android.os.Bundle
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dio.security.crypto.Algorithm
import dio.security.crypto.CryptoConfiguration
import dio.security.crypto.DigestSize
import dio.security.crypto.KeyManager
import dio.security.crypto.Jwt
import dio.security.crypto.SelectedAlgorithm
import dio.security.crypto.Signature.sign
import dio.security.crypto.Signature.verify
import dio.security.crypto.toBase64
import dio.security.crypto.toPem
import dio.security.ui.AttestationSection
import dio.security.ui.KeyAndAlgorithmDropdowns
import dio.security.ui.SigningSection
import dio.security.ui.VerificationButtons
import dio.security.ui.theme.SecurityTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.Security

class MainActivity : ComponentActivity() {

	/**
	 * Text to be signed and verified.
	 *
	 * This text is used to test the signing and verification process.
	 */
	private val textPlaceholder = "Random text to test the app"

	private val digestSizes = DigestSize.all

	private val algorithms = Algorithm.all

	private val keyManager = KeyManager(this)

	private val appSignaturesSha256 by lazy {
		val certs = packageManager.getPackageInfo(packageName, GET_SIGNING_CERTIFICATES)
			.signingInfo
			?.signingCertificateHistory

		certs
			?.map { signature ->
				val digest = MessageDigest.getInstance("SHA-256")
				val sha256 = digest.digest(signature.toByteArray())
				sha256.joinToString(":") { b -> "%02X".format(b) }
			}
			?.toSet()
			?: emptySet()
	}

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		enableEdgeToEdge()

		getCheckAvailableKeystoreProviders()

		setContent {
			SecurityTheme {
				Scaffold(
					modifier = Modifier.fillMaxSize()
				) { innerPadding ->
					Box(
						modifier = Modifier
							.padding(innerPadding)
					) {
						Column(
							modifier = Modifier.padding(16.dp)
						) {
							Text(
								text = "StrongBox available in device: ${keyManager.hasStrongBox}",
								modifier = Modifier.padding(bottom = 8.dp),
							)

							// User input
							var clearText by remember { mutableStateOf(textPlaceholder) }
							var userSelectedAlgorithm by remember { mutableStateOf(algorithms.first()) }
							var userSelectedDigestSize by remember { mutableStateOf(digestSizes.first()) }

							// Generated values
							val cryptoConfiguration by produceState<CryptoConfiguration?>(
								null,
								userSelectedAlgorithm,
								userSelectedDigestSize
							) {
								withContext(Dispatchers.IO) {
									val selectedAlgorithm =
										SelectedAlgorithm(userSelectedAlgorithm, userSelectedDigestSize)
									val keyPair = keyManager.generateAsymmetricCert(selectedAlgorithm)

									value = CryptoConfiguration(selectedAlgorithm, keyPair)
								}
							}

							cryptoConfiguration?.let { (selectedAlgorithm, keyPair) ->
								val hardwareBackedKey = remember(keyPair.private) {
									keyManager.isHardwareBacked(keyPair.private)
								}
								val publicSignature = remember(keyPair.public) { keyPair.public.toPem() }
								// RSA & ECDSA digests can be online tested with https://emn178.github.io/online-tools/ecdsa/verify/
								val signed = remember(selectedAlgorithm, keyPair.private, clearText) {
									sign(selectedAlgorithm, keyPair.private, clearText.toByteArray())
								}
								val digestText = remember(signed) { signed.toBase64() }
								// JWT can be online tested with https://jwt.io/#debugger-io
								val jwt = remember(selectedAlgorithm, keyPair.private, clearText) {
									Jwt.create(selectedAlgorithm, keyPair.private, clearText)
								}
								val verified = remember(selectedAlgorithm, keyPair.public, signed) {
									verify(
										algorithm = selectedAlgorithm,
										publicKey = keyPair.public,
										signedData = signed,
										dataToVerify = clearText.toByteArray()
									)
								}

								// Attestation
								val challengeText = remember(keyPair) {
									selectedAlgorithm.attestationChallenge.toBase64()
								}
								// Attestation can be online tested with https://certlogik.com/decoder/
								val attestationPemChain = remember(keyPair) { keyManager.getAttestationChainPem() }
								val attestationDetails = remember(keyPair) { keyManager.getAttestationDetails() }

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

									SigningSection(
										clearText = clearText,
										publicSignature = publicSignature,
										digestText = digestText,
										jwt = jwt,
										verified = verified
									)

									VerificationButtons()

									HorizontalDivider()

									AttestationSection(
										challengeText = challengeText,
										attestationPemChain = attestationPemChain,
										attestationDetails = attestationDetails,
										appSignaturesSha256 = appSignaturesSha256
									)
								}
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
}
