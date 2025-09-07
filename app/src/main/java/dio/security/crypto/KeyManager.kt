package dio.security.crypto

import android.content.Context
import android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.DIGEST_SHA256
import android.security.keystore.KeyProperties.DIGEST_SHA384
import android.security.keystore.KeyProperties.DIGEST_SHA512
import android.security.keystore.KeyProperties.PURPOSE_SIGN
import android.security.keystore.KeyProperties.PURPOSE_VERIFY
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
import android.security.keystore.KeyProperties.SIGNATURE_PADDING_RSA_PSS
import dio.security.crypto.attestation.AttestationDetails
import dio.security.crypto.attestation.convert
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.cert.X509Certificate

/**
 * Manages the creation and retrieval of cryptographic keys and their associated certificates
 * using the Android Keystore system.
 */
class KeyManager(context: Context) {

	private val keystore = KeyStore.getInstance("AndroidKeyStore").apply {
		load(null)
	}

	/**
	 * Name of the key to be used in the Android Keystore.
	 */
	private val keyName = "test_key"

	/**
	 * Check if the device has StrongBox support.
	 */
	val hasStrongBox: Boolean by lazy {
		context.packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)
	}

	private fun createKeyGenSpecs(
		selectedAlgorithm: SelectedAlgorithm,
		devicePropertiesAttestationIncluded: Boolean,
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
		.setAttestationChallenge(selectedAlgorithm.attestationChallenge)
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
		devicePropertiesAttestationIncluded: Boolean
	): KeyPair {
		val specs = createKeyGenSpecs(selectedAlgorithm, devicePropertiesAttestationIncluded)

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

	/**
	 * Generates a new asymmetric key pair and its associated certificate in the Android Keystore.
	 * If a key with the same name already exists, it will be deleted and replaced.
	 */
	fun generateAsymmetricCert(
		selectedAlgorithm: SelectedAlgorithm
	): KeyPair {
		val keyEntry = keystore.isKeyEntry(keyName)
		if (keyEntry) {
			keystore.deleteEntry(keyName)
		}

		return try {
			generateKeyPairCert(selectedAlgorithm, devicePropertiesAttestationIncluded = true)
		} catch (_: ProviderException) {
			println("Failed to attest device properties, retrying without it.")
			generateKeyPairCert(selectedAlgorithm, devicePropertiesAttestationIncluded = false)
		}
	}

	/**
	 * Retrieves the attestation certificate chain associated with the key in PEM format.
	 */
	fun getAttestationChainPem(): List<String> {
		return keystore.getCertificateChain(keyName)
			.map { it.toPem() }
	}

	/**
	 * Retrieves the attestation details from the certificate chain.
	 */
	fun getAttestationDetails(): AttestationDetails {
		return keystore.getCertificateChain(keyName)
			.filterIsInstance<X509Certificate>()
			.firstNotNullOf { it.convert() }
	}

	/**
	 * Retrieves the private key associated with the key in the Android Keystore.
	 */
	fun isHardwareBacked(privateKey: PrivateKey): Boolean {
		return privateKey.isHardwareBacked(keystore.provider.name)
	}
}