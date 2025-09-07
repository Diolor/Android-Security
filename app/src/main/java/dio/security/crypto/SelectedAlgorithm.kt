package dio.security.crypto

import dio.security.crypto.Algorithm.*
import dio.security.crypto.DigestSize.DigestSize256
import dio.security.crypto.DigestSize.DigestSize384
import dio.security.crypto.DigestSize.DigestSize512
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

/**
 * Selected algorithm and digest size for signing and verification.
 */
data class SelectedAlgorithm(
	val algorithm: Algorithm,
	val digestSize: DigestSize
) {

	/**
	 * Randomly generated attestation challenge to be used when generating the key pair.
	 *
	 * Normally the challenge should come from the server to ensure the attestation is for this specific request.
	 * Here we generate a random one for demonstration purposes.
	 */
	val attestationChallenge = ByteArray(32).also { SecureRandom().nextBytes(it) }

	/**
	 * Returns the [java.security.Signature] representation of the selected algorithm and digest size.
	 * Example: SHA256withRSA
	 */
	fun getJavaSignatureName() = "SHA${digestSize.name}with${algorithm.name}"

	/**
	 * Returns the JWT signature representation of the selected algorithm and digest size.
	 */
	fun getJwtName() = "${algorithm.jwtFamilyPrefix}${digestSize.name}"

	/**
	 * Returns the appropriate [java.security.spec.AlgorithmParameterSpec] for the selected algorithm and digest size.
	 */
	fun getAlgorithmParameterSpec(): AlgorithmParameterSpec {
		return when (algorithm) {
			ECDSA -> ECGenParameterSpec(
				when (digestSize) {
					DigestSize256 -> "secp256r1"
					DigestSize384 -> "secp384r1"
					DigestSize512 -> "secp521r1"
				}
			)

			RSA,
			RSAPSS -> RSAKeyGenParameterSpec(
				when (digestSize) {
					DigestSize256 -> 2048
					DigestSize384 -> 3072
					DigestSize512 -> 4096
				},
				RSAKeyGenParameterSpec.F4
			)
		}
	}

	/**
	 * Returns extra information about the selected curve or digest size.
	 */
	fun extraInformation(): String {
		return when (val spec = getAlgorithmParameterSpec()) {
			is ECGenParameterSpec -> spec.name.let { "Curve: $it" }
			is RSAKeyGenParameterSpec -> spec.keysize.let { "Key size: $it" }
			else -> ""
		}
	}
}