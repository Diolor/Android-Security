package dio.security.crypto.attestation

import android.util.Base64

/**
 * See https://source.android.com/docs/security/features/keystore/attestation#schema
 */
data class AttestationDetails(
	val attestationVersion: Int,
	val attestationSecurityLevel: String,
	val keymasterVersion: Int,
	val keymasterSecurityLevel: String,
	val attestationChallenge: String,
	val uniqueId: String,
	val softwareEnforced: Map<Int, Any>,
	val hardwareEnforced: Map<Int, Any>
) {

	private fun Map<Int, Any>.getAppSigningCertificates(): List<String> {
		return values
			.filterIsInstance<AttestationApplicationId>()
			.map {
				it.signatureDigests.map { signatureDigest ->
					val bytes = Base64.decode(signatureDigest, Base64.NO_WRAP)
					bytes.joinToString(":") { "%02X".format(it) }
				}
			}
			.flatten()
	}

	private fun Map<Int, Any>.getRootOfTrust(): List<RootOfTrust> {
		return values.filterIsInstance<RootOfTrust>()
	}

	/**
	 * Returns a list of SHA256 digests of the app's signing certificate(s) in hex format.
	 */
	fun getAppSigningCertificates() =
		mergeDistinct(softwareEnforced, hardwareEnforced) { getAppSigningCertificates() }

	fun getRootOfTrust() =
		mergeDistinct(softwareEnforced, hardwareEnforced) { getRootOfTrust() }

	private inline fun <reified T> mergeDistinct(
		software: Map<Int, Any>,
		hardware: Map<Int, Any>,
		crossinline extractor: Map<Int, Any>.() -> List<T>
	): List<T> {
		val softwareValues = software.extractor()
		val hardwareValues = hardware.extractor()
		return (softwareValues + hardwareValues).distinct()
	}

	override fun toString(): String {
		return """
attestationVersion: $attestationVersion
attestationSecurityLevel: $attestationSecurityLevel
keymasterVersion: $keymasterVersion
keymasterSecurityLevel: $keymasterSecurityLevel
attestationChallenge: $attestationChallenge
uniqueId: $uniqueId
softwareEnforced: ${softwareEnforced.entries.joinToString(separator = "\n\t\t")}
hardwareEnforced: ${hardwareEnforced.entries.joinToString(separator = "\n\t\t")}
				""".trimIndent()
	}
}