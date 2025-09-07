package dio.security.crypto.attestation

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