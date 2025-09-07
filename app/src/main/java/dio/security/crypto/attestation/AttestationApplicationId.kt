package dio.security.crypto.attestation

data class AttestationApplicationId(
	val packageInfos: List<AttestationPackageInfo>,
	val signatureDigests: Set<String>
) {
	override fun toString(): String {
		return "\n\t\t\tpackages: ${packageInfos.joinToString(", ")}" +
				"\n\t\t\tsignatureDigests: ${signatureDigests.joinToString(", ", prefix = "\n\t\t\t\t")}"
	}
}