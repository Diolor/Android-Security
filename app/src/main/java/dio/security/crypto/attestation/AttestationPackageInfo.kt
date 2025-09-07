package dio.security.crypto.attestation

data class AttestationPackageInfo(
	val packageName: String,
	val version: Long // ASN.1 INTEGER can be large, so Long is safer
) {
	override fun toString(): String {
		return "\n\t\t\t\t\t$packageName (v$version)"
	}
}