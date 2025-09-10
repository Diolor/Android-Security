package dio.security.crypto.attestation


data class RootOfTrust(
	val verifiedBootKey: String, // base64
	val deviceLocked: Boolean,
	val verifiedBootState: String,
	val verifiedBootHash: String // base64
)