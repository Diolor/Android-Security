package dio.security.crypto

import android.util.Base64
import java.security.PublicKey

/**
 * Convert algorithm and digest size to Java Signature format
 * Example: SHA256withRSA
 */
fun algorithmToJavaSignature(digestSize: DigestSize, algorithm: Algorithm): String {
	return "SHA${digestSize.name}with${algorithm.name}"
}

/**
 * Based on rfc7518
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3
 */
fun algorithmToJwtSignature(digestSize: DigestSize, algorithm: Algorithm): String {
	return "${algorithm.jwtFamily}${digestSize.name}"
}

/**
 * Convert ByteArray to Base64 URL Safe without padding
 */
fun ByteArray.toBase64(): String {
	return Base64.encodeToString(this, Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE)
}

/**
 * Convert PublicKey to PEM format
 */
fun PublicKey.toPublicSignature(): String {
	val signature = Base64.encodeToString(encoded, Base64.NO_PADDING or Base64.NO_WRAP)
	return "-----BEGIN PUBLIC KEY-----\n$signature\n-----END PUBLIC KEY-----"
}