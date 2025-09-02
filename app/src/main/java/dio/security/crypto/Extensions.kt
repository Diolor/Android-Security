package dio.security.crypto

import android.util.Base64.NO_PADDING
import android.util.Base64.NO_WRAP
import android.util.Base64.URL_SAFE
import android.util.Base64.encodeToString
import java.security.PublicKey

/**
 * Convert ByteArray to Base64
 */
fun ByteArray.toBase64(noPadding: Boolean = false, urlSafe: Boolean = false): String {
	var flags = NO_WRAP
	if (noPadding) {
		flags = flags or NO_PADDING
	}
	if (urlSafe) {
		flags = flags or URL_SAFE
	}
	return encodeToString(this, flags)
}

/**
 * Convert ByteArray to Base64 for JWT based on RFC 7515/7519
 */
fun ByteArray.toBase64JWTSpecs(): String {
	return toBase64(noPadding = true, urlSafe = true)
}

/**
 * Convert PublicKey to PEM format
 */
fun PublicKey.toPublicSignature(): String {
	val signature = encodeToString(encoded, NO_WRAP)
	return "-----BEGIN PUBLIC KEY-----\n$signature\n-----END PUBLIC KEY-----"
}