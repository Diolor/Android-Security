package dio.security.crypto

import android.util.Base64
import java.security.PublicKey

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