package dio.security.crypto

import android.util.Log
import dio.security.serialization.header
import dio.security.serialization.payload
import java.security.PrivateKey

/**
 * Utility object for creating JSON Web Tokens (JWT).
 */
object Jwt {

	/**
	 * Create a JWT (JSON Web Token) using the specified algorithm, digest size, private key, and text to sign.
	 */
	fun create(
		javaAlgorithm: String,
		digestSize: DigestSize,
		algorithm: Algorithm,
		privateKey: PrivateKey,
		textToSign: String
	): String {
		val headerEncoded = header(algorithmToJwtSignature(digestSize, algorithm))
		val payloadEncoded = payload(textToSign)

		val jwsArray = Signature.sign(
			algorithm = javaAlgorithm,
			privateKey = privateKey,
			dataToSign = "$headerEncoded.$payloadEncoded".encodeToByteArray()
		)

		val jws = if (algorithm == Algorithm.ECDSA) {
			val rawLen = when (digestSize) {
				DigestSize.DigestSize256 -> 32
				DigestSize.DigestSize384 -> 48
				DigestSize.DigestSize512 -> 66 // P‑521 produces 521‑bit keys, which need 66 bytes
			}
			derToRawEcdsa(jwsArray, rawLen).toBase64()
		} else {
			jwsArray.toBase64()
		}

		return "$headerEncoded.$payloadEncoded.$jws".also {
			Log.d("JWT", "https://jwt.io/#debugger-io?token=$it")
		}
	}

	/**
	 * Convert the algorithm and digest size to the corresponding JWT signature string.
	 *
	 * TODO: Works but maybe use a library for this.
	 */
	private fun derToRawEcdsa(derSig: ByteArray, rawLen: Int): ByteArray {
		var offset = 0

		// Expect 0x30 for SEQUENCE tag
		require(derSig[offset] == 0x30.toByte()) { "Not a DER ECDSA signature" }
		offset++

		// Read and skip the DER length field (handles short and long forms)
		val lengthByte = derSig[offset].toInt() and 0xFF
		offset++
		if (lengthByte and 0x80 != 0) {
			// Long form: low 7 bits give the number of length bytes
			val numLenBytes = lengthByte and 0x7F
			offset += numLenBytes
		}

		// Read the r component
		require(derSig[offset] == 0x02.toByte()) { "Expected INTEGER tag for r" }
		offset++
		val rLen = derSig[offset].toInt() and 0xFF
		offset++
		val r = derSig.copyOfRange(offset, offset + rLen)
		offset += rLen

		// Read the s component
		require(derSig[offset] == 0x02.toByte()) { "Expected INTEGER tag for s" }
		offset++
		val sLen = derSig[offset].toInt() and 0xFF
		offset++
		val s = derSig.copyOfRange(offset, offset + sLen)

		// Pad r and s on the left to rawLen and concatenate
		val rRaw = ByteArray(rawLen)
		val sRaw = ByteArray(rawLen)
		System.arraycopy(
			r,
			maxOf(0, r.size - rawLen),
			rRaw,
			maxOf(0, rawLen - r.size),
			minOf(r.size, rawLen)
		)
		System.arraycopy(
			s,
			maxOf(0, s.size - rawLen),
			sRaw,
			maxOf(0, rawLen - s.size),
			minOf(s.size, rawLen)
		)

		return rRaw + sRaw
	}
}