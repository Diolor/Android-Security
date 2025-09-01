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

	// FIXME: 512 crashes
	private fun derToRawEcdsa(derSig: ByteArray, rawLen: Int): ByteArray {
		var offset = 3                                     // skip 0x30, totalLen, 0x02
		val rLen = derSig[offset].toInt() and 0xFF        // length of r
		offset++
		val r = derSig.copyOfRange(offset, offset + rLen) // read r
		offset += rLen                                    // move to 0x02
		offset++                                          // skip 0x02 tag
		val sLen = derSig[offset].toInt() and 0xFF        // length of s
		offset++
		val s = derSig.copyOfRange(offset, offset + sLen) // read s

		// allocate fixed‑length buffers for r and s
		val rRaw = ByteArray(rawLen)
		val sRaw = ByteArray(rawLen)
		// copy r and s into the rightmost portion of the buffers
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