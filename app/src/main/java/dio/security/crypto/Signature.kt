package dio.security.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * Utility object for signing and verifying data using digital signatures.
 */
object Signature {

	/**
	 * Sign data using the provided algorithm and private key.
	 */
	fun sign(
		algorithm: String,
		privateKey: PrivateKey,
		dataToSign: ByteArray
	): ByteArray {
		return Signature.getInstance(algorithm)
			.apply {
				initSign(privateKey)
				update(dataToSign)
			}
			.sign()
	}

	/**
	 * Verify signed data using the provided algorithm and public key.
	 */
	fun verify(
		algorithm: String,
		publicKey: PublicKey,
		signedData: ByteArray,
		dataToVerify: ByteArray
	): Boolean {
		return Signature.getInstance(algorithm)
			.apply {
				initVerify(publicKey)
				update(dataToVerify)
			}
			.verify(signedData)
	}
}