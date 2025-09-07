package dio.security.crypto

import android.security.keystore.KeyProperties.KEY_ALGORITHM_EC
import android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA

/**
 * Supported algorithms for signing
 */
sealed class Algorithm(
	val name: String,
	/**
	 * Based on rfc7518
	 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3
	 */
	val jwtFamilyPrefix: String,
	/**
	 * Compliant with Java Security Standard Algorithm Names Specification.
	 */
	val javaStandardName: String
) : DropdownOption {
	override fun displayName() = name

	object ECDSA : Algorithm("ECDSA", "ES", KEY_ALGORITHM_EC)
	object RSA : Algorithm("RSA", "RS", KEY_ALGORITHM_RSA)
	object RSAPSS : Algorithm("RSA/PSS", "PS", KEY_ALGORITHM_RSA)

	companion object {
		val all = listOf(ECDSA, RSA, RSAPSS)
	}
}