package dio.security.crypto

import android.security.keystore.KeyProperties.KEY_ALGORITHM_EC
import android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA

/**
 * Supported algorithms for signing
 */
sealed class Algorithm(val name: String, val jwtFamily: String, val javaFamily: String) :
		DropdownOption {
	override fun displayName() = name

	object ECDSA : Algorithm("ECDSA", "ES", KEY_ALGORITHM_EC)
	object RSA : Algorithm("RSA", "RS", KEY_ALGORITHM_RSA)
	object RSAPSS : Algorithm("RSA/PSS", "PS", KEY_ALGORITHM_RSA)

	companion object {
		val all = listOf(ECDSA, RSA, RSAPSS)
	}
}