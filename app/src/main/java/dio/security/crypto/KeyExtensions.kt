package dio.security.crypto

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
import android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import java.security.KeyFactory
import java.security.PrivateKey

private fun PrivateKey.getKeyInfo(provider: String): KeyInfo {
	val factory = KeyFactory.getInstance(algorithm, provider)
	return factory.getKeySpec(this, KeyInfo::class.java)
}

/**
 * Check if the PrivateKey is hardware backed
 *
 * @param provider The security provider, e.g., "AndroidKeyStore"
 * @return True if the key is hardware backed, false otherwise
 */
fun PrivateKey.isHardwareBacked(provider: String): Boolean {
	val keyInfo = getKeyInfo(provider)

	return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
		keyInfo.securityLevel in setOf(
			SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
			SECURITY_LEVEL_STRONGBOX
		)
	} else {
		@Suppress("DEPRECATION")
		keyInfo.isInsideSecureHardware
	}
}