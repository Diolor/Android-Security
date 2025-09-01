package dio.security.crypto

/**
 * Supported digest sizes for algorithms
 */
sealed class DigestSize(val name: String) : DropdownOption {

	override fun displayName() = name

	object DigestSize256 : DigestSize("256")
	object DigestSize384 : DigestSize("384")
	object DigestSize512 : DigestSize("512")

	companion object Companion {
		val all = listOf(DigestSize256, DigestSize384, DigestSize512)
	}
}