package dio.security.serialization

import dio.security.crypto.toBase64JWTSpecs

// TODO: Use a proper serialization library
fun header(algorithm: String): String {
	return """{"alg": "$algorithm","typ": "JWT"}"""
		.encodeToByteArray()
		.toBase64JWTSpecs()
}

fun payload(text: String): String {
	return """{"data": "$text"}"""
		.encodeToByteArray()
		.toBase64JWTSpecs()
}