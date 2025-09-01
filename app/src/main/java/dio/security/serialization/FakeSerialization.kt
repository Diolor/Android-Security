package dio.security.serialization

import dio.security.crypto.toBase64

// TODO: Use a proper serialization library
fun header(algorithm: String): String {
	return """{"alg": "$algorithm","typ": "JWT"}""".encodeToByteArray().toBase64()
}

fun payload(text: String): String {
	return """{"data": "$text"}""".encodeToByteArray().toBase64()
}