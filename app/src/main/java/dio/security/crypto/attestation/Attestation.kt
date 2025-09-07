package dio.security.crypto.attestation

import android.util.Base64
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSet
import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.X509Certificate

private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
private val INTEGERS =
	setOf(2, 3, 8, 10, 200, 400, 401, 402, 405, 502, 504, 505, 701, 702, 705, 706, 718, 719)
private val SET_OF_INTEGERS = setOf(1, 4, 5, 6, 203)
private val NULLABLES = setOf(7, 303, 305, 503, 506, 507, 508, 509, 720)
private val OCTET_STRINGS = setOf(
	710, 711, 712, 713, 714, 715, 716, 717, 723, 724
)
private const val APPLICATION_ID = 709

private fun ASN1OctetString.toUtf8String(): String = String(octets, UTF_8)

private fun ASN1OctetString.toBase64(): String = Base64.encodeToString(octets, Base64.NO_WRAP)

/**
 *  Minimal “structure sanity check”
 */
fun X509Certificate.convert(): AttestationDetails? {
	return readAttestationExtension()?.let { der ->
		ASN1InputStream(der).use { ain ->
			val seq = ain.readObject() as ASN1Sequence
			return AttestationDetails(
				attestationVersion = seq.getObjectAt(0).toString().toInt(),
				attestationSecurityLevel = (seq.getObjectAt(1) as ASN1Enumerated).value.toString(),
				keymasterVersion = seq.getObjectAt(2).toString().toInt(),
				keymasterSecurityLevel = (seq.getObjectAt(3) as ASN1Enumerated).value.toString(),
				attestationChallenge = Base64.encodeToString(
					(seq.getObjectAt(4) as DEROctetString).octets,
					Base64.NO_WRAP
				),
				uniqueId = Base64.encodeToString(
					(seq.getObjectAt(5) as DEROctetString).octets,
					Base64.NO_WRAP
				),
				softwareEnforced = (seq.getObjectAt(6) as ASN1Sequence).decode(),
				hardwareEnforced = (seq.getObjectAt(7) as ASN1Sequence).decode(),
			)
		}
	}
}

private fun X509Certificate.readAttestationExtension(): ByteArray? {
	val ext = getExtensionValue(ATTESTATION_OID) ?: return null
	// X.509 stores extension values wrapped in an OCTET STRING. Strip it:
	val asn1 = ASN1InputStream(ext)
	val octet = asn1.readObject() as ASN1OctetString
	return octet.octets // this is the DER of the KeyDescription structure
}

private fun ASN1Sequence.decode(): Map<Int, Any> {
	val map = mutableMapOf<Int, Any>()

	objects.toList()
		.filterIsInstance<ASN1TaggedObject>()
		.sortedBy { it.tagNo }
		.forEach { element ->
			when (element.tagNo) {
				in INTEGERS -> map[element.tagNo] = element.baseObject as ASN1Integer
				in OCTET_STRINGS -> map[element.tagNo] =
					(element.baseObject as ASN1OctetString).toUtf8String()

				in SET_OF_INTEGERS -> map[element.tagNo] = (element.baseObject as DLSet)
					.objects
					.toList()
					.map { it as ASN1Integer }
					.toSet()

				in NULLABLES -> map[element.tagNo] = element.baseObject?.toString() ?: "NULL"
				APPLICATION_ID -> map[element.tagNo] =
					(element.baseObject as ASN1OctetString).octets.extractAttestationApplicationId()
			}
		}

	return map.toMap()
}

private fun ByteArray.extractAttestationApplicationId(): AttestationApplicationId {
	// The baseObject is an ASN1OctetString which contains a DER-encoded ASN.1 sequence
	// See https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema
	return ASN1InputStream(this).use { appIdStream ->
		val appIdSequence = (appIdStream.readObject() as ASN1Sequence).objects.toList()
		println(appIdSequence)

		val packageInfos = (appIdSequence[0] as DLSet).objects
			.toList()
			.filterIsInstance<ASN1Sequence>()
			.map { packageInfoEntry ->
				println(packageInfoEntry)
				val packageNameOctets = packageInfoEntry.getObjectAt(0) as DEROctetString
				val versionInteger = packageInfoEntry.getObjectAt(1) as ASN1Integer
				AttestationPackageInfo(
					packageName = packageNameOctets.toUtf8String(),
					version = versionInteger.value.toLong()
				)
			}

		val signatureDigests = (appIdSequence[1] as DLSet)
			.objects
			.toList()
			.filterIsInstance<ASN1OctetString>()
			.map { it.toBase64() }
			.toSet()

		AttestationApplicationId(packageInfos, signatureDigests)
	}
}

