package de.init.seal_service.visual;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;

import javax.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class SealEncodingStreamTest {

	@Inject
	SealEncoder sealEncoder;

	@Test
	public void testEncodes() {
		final var encodingStream = new SealEncodingStream();

		// ##########
		// # Header #
		// ##########
		encodingStream.encodeByte((char) 0xDC); // Magic Constant
		encodingStream.encodeByte((char) 0x03); // Version
		encodingStream.encodeC40("D<<"); // Issuing Country
		encodingStream.encodeC40("DEZB03001"); // Combined:
		// Signer Identifier == Cert Subject Distinguished Name (CN)
		// Cert Reference == Cert Serial Number
		encodingStream.encodeDate(LocalDate.now()); // Document Issue Date
		encodingStream.encodeDate(LocalDate.now()); // Signature Creation Date
		encodingStream.encodeByte((char) 0x01); // Document Feature Definition Reference
		encodingStream.encodeByte((char) 200); // Document Type Category

		// ################
		// # Message Zone #
		// ################
		encodingStream.encodeMessageC40((char) 0x00, "ZAB001");

		encodingStream.encodeMessageC40((char) 0x04, "2023/17856");
		encodingStream.encodeMessageString((char) 0x05, "Musterfrau");
		encodingStream.encodeMessageString((char) 0x06, "Erika");
		encodingStream.encodeMessageDate((char) 0x07, LocalDate.parse("1995-01-01"));
		encodingStream.encodeMessageString((char) 0x08, "bakalavr miznarodnych vidnosyn");
		encodingStream.encodeMessageString((char) 0x09,
				"Die Bewertung entspricht einem deutschen Hochschulabschluss Bachelor-Ebene.");
		// More extreme test attributes with binary and UTF-8
		final var bs = new byte[256];
		for (var i = 0; i <= 255; ++i) {
			bs[i] = (byte) i;
		}
		encodingStream.encodeMessageBytes((char) 0x0a, bs);
		encodingStream.encodeMessageString((char) 0x0b, "Test: ÄÖÜäöüß'´`@^°¹³²þ T\nTEST");

		// ##################
		// # Signature Zone #
		// ##################
		// ECDSA 256 Bit: Plain (r,s)-Encoding with 64 Bytes (2 * 256 Bit),
		// no ASN.1/DER encoding with 70 Byte!
		final var signature = this.sealEncoder.sign(encodingStream.toString().getBytes(StandardCharsets.ISO_8859_1));
		encodingStream.encodeMessageSignature(signature);

		final var seal = encodingStream.toString();

		Assertions.assertEquals(64, signature.length);
		Assertions.assertEquals(538, seal.getBytes(StandardCharsets.ISO_8859_1).length);
	}

}