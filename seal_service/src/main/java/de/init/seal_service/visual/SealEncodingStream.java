/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.visual;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;

/**
 * This class encodes attributes into a combined seal string. It follows the
 * standard <a href=
 * "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03171/TR-03171_node.html">BSI
 * TR-03171</a>.
 */
public class SealEncodingStream {

	private final StringBuilder sb = new StringBuilder();

	public void encodeByte(final int b) {
		this.sb.append((char) (b & 0xff));
	}

	public void encodeBytes(final byte... bs) {
		final var cs = new char[bs.length];
		for (var i = 0; i < bs.length; ++i) {
			cs[i] = (char) (bs[i] & 0xff);
		}
		encodeBytes(cs);
	}

	public void encodeBytes(final char... cs) {
		this.sb.append(cs);
	}

	public void encodeC40(final String str) {
		// See Annex B:
		// https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03137/BSI-TR-03137_Part1.pdf
		// Reduced chars in comparision to original DataMatrix C40 with Shifts
		final var l = str.length();
		for (var i = 0; i < l; i += 3) {
			if (i + 1 >= l) {
				// 1 Char remaining
				// If one C40 value (=one character) remains, then the first byte has the value
				// 254dec (0xfe). The second byte is the value of the ASCII encoding scheme of
				// DataMatrix of the character corresponding to the C40 value. Note that the
				// ASCII encoding scheme in DataMatrix for an ASCII character in the range 0-127
				// is the ASCII character plus 1.
				final int u1 = str.charAt(i);
				final var u = u1 + 1;
				encodeByte(0xfe);
				encodeByte(u); // Don't encodeC40char
			} else if (i + 2 >= l) {
				// 2 Chars remaining
				// If two C40 (=two characters) values remain at the end of a string, these two
				// C40 values are completed into a triple with the C40 value 0 (Shift 1). The
				// triple is encoded as defined above.
				final int u1 = str.charAt(i);
				final int u2 = str.charAt(i + 1);
				final var u = 1600 * encodeC40char(u1) + 40 * encodeC40char(u2) + 1;
				encodeByte(u / 256);
				encodeByte(u % 256);
			} else {
				// 3 Chars remaining - Full Triplet
				final int u1 = str.charAt(i);
				final int u2 = str.charAt(i + 1);
				final int u3 = str.charAt(i + 2);
				final var u = 1600 * encodeC40char(u1) + 40 * encodeC40char(u2) + encodeC40char(u3) + 1;
				encodeByte(u / 256);
				encodeByte(u % 256);
			}
		}
	}

	private int encodeC40char(final int c) {
		if (c >= '0' && c <= '9') {
			return c - '0' + 4;
		}
		if (c >= 'A' && c <= 'Z') {
			return c - 'A' + 14;
		}
		// assert c == ' ' || c == '<' : "Char " + c + " not allowed!";
		return 3; // Encode as space
	}

	public void encodeDate(final int day, final int month, final int year) {
		// A date is first converted into a positive integer by concatenating the month,
		// the days, and the (four digit) year.
		// This positive integer is then concatenated into a sequence of three bytes.
		final var date = month * 1000000 + day * 10000 + year;
		this.sb.append((char) (date >> 16 & 0xff));
		this.sb.append((char) (date >> 8 & 0xff));
		this.sb.append((char) (date & 0xFF));
	}

	public void encodeDate(final LocalDate localDate) {
		encodeDate(localDate.getDayOfMonth(), localDate.getMonthValue(), localDate.getYear());
	}

	public void encodeMessageBytes(final char tag, final byte... bs) {
		encodeByte(tag);
		encodeMessageLength(bs.length);
		encodeBytes(bs);
	}

	public void encodeMessageC40(final char tag, final String str) {
		encodeByte(tag);
		encodeMessageLength((int) Math.ceil(str.length() / 3f) * 2);
		encodeC40(str);
	}

	public void encodeMessageDate(final char tag, final int day, final int month, final int year) {
		encodeByte(tag);
		encodeMessageLength(3);
		encodeDate(day, month, year);
	}

	public void encodeMessageDate(final char tag, final LocalDate localDate) {
		encodeMessageDate(tag, localDate.getDayOfMonth(), localDate.getMonthValue(), localDate.getYear());
	}

	public void encodeMessageLength(final int l) {
		// https://docs.yubico.com/yesdk/users-manual/support/support-tlv.html#length
		if (l <= 0x7f) {
			encodeByte(l);
		} else if (l >= 0x80 && l <= 0xff) {
			encodeByte(0x81);
			encodeByte(l);
		} else if (l >= 0x0100 && l <= 0xffff) {
			encodeByte(0x82);
			encodeByte(l >> 8);
			encodeByte(l & 0xff);
		} else if (l >= 0x010000 && l <= 0xffffff) {
			encodeByte(0x83);
			encodeByte(l >> 16);
			encodeByte(l >> 8 & 0xff);
			encodeByte(l & 0xff);
		} else {
			assert false : "Length " + l + " not allowed!";
		}
	}

	public void encodeMessageSignature(final byte[] signature) {
		encodeByte(0xff);
		encodeMessageLength(signature.length);
		encodeBytes(signature);
	}

	public void encodeMessageString(final char tag, final String str) {
		encodeMessageBytes(tag, str.getBytes(StandardCharsets.UTF_8));
	}

	public void encodeString(final String str) {
		encodeBytes(str.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public String toString() {
		return this.sb.toString();
	}

}