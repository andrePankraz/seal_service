/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.init.seal_service.pdf.pdfbox_signature.validation;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import de.init.seal_service.pdf.pdfbox_signature.validation.CertInformationCollector.CertSignatureInformation;

public class CertInformationHelper {
	private static final Log LOG = LogFactory.getLog(CertInformationHelper.class);

	private static String extractCrlUrlFromSequence(final ASN1Sequence sequence) {
		var taggedObject = (ASN1TaggedObject) sequence.getObjectAt(0);
		taggedObject = (ASN1TaggedObject) taggedObject.getBaseObject();
		if (taggedObject.getBaseObject() instanceof ASN1TaggedObject) {
			taggedObject = (ASN1TaggedObject) taggedObject.getBaseObject();
		} else if (taggedObject.getBaseObject() instanceof ASN1Sequence) {
			// multiple URLs (we take the first)
			final var seq = (ASN1Sequence) taggedObject.getBaseObject();
			if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
				return null;
			}
			taggedObject = (ASN1TaggedObject) seq.getObjectAt(0);
		} else {
			return null;
		}
		if (taggedObject.getBaseObject() instanceof ASN1OctetString) {
			final var uri = (ASN1OctetString) taggedObject.getBaseObject();
			final var url = new String(uri.getOctets());

			// return first http(s)-Url for crl
			if (url.startsWith("http")) {
				return url;
			}
		}
		// else happens with http://blogs.adobe.com/security/SampleSignedPDFDocument.pdf
		return null;
	}

	/**
	 * Extracts authority information access extension values from the given data.
	 * The Data structure has to be implemented as described in RFC 2459, 4.2.2.1.
	 *
	 * @param extensionValue byte[] of the extension value.
	 * @param certInfo       where to put the found values
	 * @throws IOException when there is a problem with the extensionValue
	 */
	protected static void getAuthorityInfoExtensionValue(final byte[] extensionValue,
			final CertSignatureInformation certInfo) throws IOException {
		final var asn1Seq = (ASN1Sequence) JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
		final Enumeration<?> objects = asn1Seq.getObjects();
		while (objects.hasMoreElements()) {
			// AccessDescription
			final var obj = (ASN1Sequence) objects.nextElement();
			final var oid = obj.getObjectAt(0);
			// accessLocation
			final var location = (ASN1TaggedObject) obj.getObjectAt(1);

			if (X509ObjectIdentifiers.id_ad_ocsp.equals(oid)
					&& location.getTagNo() == GeneralName.uniformResourceIdentifier) {
				final var url = (ASN1OctetString) location.getBaseObject();
				certInfo.setOcspUrl(new String(url.getOctets()));
			} else if (X509ObjectIdentifiers.id_ad_caIssuers.equals(oid)) {
				final var uri = (ASN1OctetString) location.getBaseObject();
				certInfo.setIssuerUrl(new String(uri.getOctets()));
			}
		}
	}

	/**
	 * Gets the first CRL URL from given extension value. Structure has to be built
	 * as in 4.2.1.14 CRL Distribution Points of RFC 2459.
	 *
	 * @param extensionValue to get the extension value from
	 * @return first CRL- URL or null
	 * @throws IOException when there is a problem with the extensionValue
	 */
	protected static String getCrlUrlFromExtensionValue(final byte[] extensionValue) throws IOException {
		final var asn1Seq = (ASN1Sequence) JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
		final Enumeration<?> objects = asn1Seq.getObjects();

		while (objects.hasMoreElements()) {
			final Object obj = objects.nextElement();
			if (obj instanceof ASN1Sequence) {
				final var url = extractCrlUrlFromSequence((ASN1Sequence) obj);
				if (url != null) {
					return url;
				}
			}
		}
		return null;
	}

	/**
	 * Gets the SHA-1-Hash has of given byte[]-content.
	 * 
	 * @param content to be hashed
	 * @return SHA-1 hash String
	 */
	protected static String getSha1Hash(final byte[] content) {
		try {
			final var md = MessageDigest.getInstance("SHA-1");
			return Hex.getString(md.digest(content));
		} catch (final NoSuchAlgorithmException e) {
			LOG.error("No SHA-1 Algorithm found", e);
		}
		return null;
	}

	private CertInformationHelper() {
	}
}