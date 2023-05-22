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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSUpdateInfo;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import de.init.seal_service.pdf.pdfbox_signature.SigUtils;
import de.init.seal_service.pdf.pdfbox_signature.cert.CRLVerifier;
import de.init.seal_service.pdf.pdfbox_signature.cert.CertificateVerificationException;
import de.init.seal_service.pdf.pdfbox_signature.cert.OcspHelper;
import de.init.seal_service.pdf.pdfbox_signature.cert.RevokedCertificateException;
import de.init.seal_service.pdf.pdfbox_signature.validation.CertInformationCollector.CertSignatureInformation;

/**
 * An example for adding Validation Information to a signed PDF, inspired by
 * ETSI TS 102 778-4 V1.1.2 (2009-12), Part 4: PAdES Long Term - PAdES-LTV
 * Profile. This procedure appends the Validation Information of the last
 * signature (more precise its signer(s)) to a copy of the document. The
 * signature and the signed data will not be touched and stay valid.
 * <p>
 * See also <a href="http://eprints.hsr.ch/id/eprint/616">Bachelor thesis (in
 * German) about LTV</a>
 *
 * @author Alexis Suter
 */
public class AddValidationInformation {
	private static final Log LOG = LogFactory.getLog(AddValidationInformation.class);

	/**
	 * Gets or creates a dictionary entry. If existing checks for the type and sets
	 * need to be updated.
	 *
	 * @param clazz  the class of the dictionary entry, must implement COSUpdateInfo
	 * @param parent where to find the element
	 * @param name   of the element
	 * @return a Element of given class, new or existing
	 * @throws IOException when the type of the element is wrong
	 */
	private static <T extends COSBase & COSUpdateInfo> T getOrCreateDictionaryEntry(final Class<T> clazz,
			final COSDictionary parent, final String name) throws IOException {
		T result;
		final var element = parent.getDictionaryObject(name);
		if (element != null && clazz.isInstance(element)) {
			result = clazz.cast(element);
			result.setNeedToBeUpdated(true);
		} else if (element != null) {
			throw new IOException("Element " + name + " from dictionary is not of type " + clazz.getCanonicalName());
		} else {
			try {
				result = clazz.getDeclaredConstructor().newInstance();
			} catch (ReflectiveOperationException | SecurityException e) {
				throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), e);
			}
			result.setDirect(false);
			parent.setItem(COSName.getPDFName(name), result);
		}
		return result;
	}

	public static void main(final String[] args) throws IOException {
		if (args.length != 1) {
			usage();
			System.exit(1);
		}

		// register BouncyCastle provider, needed for "exotic" algorithms
		Security.addProvider(SecurityProvider.getProvider());

		// add ocspInformation
		final var addOcspInformation = new AddValidationInformation();

		final var inFile = new File(args[0]);
		final var name = inFile.getName();
		final var substring = name.substring(0, name.lastIndexOf('.'));

		final var outFile = new File(inFile.getParent(), substring + "_LTV.pdf");
		addOcspInformation.validateSignature(inFile, outFile);
	}

	private static void usage() {
		System.err.println("usage: java " + AddValidationInformation.class.getName() + " " + "<pdf_to_add_ocsp>\n");
	}

	private CertInformationCollector certInformationHelper;
	private COSArray correspondingOCSPs;
	private COSArray correspondingCRLs;
	private COSDictionary vriBase;
	private COSArray ocsps;
	private COSArray crls;
	private COSArray certs;
	private final Map<X509Certificate, COSStream> certMap = new HashMap<>();
	private PDDocument document;

	private final Set<X509Certificate> foundRevocationInformation = new HashSet<>();

	private Calendar signDate;

	private final Set<X509Certificate> ocspChecked = new HashSet<>();
	// TODO foundRevocationInformation and ocspChecked have a similar purpose. One
	// of them should likely
	// be removed and the code improved. When doing so, keep in mind that
	// ocspChecked was added last,
	// because of a problem with freetsa.

	/**
	 * Adds all certs to the certs-array. Make sure that all certificates are inside
	 * the certificateStore of certInformationHelper. This should be the only call
	 * to fill certs.
	 *
	 * @throws IOException
	 */
	private void addAllCertsToCertArray() throws IOException {
		for (final X509Certificate cert : this.certInformationHelper.getCertificateSet()) {
			if (!this.certMap.containsKey(cert)) {
				try {
					final var certStream = writeDataToStream(cert.getEncoded());
					this.certMap.put(cert, certStream);
				} catch (final CertificateEncodingException ex) {
					throw new IOException(ex);
				}
			}
		}
		this.certMap.values().forEach(certStream -> this.certs.add(certStream));
	}

	/**
	 * Fetches and adds CRL data to storage for the given Certificate.
	 *
	 * @param certInfo the certificate info, for it to check CRL data.
	 * @throws IOException
	 * @throws RevokedCertificateException
	 * @throws GeneralSecurityException
	 * @throws CertificateVerificationException
	 */
	private void addCrlRevocationInfo(final CertSignatureInformation certInfo) throws IOException,
			RevokedCertificateException, GeneralSecurityException, CertificateVerificationException {
		final var crl = CRLVerifier.downloadCRLFromWeb(certInfo.getCrlUrl());
		var issuerCertificate = certInfo.getIssuerCertificate();

		// find the issuer certificate (usually issuer of signature certificate)
		for (final X509Certificate certificate : this.certInformationHelper.getCertificateSet()) {
			if (certificate.getSubjectX500Principal().equals(crl.getIssuerX500Principal())) {
				issuerCertificate = certificate;
				break;
			}
		}
		crl.verify(issuerCertificate.getPublicKey(), SecurityProvider.getProvider().getName());
		CRLVerifier.checkRevocation(crl, certInfo.getCertificate(), this.signDate.getTime(), certInfo.getCrlUrl());
		final var crlStream = writeDataToStream(crl.getEncoded());
		this.crls.add(crlStream);
		if (this.correspondingCRLs != null) {
			this.correspondingCRLs.add(crlStream);

			byte[] signatureHash;
			try {
				// https://www.etsi.org/deliver/etsi_ts/102700_102799/10277804/01.01.02_60/ts_10277804v010102p.pdf
				// "For the signatures of the CRL and OCSP response, it is the respective
				// signature
				// object represented as a BER-encoded OCTET STRING encoded with primitive
				// encoding"
				final var berEncodedSignature = new BEROctetString(crl.getSignature());
				signatureHash = MessageDigest.getInstance("SHA-1").digest(berEncodedSignature.getEncoded());
			} catch (final NoSuchAlgorithmException ex) {
				throw new CertificateVerificationException(ex.getMessage(), ex);
			}
			final var signatureHashHex = Hex.getString(signatureHash);

			if (!this.vriBase.containsKey(signatureHashHex)) {
				final var savedCorrespondingOCSPs = this.correspondingOCSPs;
				final var savedCorrespondingCRLs = this.correspondingCRLs;

				final var vri = new COSDictionary();
				this.vriBase.setItem(signatureHashHex, vri);

				CertSignatureInformation crlCertInfo;
				try {
					crlCertInfo = this.certInformationHelper.getCertInfo(issuerCertificate);
				} catch (final CertificateProccessingException ex) {
					throw new CertificateVerificationException(ex.getMessage(), ex);
				}

				updateVRI(crlCertInfo, vri);

				this.correspondingOCSPs = savedCorrespondingOCSPs;
				this.correspondingCRLs = savedCorrespondingCRLs;
			}
		}
		this.foundRevocationInformation.add(certInfo.getCertificate());
	}

	/**
	 * Adds Extensions to the document catalog. So that the use of DSS is
	 * identified. Described in PAdES Part 4, Chapter 4.4.
	 *
	 * @param catalog to add Extensions into
	 */
	private void addExtensions(final PDDocumentCatalog catalog) {
		final var dssExtensions = new COSDictionary();
		dssExtensions.setDirect(true);
		catalog.getCOSObject().setItem("Extensions", dssExtensions);

		final var adbeExtension = new COSDictionary();
		adbeExtension.setDirect(true);
		dssExtensions.setItem("ADBE", adbeExtension);

		adbeExtension.setName("BaseVersion", "1.7");
		adbeExtension.setInt("ExtensionLevel", 5);

		catalog.setVersion("1.7");
	}

	/**
	 * Fetches and adds OCSP data to storage for the given Certificate.
	 *
	 * @param certInfo the certificate info, for it to check OCSP data.
	 * @throws IOException
	 * @throws OCSPException
	 * @throws CertificateProccessingException
	 * @throws RevokedCertificateException
	 */
	private void addOcspData(final CertSignatureInformation certInfo)
			throws IOException, OCSPException, CertificateProccessingException, RevokedCertificateException {
		if (this.ocspChecked.contains(certInfo.getCertificate())) {
			// This certificate has been OCSP-checked before
			return;
		}
		final var ocspHelper = new OcspHelper(certInfo.getCertificate(), this.signDate.getTime(),
				certInfo.getIssuerCertificate(), new HashSet<>(this.certInformationHelper.getCertificateSet()),
				certInfo.getOcspUrl());
		final var ocspResp = ocspHelper.getResponseOcsp();
		this.ocspChecked.add(certInfo.getCertificate());
		final var basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
		final var ocspResponderCertificate = ocspHelper.getOcspResponderCertificate();
		this.certInformationHelper.addAllCertsFromHolders(basicResponse.getCerts());
		byte[] signatureHash;
		try {
			// https://www.etsi.org/deliver/etsi_ts/102700_102799/10277804/01.01.02_60/ts_10277804v010102p.pdf
			// "For the signatures of the CRL and OCSP response, it is the respective
			// signature
			// object represented as a BER-encoded OCTET STRING encoded with primitive
			// encoding"
			final var encodedSignature = new BEROctetString(basicResponse.getSignature());
			signatureHash = MessageDigest.getInstance("SHA-1").digest(encodedSignature.getEncoded());
		} catch (final NoSuchAlgorithmException ex) {
			throw new CertificateProccessingException(ex);
		}
		final var signatureHashHex = Hex.getString(signatureHash);

		if (!this.vriBase.containsKey(signatureHashHex)) {
			final var savedCorrespondingOCSPs = this.correspondingOCSPs;
			final var savedCorrespondingCRLs = this.correspondingCRLs;

			final var vri = new COSDictionary();
			this.vriBase.setItem(signatureHashHex, vri);
			final var ocspCertInfo = this.certInformationHelper.getCertInfo(ocspResponderCertificate);

			updateVRI(ocspCertInfo, vri);

			this.correspondingOCSPs = savedCorrespondingOCSPs;
			this.correspondingCRLs = savedCorrespondingCRLs;
		}

		final var ocspData = ocspResp.getEncoded();

		final var ocspStream = writeDataToStream(ocspData);
		this.ocsps.add(ocspStream);
		if (this.correspondingOCSPs != null) {
			this.correspondingOCSPs.add(ocspStream);
		}
		this.foundRevocationInformation.add(certInfo.getCertificate());
	}

	/**
	 * Fetches and adds revocation information based on the certInfo to the DSS.
	 *
	 * @param certInfo Certificate information from CertInformationHelper containing
	 *                 certificate chains.
	 * @throws IOException
	 */
	private void addRevocationData(final CertSignatureInformation certInfo) throws IOException {
		final var vri = new COSDictionary();
		this.vriBase.setItem(certInfo.getSignatureHash(), vri);

		updateVRI(certInfo, vri);

		if (certInfo.getTsaCerts() != null) {
			// Don't add RevocationInfo from tsa to VRI's
			this.correspondingOCSPs = null;
			this.correspondingCRLs = null;
			addRevocationDataRecursive(certInfo.getTsaCerts());
		}
	}

	/**
	 * Tries to get Revocation Data (first OCSP, else CRL) from the given
	 * Certificate Chain.
	 *
	 * @param certInfo from which to fetch revocation data. Will work recursively
	 *                 through its chains.
	 * @throws IOException when failed to fetch an revocation data.
	 */
	private void addRevocationDataRecursive(final CertSignatureInformation certInfo) throws IOException {
		if (certInfo.isSelfSigned()) {
			return;
		}
		// To avoid getting same revocation information twice.
		var isRevocationInfoFound = this.foundRevocationInformation.contains(certInfo.getCertificate());
		if (!isRevocationInfoFound) {
			if (certInfo.getOcspUrl() != null && certInfo.getIssuerCertificate() != null) {
				isRevocationInfoFound = fetchOcspData(certInfo);
			}
			if (!isRevocationInfoFound && certInfo.getCrlUrl() != null) {
				fetchCrlData(certInfo);
				isRevocationInfoFound = true;
			}

			if (certInfo.getOcspUrl() == null && certInfo.getCrlUrl() == null) {
				LOG.info("No revocation information for cert " + certInfo.getCertificate().getSubjectX500Principal());
			} else if (!isRevocationInfoFound) {
				throw new IOException("Could not fetch Revocation Info for Cert: "
						+ certInfo.getCertificate().getSubjectX500Principal());
			}
		}

		if (certInfo.getAlternativeCertChain() != null) {
			addRevocationDataRecursive(certInfo.getAlternativeCertChain());
		}

		if (certInfo.getCertChain() != null && certInfo.getCertChain().getCertificate() != null) {
			addRevocationDataRecursive(certInfo.getCertChain());
		}
	}

	/**
	 * Fetches certificate information from the last signature of the document and
	 * appends a DSS with the validation information to the document.
	 *
	 * @param filename in file to extract signature
	 * @param output   where to write the changed document
	 * @throws IOException
	 */
	private void doValidation(final byte[] inPdf, final OutputStream output) throws IOException {
		this.certInformationHelper = new CertInformationCollector();
		CertSignatureInformation certInfo = null;
		try {
			final var signature = SigUtils.getLastRelevantSignature(this.document);
			if (signature != null) {
				certInfo = this.certInformationHelper.getLastCertInfo(signature, inPdf);
				this.signDate = signature.getSignDate();
				if ("ETSI.RFC3161".equals(signature.getSubFilter())) {
					final var contents = signature.getContents();
					final var timeStampToken = new TimeStampToken(new CMSSignedData(contents));
					final var timeStampInfo = timeStampToken.getTimeStampInfo();
					this.signDate = Calendar.getInstance();
					this.signDate.setTime(timeStampInfo.getGenTime());
				}
			}
		} catch (TSPException | CMSException | CertificateProccessingException e) {
			throw new IOException("An Error occurred processing the Signature", e);
		}
		if (certInfo == null) {
			throw new IOException("No Certificate information or signature found in the given document");
		}

		final var docCatalog = this.document.getDocumentCatalog();
		final var catalog = docCatalog.getCOSObject();
		catalog.setNeedToBeUpdated(true);

		final var dss = getOrCreateDictionaryEntry(COSDictionary.class, catalog, "DSS");

		addExtensions(docCatalog);

		this.vriBase = getOrCreateDictionaryEntry(COSDictionary.class, dss, "VRI");

		this.ocsps = getOrCreateDictionaryEntry(COSArray.class, dss, "OCSPs");

		this.crls = getOrCreateDictionaryEntry(COSArray.class, dss, "CRLs");

		this.certs = getOrCreateDictionaryEntry(COSArray.class, dss, "Certs");

		addRevocationData(certInfo);

		addAllCertsToCertArray();

		// write incremental
		this.document.saveIncremental(output);
	}

	/**
	 * Fetches certificate information from the last signature of the document and
	 * appends a DSS with the validation information to the document.
	 *
	 * @param filename in file to extract signature
	 * @param output   where to write the changed document
	 * @throws IOException
	 */
	private void doValidation(final String filename, final OutputStream output) throws IOException {
		this.certInformationHelper = new CertInformationCollector();
		CertSignatureInformation certInfo = null;
		try {
			final var signature = SigUtils.getLastRelevantSignature(this.document);
			if (signature != null) {
				certInfo = this.certInformationHelper.getLastCertInfo(signature, filename);
				this.signDate = signature.getSignDate();
				if ("ETSI.RFC3161".equals(signature.getSubFilter())) {
					final var contents = signature.getContents();
					final var timeStampToken = new TimeStampToken(new CMSSignedData(contents));
					final var timeStampInfo = timeStampToken.getTimeStampInfo();
					this.signDate = Calendar.getInstance();
					this.signDate.setTime(timeStampInfo.getGenTime());
				}
			}
		} catch (TSPException | CMSException | CertificateProccessingException e) {
			throw new IOException("An Error occurred processing the Signature", e);
		}
		if (certInfo == null) {
			throw new IOException("No Certificate information or signature found in the given document");
		}

		final var docCatalog = this.document.getDocumentCatalog();
		final var catalog = docCatalog.getCOSObject();
		catalog.setNeedToBeUpdated(true);

		final var dss = getOrCreateDictionaryEntry(COSDictionary.class, catalog, "DSS");

		addExtensions(docCatalog);

		this.vriBase = getOrCreateDictionaryEntry(COSDictionary.class, dss, "VRI");

		this.ocsps = getOrCreateDictionaryEntry(COSArray.class, dss, "OCSPs");

		this.crls = getOrCreateDictionaryEntry(COSArray.class, dss, "CRLs");

		this.certs = getOrCreateDictionaryEntry(COSArray.class, dss, "Certs");

		addRevocationData(certInfo);

		addAllCertsToCertArray();

		// write incremental
		this.document.saveIncremental(output);
	}

	/**
	 * Tries to fetch and add CRL Data to its containers.
	 *
	 * @param certInfo the certificate info, for it to check CRL data.
	 * @throws IOException when failed to fetch, because no validation data could be
	 *                     fetched for data.
	 */
	private void fetchCrlData(final CertSignatureInformation certInfo) throws IOException {
		try {
			addCrlRevocationInfo(certInfo);
		} catch (GeneralSecurityException | IOException | RevokedCertificateException
				| CertificateVerificationException e) {
			LOG.warn("Failed fetching CRL", e);
			throw new IOException(e);
		}
	}

	/**
	 * Tries to fetch and add OCSP Data to its containers.
	 *
	 * @param certInfo the certificate info, for it to check OCSP data.
	 * @return true when the OCSP data has successfully been fetched and added
	 * @throws IOException when Certificate is revoked.
	 */
	private boolean fetchOcspData(final CertSignatureInformation certInfo) throws IOException {
		try {
			addOcspData(certInfo);
			return true;
		} catch (OCSPException | CertificateProccessingException | IOException e) {
			LOG.error("Failed fetching OCSP at " + certInfo.getOcspUrl(), e);
			return false;
		} catch (final RevokedCertificateException e) {
			throw new IOException(e);
		}
	}

	private void updateVRI(final CertSignatureInformation certInfo, final COSDictionary vri) throws IOException {
		if (certInfo.getCertificate().getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) == null) {
			this.correspondingOCSPs = new COSArray();
			this.correspondingCRLs = new COSArray();
			addRevocationDataRecursive(certInfo);
			if (this.correspondingOCSPs.size() > 0) {
				vri.setItem("OCSP", this.correspondingOCSPs);
			}
			if (this.correspondingCRLs.size() > 0) {
				vri.setItem("CRL", this.correspondingCRLs);
			}
		}

		final var correspondingCerts = new COSArray();
		var ci = certInfo;
		do {
			final var cert = ci.getCertificate();
			try {
				final var certStream = writeDataToStream(cert.getEncoded());
				correspondingCerts.add(certStream);
				this.certMap.put(cert, certStream);
			} catch (final CertificateEncodingException ex) {
				// should not happen because these are existing certificates
				LOG.error(ex, ex);
			}

			if (cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null) {
				break;
			}
			ci = ci.getCertChain();
		} while (ci != null);
		vri.setItem(COSName.CERT, correspondingCerts);

		vri.setDate(COSName.TU, Calendar.getInstance());
	}

	public byte[] validateSignature(final byte[] inPdf) throws IOException {
		try (var doc = Loader.loadPDF(inPdf); var fos = new ByteArrayOutputStream()) {
			final var accessPermissions = SigUtils.getMDPPermission(doc);
			if (accessPermissions == 1) {
				System.out.println("""
						PDF is certified to forbid changes,\s\
						some readers may report the document as invalid despite that\s\
						the PDF specification allows DSS additions""");
			}
			this.document = doc;
			doValidation(inPdf, fos);
			return fos.toByteArray();
		}
	}

	/**
	 * Signs the given PDF file.
	 *
	 * @param inFile  input PDF file
	 * @param outFile output PDF file
	 * @throws IOException if the input file could not be read
	 */
	public void validateSignature(final File inFile, final File outFile) throws IOException {
		if (inFile == null || !inFile.exists()) {
			final var err = new StringBuilder("Document for signing ");
			if (null == inFile) {
				err.append("is null");
			} else {
				err.append("does not exist: ").append(inFile.getAbsolutePath());
			}
			throw new FileNotFoundException(err.toString());
		}

		try (var doc = Loader.loadPDF(inFile); var fos = new FileOutputStream(outFile)) {
			final var accessPermissions = SigUtils.getMDPPermission(doc);
			if (accessPermissions == 1) {
				System.out.println("""
						PDF is certified to forbid changes,\s\
						some readers may report the document as invalid despite that\s\
						the PDF specification allows DSS additions""");
			}
			this.document = doc;
			doValidation(inFile.getAbsolutePath(), fos);
		}
	}

	/**
	 * Creates a Flate encoded <code>COSStream</code> object with the given data.
	 *
	 * @param data to write into the COSStream
	 * @return COSStream a COSStream object that can be added to the document
	 * @throws IOException
	 */
	private COSStream writeDataToStream(final byte[] data) throws IOException {
		final var stream = this.document.getDocument().createCOSStream();
		try (var os = stream.createOutputStream(COSName.FLATE_DECODE)) {
			os.write(data);
		}
		return stream;
	}
}
