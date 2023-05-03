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
package de.init.seal_service.pdf.pdfbox_signature;

import java.awt.Color;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Calendar;
import java.util.Locale;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Hex;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * This is a second example for visual signing a pdf. It doesn't use the "design
 * pattern" influenced PDVisibleSignDesigner, and doesn't create its complex
 * multilevel forms described in the Adobe document <a href=
 * "https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/PPKAppearances.pdf">Digital
 * Signature Appearances</a>, because this isn't required by the PDF
 * specification. See the discussion in December 2017 in PDFBOX-3198.
 *
 * @author Vakhtang Koroghlishvili
 * @author Tilman Hausherr
 */
public class CreateVisibleSignature2 extends CreateSignatureBase {
	/**
	 * Arguments are [0] key store [1] pin [2] document that will be signed [3]
	 * image of visible signature
	 *
	 * @param args
	 * @throws java.security.KeyStoreException
	 * @throws java.security.cert.CertificateException
	 * @throws java.io.IOException
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws java.security.UnrecoverableKeyException
	 */
	public static void main(String[] args) throws KeyStoreException, CertificateException, IOException,
			NoSuchAlgorithmException, UnrecoverableKeyException {

		if (args.length < 3) {
			usage();
			System.exit(1);
		}

		String tsaUrl = null;
		// External signing is needed if you are using an external signing service, e.g.
		// to sign
		// several files at once.
		var externalSig = false;
		for (var i = 0; i < args.length; i++) {
			if ("-tsa".equals(args[i])) {
				i++;
				if (i >= args.length) {
					usage();
					System.exit(1);
				}
				tsaUrl = args[i];
			}
			if ("-e".equals(args[i])) {
				externalSig = true;
			}
		}

		final var ksFile = new File(args[0]);
		final var keystore = KeyStore.getInstance("PKCS12");
		final var pin = args[1].toCharArray();
		try (InputStream is = new FileInputStream(ksFile)) {
			keystore.load(is, pin);
		}

		final var documentFile = new File(args[2]);

		final var signing = new CreateVisibleSignature2(keystore, pin.clone());

		if (args.length >= 4 && !"-tsa".equals(args[3])) {
			signing.setImageFile(new File(args[3]));
		}

		File signedDocumentFile;
		final var name = documentFile.getName();
		final var substring = name.substring(0, name.lastIndexOf('.'));
		signedDocumentFile = new File(documentFile.getParent(), substring + "_signed.pdf");

		signing.setExternalSigning(externalSig);

		// Set the signature rectangle
		// Although PDF coordinates start from the bottom, humans start from the top.
		// So a human would want to position a signature (x,y) units from the
		// top left of the displayed page, and the field has a horizontal width and a
		// vertical height
		// regardless of page rotation.
		final Rectangle2D humanRect = new Rectangle2D.Float(70, 580, 200, 250);

		signing.signPDF(documentFile, signedDocumentFile, humanRect, tsaUrl, "Signature1");
	}

	/**
	 * This will print the usage for this program.
	 */
	private static void usage() {
		System.err.println("Usage: java " + CreateVisibleSignature2.class.getName()
				+ " <pkcs12-keystore-file> <pin> <input-pdf> <sign-image>\n" + "" + "options:\n"
				+ "  -tsa <url>    sign timestamp using the given TSA server\n"
				+ "  -e            sign using external signature creation scenario");

		// generate pkcs12-keystore-file with
		// keytool -storepass 123456 -storetype PKCS12 -keystore file.p12 -genkey -alias
		// client -keyalg RSA
	}

	private SignatureOptions signatureOptions;

	private boolean lateExternalSigning = false;

	private File imageFile = null;

	/**
	 * Initialize the signature creator with a keystore (pkcs12) and pin that should
	 * be used for the signature.
	 *
	 * @param keystore is a pkcs12 keystore.
	 * @param pin      is the pin for the keystore / private key
	 * @throws KeyStoreException         if the keystore has not been initialized
	 *                                   (loaded)
	 * @throws NoSuchAlgorithmException  if the algorithm for recovering the key
	 *                                   cannot be found
	 * @throws UnrecoverableKeyException if the given password is wrong
	 * @throws CertificateException      if the certificate is not valid as signing
	 *                                   time
	 * @throws IOException               if no certificate could be found
	 */
	public CreateVisibleSignature2(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException,
			NoSuchAlgorithmException, IOException, CertificateException {
		super(keystore, pin);
	}

	private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect) {
		final var x = (float) humanRect.getX();
		final var y = (float) humanRect.getY();
		final var width = (float) humanRect.getWidth();
		final var height = (float) humanRect.getHeight();
		final var page = doc.getPage(0);
		final var pageRect = page.getCropBox();
		final var rect = new PDRectangle();
		// signing should be at the same position regardless of page rotation.
		switch (page.getRotation()) {
		case 90:
			rect.setLowerLeftY(x);
			rect.setUpperRightY(x + width);
			rect.setLowerLeftX(y);
			rect.setUpperRightX(y + height);
			break;
		case 180:
			rect.setUpperRightX(pageRect.getWidth() - x);
			rect.setLowerLeftX(pageRect.getWidth() - x - width);
			rect.setLowerLeftY(y);
			rect.setUpperRightY(y + height);
			break;
		case 270:
			rect.setLowerLeftY(pageRect.getHeight() - x - width);
			rect.setUpperRightY(pageRect.getHeight() - x);
			rect.setLowerLeftX(pageRect.getWidth() - y - height);
			rect.setUpperRightX(pageRect.getWidth() - y);
			break;
		case 0:
		default:
			rect.setLowerLeftX(x);
			rect.setUpperRightX(x + width);
			rect.setLowerLeftY(pageRect.getHeight() - y - height);
			rect.setUpperRightY(pageRect.getHeight() - y);
			break;
		}
		return rect;
	}

	// create a template PDF document with empty signature and return it as a
	// stream.
	private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum, PDRectangle rect,
			PDSignature signature) throws IOException {
		try (var doc = new PDDocument()) {
			final var page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
			doc.addPage(page);
			final var acroForm = new PDAcroForm(doc);
			doc.getDocumentCatalog().setAcroForm(acroForm);
			final var signatureField = new PDSignatureField(acroForm);
			final var widget = signatureField.getWidgets().get(0);
			final var acroFormFields = acroForm.getFields();
			acroForm.setSignaturesExist(true);
			acroForm.setAppendOnly(true);
			acroForm.getCOSObject().setDirect(true);
			acroFormFields.add(signatureField);

			widget.setRectangle(rect);

			// from PDVisualSigBuilder.createHolderForm()
			final var stream = new PDStream(doc);
			final var form = new PDFormXObject(stream);
			final var res = new PDResources();
			form.setResources(res);
			form.setFormType(1);
			final var bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
			var height = bbox.getHeight();
			Matrix initialScale = null;
			switch (srcDoc.getPage(pageNum).getRotation()) {
			case 90:
				form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
				initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(),
						bbox.getHeight() / bbox.getWidth());
				height = bbox.getWidth();
				break;
			case 180:
				form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
				break;
			case 270:
				form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
				initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(),
						bbox.getHeight() / bbox.getWidth());
				height = bbox.getWidth();
				break;
			case 0:
			default:
				break;
			}
			form.setBBox(bbox);
			final PDFont font = new PDType1Font(FontName.HELVETICA_BOLD);

			// from PDVisualSigBuilder.createAppearanceDictionary()
			final var appearance = new PDAppearanceDictionary();
			appearance.getCOSObject().setDirect(true);
			final var appearanceStream = new PDAppearanceStream(form.getCOSObject());
			appearance.setNormalAppearance(appearanceStream);
			widget.setAppearance(appearance);

			try (var cs = new PDPageContentStream(doc, appearanceStream)) {
				// for 90° and 270° scale ratio of width / height
				// not really sure about this
				// why does scale have no effect when done in the form matrix???
				if (initialScale != null) {
					cs.transform(initialScale);
				}

				// show background (just for debugging, to see the rect size + position)
				cs.setNonStrokingColor(Color.yellow);
				cs.addRect(-5000, -5000, 10000, 10000);
				cs.fill();

				if (imageFile != null) {
					// show background image
					// save and restore graphics if the image is too large and needs to be scaled
					cs.saveGraphicsState();
					final var img = PDImageXObject.createFromFileByExtension(imageFile, doc);
					// Scale image width, optionally preserve vertical space for upper text
					final var scale = rect.getWidth() / img.getWidth();
					cs.transform(Matrix.getScaleInstance(scale, scale));
					cs.drawImage(img, 0, 0);
					cs.restoreGraphicsState();
				}

				// show text
				final var fontSize = 10F;
				final var leading = fontSize * 1.5f;
				cs.beginText();
				cs.setFont(font, fontSize);
				cs.setNonStrokingColor(Color.black);
				cs.newLineAtOffset(fontSize, height - leading);
				cs.setLeading(leading);

				final var cert = (X509Certificate) getCertificateChain()[0];

				// https://stackoverflow.com/questions/2914521/
				final var x500Name = new X500Name(cert.getSubjectX500Principal().getName());
				final var cn = x500Name.getRDNs(BCStyle.CN)[0];
				final var name = IETFUtils.valueToString(cn.getFirst().getValue());

				// See https://stackoverflow.com/questions/12575990
				// for better date formatting
				// final var date = signature.getSignDate().getTime().toString();
				final var germanFormatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT)
						.withLocale(Locale.GERMANY);
				final var date = signature.getSignDate().toInstant().atZone(ZoneId.systemDefault())
						.format(germanFormatter);
				final var reason = signature.getReason();

				cs.showText("Unterzeichner: " + name);
				cs.newLine();
				cs.showText("Datum: " + date);
				cs.newLine();
				cs.showText("Grund: " + reason);

				cs.endText();
			}

			// no need to set annotations and /P entry

			final var baos = new ByteArrayOutputStream();
			doc.save(baos);
			return new ByteArrayInputStream(baos.toByteArray());
		}
	}

	// Find an existing signature (assumed to be empty). You will usually not need
	// this.
	private PDSignature findExistingSignature(PDAcroForm acroForm, String sigFieldName) {
		PDSignature signature = null;
		PDSignatureField signatureField;
		if (acroForm != null) {
			signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
			if (signatureField != null) {
				// retrieve signature dictionary
				signature = signatureField.getSignature();
				if (signature != null) {
					throw new IllegalStateException("The signature field " + sigFieldName + " is already signed.");
				}
				signature = new PDSignature();
				// after solving PDFBOX-3524
				// signatureField.setValue(signature)
				// until then:
				signatureField.getCOSObject().setItem(COSName.V, signature);
			}
		}
		return signature;
	}

	public File getImageFile() {
		return imageFile;
	}

	public boolean isLateExternalSigning() {
		return lateExternalSigning;
	}

	public void setImageFile(File imageFile) {
		this.imageFile = imageFile;
	}

	/**
	 * Set late external signing. Enable this if you want to activate the demo code
	 * where the signature is kept and added in an extra step without using PDFBox
	 * methods. This is disabled by default.
	 *
	 * @param lateExternalSigning
	 */
	public void setLateExternalSigning(boolean lateExternalSigning) {
		this.lateExternalSigning = lateExternalSigning;
	}

	/**
	 * Sign pdf file and create new file that ends with "_signed.pdf".
	 *
	 * @param inputFile  The source pdf document file.
	 * @param signedFile The file to be signed.
	 * @param humanRect  rectangle from a human viewpoint (coordinates start at top
	 *                   left)
	 * @param tsaUrl     optional TSA url
	 * @throws IOException
	 */
	public void signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl) throws IOException {
		this.signPDF(inputFile, signedFile, humanRect, tsaUrl, null);
	}

	/**
	 * Sign pdf file and create new file that ends with "_signed.pdf".
	 *
	 * @param inputFile          The source pdf document file.
	 * @param signedFile         The file to be signed.
	 * @param humanRect          rectangle from a human viewpoint (coordinates start
	 *                           at top left)
	 * @param tsaUrl             optional TSA url
	 * @param signatureFieldName optional name of an existing (unsigned) signature
	 *                           field
	 * @throws IOException
	 */
	public void signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl,
			String signatureFieldName) throws IOException {
		if (inputFile == null || !inputFile.exists()) {
			throw new IOException("Document for signing does not exist");
		}

		setTsaUrl(tsaUrl);

		// creating output document and prepare the IO streams.

		try (var fos = new FileOutputStream(signedFile); var doc = Loader.loadPDF(inputFile)) {
			// call SigUtils.checkCrossReferenceTable(doc) if Adobe complains
			// and read https://stackoverflow.com/a/71293901/535646
			// and https://issues.apache.org/jira/browse/PDFBOX-5382

			final var accessPermissions = SigUtils.getMDPPermission(doc);
			if (accessPermissions == 1) {
				throw new IllegalStateException(
						"No changes to the document are permitted due to DocMDP transform parameters dictionary");
			}
			// Note that PDFBox has a bug that visual signing on certified files with
			// permission 2
			// doesn't work properly, see PDFBOX-3699. As long as this issue is open, you
			// may want to
			// be careful with such files.

			PDSignature signature = null;
			final var acroForm = doc.getDocumentCatalog().getAcroForm(null);
			PDRectangle rect = null;

			// sign a PDF with an existing empty signature, as created by the
			// CreateEmptySignatureForm example.
			if (acroForm != null) {
				signature = findExistingSignature(acroForm, signatureFieldName);
				if (signature != null) {
					rect = acroForm.getField(signatureFieldName).getWidgets().get(0).getRectangle();
				}
			}

			if (signature == null) {
				// create signature dictionary
				signature = new PDSignature();
			}

			if (rect == null) {
				rect = createSignatureRectangle(doc, humanRect);
			}

			// Optional: certify
			// can be done only if version is at least 1.5 and if not already set
			// doing this on a PDF/A-1b file fails validation by Adobe preflight
			// (PDFBOX-3821)
			// PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such
			// files.
			if (doc.getVersion() >= 1.5f && accessPermissions == 0) {
				SigUtils.setMDPPermission(doc, signature, 2);
			}

			if (acroForm != null && acroForm.getNeedAppearances()) {
				// PDFBOX-3738 NeedAppearances true results in visible signature becoming
				// invisible
				// with Adobe Reader
				if (acroForm.getFields().isEmpty()) {
					// we can safely delete it if there are no fields
					acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
					// note that if you've set MDP permissions, the removal of this item
					// may result in Adobe Reader claiming that the document has been changed.
					// and/or that field content won't be displayed properly.
					// ==> decide what you prefer and adjust your code accordingly.
				} else {
					System.out.println("/NeedAppearances is set, signature may be ignored by Adobe Reader");
				}
			}

			// default filter
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

			// subfilter for basic and PAdES Part 2 signatures
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

			signature.setName("ZAB");
			signature.setLocation("Berlin");
			signature.setReason("Zeugnisbewertung");

			// the signing date, needed for valid signature
			signature.setSignDate(Calendar.getInstance());

			// do not set SignatureInterface instance, if external signing used
			final var signatureInterface = isExternalSigning() ? null : this;

			// register signature dictionary and sign interface
			signatureOptions = new SignatureOptions();
			signatureOptions.setVisualSignature(createVisualSignatureTemplate(doc, 0, rect, signature));
			signatureOptions.setPage(0);
			doc.addSignature(signature, signatureInterface, signatureOptions);

			if (isExternalSigning()) {
				final var externalSigning = doc.saveIncrementalForExternalSigning(fos);
				// invoke external signature service
				final var cmsSignature = sign(externalSigning.getContent());

				// Explanation of late external signing (off by default):
				// If you want to add the signature in a separate step, then set an empty byte
				// array
				// and call signature.getByteRange() and remember the offset
				// signature.getByteRange()[1]+1.
				// you can write the ascii hex signature at a later time even if you don't have
				// this
				// PDDocument object anymore, with classic java file random access methods.
				// If you can't remember the offset value from ByteRange because your context
				// has changed,
				// then open the file with PDFBox, find the field with findExistingSignature()
				// or
				// PDDocument.getLastSignatureDictionary() and get the ByteRange from there.
				// Close the file and then write the signature as explained earlier in this
				// comment.
				if (isLateExternalSigning()) {
					// this saves the file with a 0 signature
					externalSigning.setSignature(new byte[0]);

					// remember the offset (add 1 because of "<")
					final var offset = signature.getByteRange()[1] + 1;

					// now write the signature at the correct offset without any PDFBox methods
					try (var raf = new RandomAccessFile(signedFile, "rw")) {
						raf.seek(offset);
						raf.write(Hex.getBytes(cmsSignature));
					}
				} else {
					// set signature bytes received from the service and save the file
					externalSigning.setSignature(cmsSignature);
				}
			} else {
				// write incremental (only for signing purpose)
				doc.saveIncremental(fos);
			}
		}

		// Do not close signatureOptions before saving, because some COSStream objects
		// within
		// are transferred to the signed document.
		// Do not allow signatureOptions get out of scope before saving, because then
		// the COSDocument
		// in signature options might by closed by gc, which would close COSStream
		// objects prematurely.
		// See https://issues.apache.org/jira/browse/PDFBOX-3743
		IOUtils.closeQuietly(signatureOptions);
	}

}
