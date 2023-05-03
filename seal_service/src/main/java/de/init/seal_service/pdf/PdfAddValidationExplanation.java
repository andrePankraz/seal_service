/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream.AppendMode;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

public class PdfAddValidationExplanation {

	public static byte[] addExplanation(final byte[] pdf) throws IOException {
		// Load the PDF document
		final var document = Loader.loadPDF(pdf);

		// Get the first page
		final var firstPage = document.getPage(0);

		// Create a content stream for adding content to the first page
		final var contentStream = new PDPageContentStream(document, firstPage, AppendMode.APPEND, true);

		// Write the headline
		final var helveticaBoldFont = new PDType1Font(FontName.HELVETICA_BOLD);
		contentStream.setFont(helveticaBoldFont, 18);
		contentStream.beginText();
		contentStream.newLineAtOffset(300, firstPage.getMediaBox().getHeight() - 600);
		contentStream.showText("Siegelvalidierung");
		contentStream.endText();

		// Write the text
		final var helveticaFont = new PDType1Font(FontName.HELVETICA);
		contentStream.setFont(helveticaFont, 12);
		contentStream.beginText();
		contentStream.newLineAtOffset(300, firstPage.getMediaBox().getHeight() - 620);
		contentStream.showText("Das Dokument ist mit einem Siegel (links) versehen.");
		contentStream.endText();

		contentStream.beginText();
		contentStream.newLineAtOffset(300, firstPage.getMediaBox().getHeight() - 640);
		contentStream.showText("Dieses sollten Sie auf folgender Webseite prüfen:");
		contentStream.endText();

		// Write the link
		contentStream.beginText();
		contentStream.setNonStrokingColor(0, 0, 1);
		contentStream.setFont(helveticaFont, 12);
		contentStream.newLineAtOffset(300, firstPage.getMediaBox().getHeight() - 660);
		contentStream.showText("https://zab.de/validierung.html");
		contentStream.endText();

		// Load the image
		final var imageInputStream = PdfAddValidationExplanation.class.getResourceAsStream("/qr-code.png");
		final var imageBytes = imageInputStream.readAllBytes();

		// Create the PDImageXObject from the byte array
		final var imageName = "qr-code";
		final var qrCodeImage = PDImageXObject.createFromByteArray(document, imageBytes, imageName);

		// Scale the image
		final var imageWidth = 100F;
		final var imageHeight = 100F;
		final var imageXPosition = 350F;
		final var imageYPosition = firstPage.getMediaBox().getHeight() - 770;

		// Add the image to the content stream
		contentStream.drawImage(qrCodeImage, imageXPosition, imageYPosition, imageWidth, imageHeight);

		// Close the content stream
		contentStream.close();

		// Save the modified PDF document to a byte array
		final var outputStream = new ByteArrayOutputStream();
		document.save(outputStream);
		document.close();

		// Output PDF byte array
		return outputStream.toByteArray();
	}

}