/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_verification.spi;

import java.util.Base64;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;

import de.init.seal_verification.pdf.PdfTrustCerts;
import de.init.seal_verification.visual.DocumentNumberCache;
import de.init.seal_verification.visual.DocumentProfileCache;
import de.init.seal_verification.visual.VisualTrustCerts;

@Path("/seal_verification")
public class SealVerification {

	private static final Logger LOGGER = Logger.getLogger(SealVerification.class);

	@Inject
	DocumentNumberCache documentNumberCache;

	@Inject
	DocumentProfileCache documentProfileCache;

	@Inject
	PdfTrustCerts pdfTrustCerts;

	@Inject
	VisualTrustCerts visualTrustCerts;

	/**
	 * Get document profile for given number.
	 *
	 * @param docProfileNr document profile number
	 * @return document profile
	 */
	@GET
	@Path("profile")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getProfile(@QueryParam("doc_profile_nr") String docProfileNr) {
		LOGGER.debug("Get document profile for docProfileNr : " + docProfileNr);
		final var docProfile = this.documentProfileCache.getDocProfile(docProfileNr);
		if (docProfile == null) {
			return Response.status(Status.NOT_FOUND)
					.entity("Document profile not found for docProfileNr: " + docProfileNr).build();
		}
		return Response.ok(docProfile).build();
	}

	@GET
	@Path("ping")
	@Produces(MediaType.TEXT_PLAIN)
	public String hello() {
		return "Hello from RESTEasy Reactive";
	}

	/**
	 * Get RSA public key for PDF seal signature with given serial number.
	 *
	 * @param serialNumber serial number from PDF signature
	 * @return RSA public key
	 */
	@GET
	@Path("pdf_public_key")
	@Produces(MediaType.TEXT_PLAIN)
	public Response pdfPublicKey(@QueryParam("serial_number") String serialNumber) {
		LOGGER.debug("Get PDF public key for serial number : " + serialNumber);
		final var publicKey = this.pdfTrustCerts.getPublicKey(serialNumber);
		if (publicKey == null) {
			return Response.status(Status.NOT_FOUND)
					.entity("PDF public key not found for serial number: " + serialNumber).build();
		}
		final var encodedPublicKey = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
		return Response.ok(encodedPublicKey).build();
	}

	/**
	 * Check validity for document with given document number.
	 *
	 * @param documentNumber document number
	 * @return {@code "true"} - valid
	 */
	@GET
	@Path("valid")
	@Produces(MediaType.APPLICATION_JSON)
	public boolean valid(@QueryParam("document_number") String documentNumber) {
		LOGGER.debug("Check validity of document number: " + documentNumber);
		return !this.documentNumberCache.isDocumentNumberInvalid(documentNumber);
	}

	/**
	 * Get EC public key for visual seal signature with given serial number.
	 *
	 * @param serialNumber serial number from visual seal, see "Cert Serial Number"
	 *                     in TR-03171 header
	 * @return EC public key
	 */
	@GET
	@Path("visual_public_key")
	@Produces(MediaType.TEXT_PLAIN)
	public Response visualPublicKey(@QueryParam("serial_number") String serialNumber) {
		LOGGER.debug("Get visual public key for serial number : " + serialNumber);
		final var publicKey = this.visualTrustCerts.getPublicKey(serialNumber);
		if (publicKey == null) {
			return Response.status(Status.NOT_FOUND)
					.entity("Visual public key not found for serial number: " + serialNumber).build();
		}
		final var encodedPublicKey = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
		return Response.ok(encodedPublicKey).build();
	}

}