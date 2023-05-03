/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.spi;

import java.io.IOException;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse.Status;

import de.init.seal_service.pdf.PdfSealer;

@Path("/seal_service")
public class SealService {

	private static final Logger LOGGER = Logger.getLogger(SealService.class);

	@Inject
	PdfSealer pdfSealer;

	@GET
	@Path("ping")
	@Produces(MediaType.TEXT_PLAIN)
	public String hello() {
		return "Hello from RESTEasy Reactive";
	}

	@POST
	@Path("seal")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response sealPdf(final SealRequest sealRequest) {
		try {
			final var signedPdf = this.pdfSealer.sealPdf(sealRequest.pdf, sealRequest.docValues);
			return Response.ok(signedPdf, MediaType.APPLICATION_OCTET_STREAM)
					.header("Content-Disposition", "attachment; filename=\"signed_pdf.pdf\"").build();
		} catch (final IOException e) {
			LOGGER.error("An error occurred while sealing the PDF!", e);
			return Response.status(Status.INTERNAL_SERVER_ERROR)
					.entity("An error occurred while sealing the PDF. Please try again later.")
					.type(MediaType.TEXT_PLAIN).build();
		}
	}

}