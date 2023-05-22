/**
 * @fileoverview This file was created by ]init[ AG 2023.
 * 
 * This file contains all methods for validating PDF signatures.
 */
const pdfSignatureReader = require('./local_modules/pdf-signature-reader');
const forge = require('node-forge')
const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js')

// Set the workerSrc property for pdf.js to work correctly
pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.js'

function readFileAsync(file) {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = _ => {
			resolve(reader.result);
		};
		reader.onerror = reject;
		reader.readAsArrayBuffer(file);
	});
}

async function getPublicKey(serialNumber) {
	const response = await fetch(`/seal_verification/pdf_public_key?serial_number=${serialNumber}`)
	if (!response.ok) {
		if (response.status === 404) {
			return null
		}
		throw new Error(`HTTP error: ${response.status}`);
	}
	const pemContents = await response.text()
	return pemContents
}

function cleanPEMCertificate(pemCert) {
	return pemCert.replace(/-+BEGIN PUBLIC KEY-+|-+END PUBLIC KEY-+|\s+/g, '');
}

function attr2html(value) {
	if (value instanceof Date) {
		const options = { day: '2-digit', month: '2-digit', year: 'numeric' };
		return value.toLocaleDateString('de-DE', options);
	}
	return value
}

async function fetchDocumentValid(documentNumber) {
	const response = await fetch(`/seal_verification/valid?document_number=${documentNumber}`)
	if (!response.ok) {
		// No 404 possible, unknown documentNumbers are automatically acknowledged with valid (true)
		throw new Error(`HTTP error: ${response.status}`);
	}
	return await response.json()
}

/**
 * Check if document with document number is valid.
 * Document number is part of the signature reason.
 *
 * @param {string} reason - Signature metadata reason
 * @return {Promise<string|boolean>} True for OK or String with problems
 */
async function verifyDocument(reason) {
	// TODO make configurable, where document number is
	const regex = /Zeugnisbewertung (.+)/
	const match = reason.match(regex)
	if (!match) {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ '<p>Das PDF enthält zwar eine gültige digitale Signatur,'
			+ ' aber der Grund enthält keine Urkundenummer!</p>'
	}
	const documentNumber = match[1];
	const documentValid = await fetchDocumentValid(documentNumber)
	if (!documentValid) {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ '<p>Das PDF enthält zwar eine gültige digitale Signatur,'
			+ ` aber die Zeugnisbewertung für die Urkundennummer ${documentNumber} wurde zurückgezogen!</p>`
	}
	return true
}

async function verifySignatures(signatures) {
	let foundSig = false
	for (const signature of signatures) {
		// Decompose signature:
		// + authenticity - cert chain OK, including Browser trust store check (hence temporary certs fail here!)
		// + integrity - PDF hash-signature OK
		// + expired - is expired?
		// + verified - all together
		const { verified, authenticity, integrity, expired, meta } = signature
		if (!integrity) {
			// Is PDF content hash and it's hash signature OK?
			return '<h2>Prüfergebnis: Negativ</h2>'
				+ '<p>Das PDF enthält zwar eine digitale Signatur,'
				+ 'aber das Dokument wurde nachträglich modifiziert!</p>'
		}
		const { certs, signatureMeta } = meta
		const { reason, contactInfo, location, name } = signatureMeta

		// output cert information	
		for (const cert of certs) {
			if (!cert.clientCertificate) {
				continue
			}
			foundSig = true
			const { clientCertificate, issuedBy, issuedTo, pemCertificate, validityPeriod } = cert
			const forgeCert = forge.pki.certificateFromPem(pemCertificate)
			const publicKeyFromServer = await getPublicKey(forgeCert.serialNumber)
			if (publicKeyFromServer === null) {
				continue
			}
			const publicKeyFromCert = forge.pki.publicKeyToPem(forgeCert.publicKey)
			const valid = cleanPEMCertificate(publicKeyFromServer) === cleanPEMCertificate(publicKeyFromCert)
			if (valid) {
				documentValid = await verifyDocument(reason)
				if (typeof documentValid === 'string') {
					return documentValid
				}

				let html = '<h2>Prüfergebnis: Positiv</h2>'
				html += '<p>Das PDF enthält eine gültige digitale Signatur.</p>'
				html += '<dl id="key-value-list">'
				if (name) {
					html += `<dt>Aussteller</dt><dd>${attr2html(name)}</dd>`
				}
				if (reason) {
					html += `<dt>Ausstellungsgrund</dt><dd>${attr2html(reason)}</dd>`
				}
				if (contactInfo) {
					html += `<dt>Kontaktinformationen</dt><dd>${attr2html(contactInfo)}</dd>`
				}
				if (location) {
					html += `<dt>Ausstellungsort</dt><dd>${attr2html(location)}</dd>`
				}
				html += `<dt>Aussteller verifiziert durch</dt><dd>${attr2html(issuedBy.commonName)}${authenticity ? '' : '   (Vertrauenskette nicht verifizierbar)'}</dd>`
				html += `<dt>Gültigkeit</dt><dd>${attr2html(validityPeriod.notBefore)} - ${attr2html(validityPeriod.notAfter)}${expired ? '   (abgelaufen)' : ''}</dd>`
				html += '</dl>'
				return html
			}
		}
	}
	if (foundSig) {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ '<p>Das PDF enthält zwar eine digitale Signatur, aber diese konnte nicht zugeordnet werden.'
			+ ' Das Dokument wurde nicht durch die ZAB ausgestellt.</p>'
	}
	return false
}

async function verifyPdfSeal(file, pageNumber = 1) {
	// Following doesn't work, because pdf.js right now doesn't parse annotation data
	//	const annotations = await pdfPage.getAnnotations();
	//	annotations.forEach(annotation => {
	//		if (annotation.subtype === 'Widget' && annotation.fieldType === 'Sig') {
	//			const signatureData = annotation.data;
	//			// ...
	//		}
	//	});

	const fileBuffer = await readFileAsync(file)
	let verified, authenticity, integrity, expired, signatures
	try {
		({ verified, authenticity, integrity, expired, signatures } = pdfSignatureReader(fileBuffer))
	} catch (error) {
		// If no signature found: cannot find subfilter
		return false
	}
	if (signatures.length === 0) {
		// Dunno of this can happen, "cannot find subfilter"-error should happen before
		return false
	}
	return await verifySignatures(signatures)
}

async function convertPdfToImageFile(file, pageNumber = 1) {
	const arrayBuffer = await readFileAsync(file);

	// Load the PDF document using pdf.js
	const loadingTask = pdfjsLib.getDocument({ data: new Uint8Array(arrayBuffer) });
	const pdfDocument = await loadingTask.promise;

	// Fetch the requested page
	const pdfPage = await pdfDocument.getPage(pageNumber);

	// Create the canvas element and its context
	const canvas = document.createElement('canvas');
	const context = canvas.getContext('2d');

	// Calculate the desired viewport based on the canvas size
	const viewport = pdfPage.getViewport({ scale: 1 });
	canvas.width = viewport.width;
	canvas.height = viewport.height;

	// Render the PDF page to the canvas
	await pdfPage.render({ canvasContext: context, viewport: viewport }).promise;

	// Get the image data from the canvas as a Blob
	return new Promise((resolve, reject) => {
		canvas.toBlob(blob => {
			// Resolve the promise with the File-of-Blob object
			if (blob) {
				resolve(new File([blob], 'image.png', { type: 'image/png' }));
			} else {
				reject(new Error('Unable to convert canvas to blob'));
			}
		}, 'image/png');
	});
}

module.exports = verifyPdfSeal
module.exports = {
	verifyPdfSeal: verifyPdfSeal,
	convertPdfToImageFile: convertPdfToImageFile
}