/**
 * @fileoverview This file was created by ]init[ AG 2023.
 * 
 * This file contains methods for validating PDF signatures and visual signatures (DataMatrix).
 */

const { verifyPdfSeal, convertPdfToImageFile } = require('./verify-pdf-seal')
const { verifyImageSeal, checkWebcamAvailability, setupScanner } = require('./verify-image-seal')

async function verifyUpload(file) {
	if (file instanceof FileList) {
		if (file.length == 0) {
			return '<h2>Prüfergebnis: Negativ</h2>'
				+ '<p>Bitte wählen Sie eine Datei aus.</p>'
		}
		if (file.length > 1) {
			return '<h2>Prüfergebnis: Negativ</h2>'
				+ '<p>Bitte wählen Sie nur eine Datei aus.</p>'
		}
		file = file[0]
	}
	if (file.type === 'application/pdf') {
		result = await verifyPdfSeal(file)
		if (typeof result === 'string') {
			return result
		}
		// no string -> couldn't check
		file = await convertPdfToImageFile(file)
	}
	if (file.type.startsWith('image/')) {
		return await verifyImageSeal(file)
	}
	return '<h2>Prüfergebnis: Negativ</h2>'
		+ '<p>Die Datei wurde nicht erkannt. Bitte verwenden Sie nur PDFs oder übliche Bildformate (PNG, JPG etc.).</p>'
}

module.exports = {
	verifyUpload: verifyUpload,
	checkWebcamAvailability: checkWebcamAvailability,
	setupScanner: setupScanner
}