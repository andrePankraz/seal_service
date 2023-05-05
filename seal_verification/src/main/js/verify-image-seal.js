/**
 * @fileoverview This file was created by ]init[ AG 2023.
 * 
 * This file contains all methods for validating visual signatures (DataMatrix).
 */
const { Image } = require('image-js')
const { Html5Qrcode, Html5QrcodeScanner, Html5QrcodeSupportedFormats, Html5QrcodeScanType } = require('html5-qrcode')

class Decoder {

	constructor(text) {
		const data = new Uint8Array(text.length)
		// Special UTF-16 char mappings below 0xff
		const encodeList = { 0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87, 0x02C6: 0x88, 0x2030: 0x89, 0x0160: 0x8A, 0x2039: 0x8B, 0x0152: 0x8C, 0x017D: 0x8E, 0x2018: 0x91, 0x2019: 0x92, 0x201C: 0x93, 0x201D: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97, 0x02DC: 0x98, 0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B, 0x0153: 0x9C, 0x017E: 0x9E, 0x0178: 0x9F }
		for (let i = 0; i < text.length; i++) {
			const b = text.charCodeAt(i)
			// decode UTF-16 char - some speciall chars below 0xff are automatically mapped to high UTF-16 chars with 2 bytes 
			const bDecoded = encodeList[b]
			data[i] = bDecoded === undefined ? b : bDecoded
		}
		this.data = data
	}

	/**
	 * Decode.
	 * 
	 * @returns {boolean|string} true or string with user fault message
	 */
	async decode() {
		this.pos = 0

		// ##########
		// # Header #
		// ##########
		this.magicConstant = this.decodeByte()
		if (this.magicConstant != 0xdc) {
			throw new Error(`Magic Constant isn't 0xdc, but is 0x${this.magicConstant.toString(16)}!`)
		}
		this.version = this.decodeByte() + 1
		if (this.version != 3 && this.version != 4) {
			throw new Error(`Version isn't 3 or 4, but is ${this.version.toString(10)}!`)
		}
		this.issuingCountry = this.decodeC40(2).replaceAll(' ', '<')
		if (this.issuingCountry != 'D<<') {
			throw new Error(`Issuing Country isn't 'D<<', but is ${this.issuingCountry}!`)
		}
		if (this.version == 3) {
			const signerCert = this.decodeC40(6)
			this.signerIdentifier = signerCert.substring(0, 4)
			this.certificateReference = signerCert.substring(4)
		} else if (this.version == 4) {
			const signerCert = this.decodeC40(4)
			this.signerIdentifier = signerCert.substring(0, 4)
			const l = parseInt(signerCert.substring(4))
			this.certificateReference = this.decodeC40(Math.ceil(l * 2 / 3)).substring(0, l)
		}
		this.documentIssueDate = this.decodeDate()
		this.signatureCreationDate = this.decodeDate()
		this.documentFeatureDefinitionReference = this.decodeByte()
		this.documentTypeCategory = this.decodeByte()

		// ################
		// # Message Zone #
		// ################
		this.docProfileNr = this.decodeMessageC40(0x00)

		// All following values are dynamic, dependent of a XML profile with docProfileNr
		const profileXml = await this.fetchProfile(this.docProfileNr)
		if (profileXml === null) {
			return `Das Siegel enthält eine unkannte Dokumentenprofilnummer '${this.docProfileNr}'.`
		}
		const domParser = new DOMParser()
		const domProfile = domParser.parseFromString(profileXml, 'application/xml')

		const values = new Map()
		for (let tag = this.peekMessageTag(); tag !== 0xff; tag = this.peekMessageTag()) {
			const entry = domProfile.querySelector(`entry[tag="${tag}"]`)
			if (entry === null) {
				return `Das Siegel enthält ein unkanntes Nachrichtentag '${tag}'.`
			}
			const type = entry.querySelector("type").textContent
			let value
			switch (type) {
				case 'alphanum':
					value = this.decodeMessageC40(tag)
					break
				case 'string':
					value = this.decodeMessageString(tag)
					break
				case 'multistring':
					value = this.decodeMessageString(tag)
					break
				case 'binary':
					value = this.decodeMessageBytes(tag)
					break
				case 'date':
					value = this.decodeMessageDate(tag)
					break
			}
			const name = entry.querySelector("name").textContent
			values.set(tag, { 'name': name, 'value': value })
		}
		// Check required fields
		const entries = domProfile.querySelectorAll('entry[optional="false"]')
		entries.forEach(entry => {
			const tag = entry.getAttribute("tag")
			if (!values.has(parseInt(tag))) {
				throw new Error(`Value for tag ${tag} is missing.`)
			}
		})
		this.values = values

		// ##################
		// # Signature Zone #
		// ##################
		this.signaturePos = this.pos
		this.signature = this.decodeMessageSignature()
		const publicKey = await this.fetchPublicKey(this.certificateReference)
		if (publicKey === null) {
			return `Das Siegel enthält eine unkannte Zertifikatsreferenz '${this.certificateReference}'.`
		}
		this.signatureValid = await this.verifySignature(this.data.subarray(0, this.signaturePos), this.signature, publicKey)

		// Debugging: Log info...
		if (false) {
			console.log('Header:')
			console.log(`  Aussteller: ${this.signerIdentifier}`)
			console.log(`  Zertifikat: ${this.certificateReference}`)
			console.log(`  Ausstelldatum: ${this.documentIssueDate}`)
			console.log(`  Signierdatum: ${this.signatureCreationDate}`)

			console.log('Message:')
			console.log(`  Dokumentenprofilnummer: ${this.docProfileNr}`)
			for (const [key, value] of this.values.entries()) {
				console.log(`  ${key} - ${value.name}: ${value.value}`)
			}

			console.log('Signature:')
			console.log(`  Signature valid: ${this.signatureValid}`)
		}
		return true
	}

	decodeByte() {
		return this.data[this.pos++]
	}

	decodeBytes(l) {
		return this.data.subarray(this.pos, this.pos += l)
	}

	decodeC40(l) {
		let text = ''
		for (let i = 0; i < l; i += 2) {
			// see Annex B in https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03137/BSI-TR-03137_Part1.pdf
			const i1 = this.decodeByte()
			const i2 = this.decodeByte()
			if (i1 == 0xfe) {
				text += String.fromCharCode(i2 - 1)
				continue
			}
			const v16 = (i1 << 8) + i2
			const u1 = Math.floor((v16 - 1) / 1600)
			const u2 = Math.floor((v16 - (u1 * 1600) - 1) / 40)
			const u3 = v16 - (u1 * 1600) - (u2 * 40) - 1
			if (u3 == 0) {
				text += String.fromCharCode(Decoder.decodeC40char(u1), Decoder.decodeC40char(u2))
				continue
			}
			text += String.fromCharCode(Decoder.decodeC40char(u1), Decoder.decodeC40char(u2), Decoder.decodeC40char(u3))
		}
		return text
	}

	static decodeC40char(c) {
		if (c >= 4 && c <= 13) {
			return c - 4 + '0'.charCodeAt()
		}
		if (c >= 14 && c <= 39) {
			return c - 14 + 'A'.charCodeAt()
		}
		return ' '.charCodeAt() // Decode as space
	}

	decodeDate() {
		// A date is first converted into a positive integer by concatenating the month, the days, and the (four digit) year.
		// This positive integer is then concatenated into a sequence of three bytes.
		const i1 = this.decodeByte()
		const i2 = this.decodeByte()
		const i3 = this.decodeByte()
		const v24 = (i1 << 16) + (i2 << 8) + i3
		// day|month|year -> Date(year, month, day)
		return new Date(v24 % 10000, Math.floor(v24 / 1000000) % 100 - 1, Math.floor(v24 / 10000) % 100)
	}

	decodeMessageBytes(tag) {
		this.decodeMessageTag(tag)
		const l = this.decodeMessageLength()
		return this.decodeBytes(l)
	}

	decodeMessageC40(tag) {
		this.decodeMessageTag(tag)
		const l = this.decodeMessageLength()
		return this.decodeC40(l)
	}

	decodeMessageDate(tag) {
		this.decodeMessageTag(tag)
		const l = this.decodeMessageLength()
		if (l != 3) {
			throw new Error(`Date must have length 3, but is ${l.toString(10)}!`)
		}
		return this.decodeDate()
	}

	decodeMessageLength() {
		const b = this.decodeByte()
		if (b <= 0x7f) {
			return b
		}
		if (b == 0x81) {
			return this.decodeByte()
		}
		if (b == 0x82) {
			return this.decodeByte() << 8 + this.decodeByte()
		}
		if (b == 0x83) {
			return this.decodeByte() << 16 + this.decodeByte() << 8 + this.decodeByte()
		}
		throw new Error(`Cannot decode length with 0x${b.toString(16)}!`)
	}

	decodeMessageSignature() {
		this.decodeMessageTag(0xff)
		const l = this.decodeMessageLength()
		return this.decodeBytes(l)
	}

	decodeMessageString(tag) {
		this.decodeMessageTag(tag)
		const l = this.decodeMessageLength()
		return new TextDecoder().decode(this.decodeBytes(l))
	}

	decodeMessageTag(tag) {
		const foundTag = this.decodeByte()
		if (tag != foundTag) {
			throw new Error(`Tag isn't 0x${tag.toString(16)}, but is 0x${foundTag.toString(16)}!`)
		}
	}

	/**
	 * Get next message tag without increasing stream position.

	 * @returns {number} next message tag
	 */
	peekMessageTag() {
		return this.data[this.pos]
	}

	async fetchProfile(docProfileNr) {
		const response = await fetch(`/seal_verification/profile?doc_profile_nr=${docProfileNr}`)
		if (!response.ok) {
			if (response.status === 404) {
				return null
			}
			throw new Error(`HTTP error: ${response.status}`)
		}
		return await response.text()
	}

	/**
	 * Fetch ECDSA signature public key for a given serial number from server and convert to ECDSA public key.
	 * 
	 * @param {string} serialNumber - Serial number of ECDSA signature public key ("001", "002", ...)
	 * @returns {Promise<PublicKey>} ECDSA signature public key
	 * @throws {Error} Cannot read public key for given serial number
	 */
	async fetchPublicKey(serialNumber) {
		const response = await fetch(`/seal_verification/visual_public_key?serial_number=${serialNumber}`)
		if (!response.ok) {
			if (response.status === 404) {
				return null
			}
			throw new Error(`HTTP error: ${response.status}`)
		}
		const pemContents = await response.text()
		const binaryDerString = window.atob(pemContents)
		const binaryDer = new Uint8Array(binaryDerString.length)
		for (let i = 0; i < binaryDerString.length; i++) {
			binaryDer[i] = binaryDerString.charCodeAt(i)
		}
		return await window.crypto.subtle.importKey('spki', binaryDer.buffer, {
			name: 'ECDSA',
			namedCurve: 'P-256'
		}, true, ['verify'])
	}

	/**
	 * Verify content hash signature against ECDSA signature public key for given serial number.
	 * 
	 * @param {Uint8Array} content - Content
	 * @param {Uint8Array} signature - Signature
	 * @param {PublicKey} publicKey - ECDSA signature public key
	 * @returns {Promise<boolean>} Content signature and ECDSA public key don't match.
	 * @throws {Error} Cannot read public key for given serial number
	 */
	async verifySignature(content, signature, publicKey) {
		const verify = await window.crypto.subtle.verify({
			name: 'ECDSA',
			hash: {
				name: 'SHA-256'
			}
		}, publicKey, signature, content)
		return verify
	}

}

function attr2html(value) {
	if (value instanceof Date) {
		const options = { day: '2-digit', month: '2-digit', year: 'numeric' }
		return value.toLocaleDateString('de-DE', options)
	}
	return value
}

async function fetchDocumentValid(documentNumber) {
	const response = await fetch(`/seal_verification/valid?document_number=${documentNumber}`)
	if (!response.ok) {
		// No 404 possible, unknown documentNumbers are automatically acknowledged with valid (true)
		throw new Error(`HTTP error: ${response.status}`)
	}
	return await response.json()
}

async function decodeToHtml(decodedText, result) {
	const decoder = new Decoder(decodedText)
	const decodeResult = await decoder.decode()
	if (typeof decodeResult === 'string') {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ `<p>${decodeResult}</p>`
	}
	if (!decoder.signatureValid) {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ '<p>Der QR-Code wurde erkannt, aber die darin enthaltene digitale Unterschrift ist ungültig!'
			+ ' Der QR-Code wurde manipuliert bzw. nicht durch die ZAB ausgestellt.</p>'
	}
	// TODO make configurable, where the documentNumber is
	const documentNumber = decoder.values.get(4).value
	const documentValid = await fetchDocumentValid(documentNumber)
	if (!documentValid) {
		return '<h2>Prüfergebnis: Negativ</h2>'
			+ '<p>Der QR-Code wurde korrekt erkannt,'
			+ ` aber die Zeugnisbewertung für die Urkundennummer ${documentNumber} wurde zurückgezogen!</p>`
	}
	let html = '<h2>Prüfergebnis: Positiv</h2>'
	html += '<p>Die visuelle Signatur ("QR-Code") ist gültig.'
		+ ' Bitte vergleichen Sie folgende Angaben aus dem QR-Code mit dem Dokument.'
		+ ' Nur wenn die Angaben übereinstimmen, ist das gesamte Dokument mit dem QR-Code gültig!</p>'
	html += '<dl id="key-value-list">'
	html += `<dt>Aussteller</dt><dd>ZAB</dd>` // In seal it's DEZB, but we know, because signature fine
	html += `<dt>Ausstellungsdatum</dt><dd>${attr2html(decoder.documentIssueDate)}</dd>`
	for (const [_, value] of decoder.values.entries()) {
		html += `<dt>${value.name}</dt><dd>${attr2html(value.value)}</dd>`
	}
	html += '</dl>'
	html += '<p>Sollten die Angaben nicht übereinstimmen, so wurde der QR-Code für eine andere Person ausgestellt.'
	return html + '</p>'
}

function readFileAsync(file) {
	return new Promise((resolve, reject) => {
		const reader = new FileReader()
		reader.onload = _ => {
			resolve(reader.result)
		}
		reader.onerror = reject
		reader.readAsArrayBuffer(file)
	})
}

async function cropToDataMatrix(file) {
	const imgArrayBuffer = await readFileAsync(file)
	const image = await Image.load(imgArrayBuffer)

	let imageFiltered = image

	if (imageFiltered.bitDepth == 1) {
		// Convert binary monochrome to grayscale for following ops
		imageFiltered = imageFiltered.colorDepth(8)
	}

	// Convert to greyscale
	imageFiltered = imageFiltered.grey()

	// Rot away small structures (like writing) and emphasize thicker areas (like Datamatrix)
	const kernelSize = 7
	const kernel = new Array(kernelSize).fill(new Array(kernelSize).fill(1))
	imageFiltered = imageFiltered.open({ kernel })

	// Blur -> blacks in sparse areas (like writing) get lighter in color
	imageFiltered = imageFiltered.blurFilter({ radius: 3 })

	// Now threshhold this lighter colors
	let mask = imageFiltered.mask({ threshold: 25, invert: true })

	// Get the Region of Interest (ROI) Manager from mask
	const roiManager = imageFiltered.getRoiManager()
	roiManager.fromMask(mask)
	const rois = roiManager.getRois({
		negative: false,
		minSurface: 100
	})

	// Find the region with the highest concentration of non-white pixels
	let maxRoi = null
	let maxSurface = 0
	for (const roi of rois) {
		// console.log(roi)
		const surface = roi.surface
		if (surface > maxSurface) {
			maxSurface = surface
			maxRoi = roi
		}
	}

	// Crop to this region
	const padding = 20
	const cropX = Math.max(0, maxRoi.minX - padding)
	const cropY = Math.max(0, maxRoi.minY - padding)
	const cropWidth = Math.min(image.width - cropX, maxRoi.maxX - maxRoi.minX + padding + padding)
	const cropHeight = Math.min(image.height - cropY, maxRoi.maxY - maxRoi.minY + padding + padding)
	datamatrixImage = image.crop({
		x: cropX,
		y: cropY,
		width: cropWidth,
		height: cropHeight
	})
	const buffer = datamatrixImage.toBuffer({ format: 'png' })
	file = new File([buffer], 'datamatrix.png', { type: 'image/png' })

	// Debugging: Draw converted image(s)...
	if (false) {
		console.log('Region with the most concentration of visual pixels:', maxRoi)

		const showImage = datamatrixImage.clone()

		const points = [
			[maxRoi.minX, maxRoi.minY],
			[maxRoi.minX, maxRoi.maxY],
			[maxRoi.maxX, maxRoi.maxY],
			[maxRoi.maxX, maxRoi.minY]]
		showImage.paintPolygon(points, {
			color: [100],
			filled: false
		})

		let debugElement = document.getElementById('debug')
		if (debugElement) {
			debugElement.innerHTML = ''
		} else {
			debugElement = document.createElement('div')
			debugElement.id = 'debug'
			document.getElementById('result').appendChild(debugElement)
		}

		const canvasElement = document.createElement("canvas")
		canvasElement.width = showImage.width
		canvasElement.height = showImage.height
		let ctx = canvasElement.getContext('2d')
		const imageData = new ImageData(
			new Uint8ClampedArray(showImage.getRGBAData()),
			showImage.width,
			showImage.height
		)
		ctx.putImageData(imageData, 0, 0)
		debugElement.appendChild(canvasElement)
	}
	return file
}

async function verifyImageSeal(file) {
	const qrcodeElement = document.createElement('div')
	qrcodeElement.id = 'qrcodeElement'
	qrcodeElement.hidden = true
	document.body.appendChild(qrcodeElement)
	try {
		const qrcode = new Html5Qrcode('qrcodeElement', {
			formatsToSupport: [Html5QrcodeSupportedFormats.DATA_MATRIX],
			useBarCodeDetectorIfSupported: true
		})
		try {
			// First try to recognize DataMatrix directly with ZXing
			const { decodedText, result } = await qrcode.scanFileV2(file)
			return await decodeToHtml(decodedText, result)
		} catch (error) {
			if (error.constructor.name === 'NotFoundException') {
				// Datamatrix must be centered for ZXing, or it wount find it!
				// Try to find and crop image file to Datamatrix area with Computer Vision (CV) first... 
				file = await cropToDataMatrix(file)
				// Now try again...
				try {
					const { decodedText, result } = await qrcode.scanFileV2(file)
					return await decodeToHtml(decodedText, result)
				} catch (error) {
					if (error.constructor.name === 'NotFoundException') {
						return '<h2>Prüfergebnis: Negativ</h2>'
							+ '<p>Es konnte kein QR-Code erkannt werden.</p>'
					}
					throw error
				}
			}
			throw error
		}
	} finally {
		qrcodeElement.remove()
	}
}

async function checkWebcamAvailability() {
	if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
		console.log("Diese Browser-Version unterstützt nicht enumerateDevices().")
		return false
	}
	try {
		const devices = await navigator.mediaDevices.enumerateDevices()
		for (const device of devices) {
			if (device.kind === 'videoinput') {
				return true
			}
		}
	} catch (error) {
		console.error('Fehler beim Abrufen der Geräteliste:', error)
		return false
	}
}

function qrboxFunction(viewfinderWidth, viewfinderHeight) {
	// Square QR Box, with size = 80% of the min edge.
	var minEdgeSizeThreshold = 250
	var edgeSizePercentage = 0.75
	var minEdgeSize = (viewfinderWidth > viewfinderHeight) ?
		viewfinderHeight : viewfinderWidth
	var qrboxEdgeSize = Math.floor(minEdgeSize * edgeSizePercentage)
	if (qrboxEdgeSize < minEdgeSizeThreshold) {
		if (minEdgeSize < minEdgeSizeThreshold) {
			return { width: minEdgeSize, height: minEdgeSize }
		} else {
			return {
				width: minEdgeSizeThreshold,
				height: minEdgeSizeThreshold
			}
		}
	}
	return { width: qrboxEdgeSize, height: qrboxEdgeSize }
}

function setupScanner(elementId, onScannerSuccess, onScannerError) {
	const html5QrcodeScanner = new Html5QrcodeScanner(
		elementId,
		{
			fps: 10,
			qrbox: qrboxFunction,
			formatsToSupport: [Html5QrcodeSupportedFormats.DATA_MATRIX],
			experimentalFeatures: {
				useBarCodeDetectorIfSupported: true
			},
			rememberLastUsedCamera: true,
			supportedScanTypes: [Html5QrcodeScanType.SCAN_TYPE_CAMERA],
			showTorchButtonIfSupported: true
		})
	const successCallback = async (decodedText, result) => {
		onScannerSuccess(await decodeToHtml(decodedText, result))
	}
	const errorCallback = (errorMessage, error) => {
		if (errorMessage === 'QR code parse error, error = NotFoundException: No MultiFormat Readers were able to detect the code.') {
			// Will be triggered all 1/FPS seconds ==> no Webcam area
			return
		}
		onScannerError(new Error(errorMessage))
	}
	html5QrcodeScanner.render(successCallback, errorCallback)
}

module.exports = {
	verifyImageSeal: verifyImageSeal,
	checkWebcamAvailability: checkWebcamAvailability,
	setupScanner: setupScanner
}