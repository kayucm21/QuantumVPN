package com.quantumvpn.importer

import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.ScanOptions

/** Intent-only scanner host. It is opened exclusively after an explicit user action. */
class QrCaptureActivity : CaptureActivity()

fun qrImportScanOptions(): ScanOptions = ScanOptions()
    .setCaptureActivity(QrCaptureActivity::class.java)
    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
    .setPrompt("Наведите камеру на QR с профилем или ссылкой")
    .setBeepEnabled(false)
    .setBarcodeImageEnabled(false)
    .setOrientationLocked(false)
