use supports_unicode::Stream;

use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

pub fn log_qr_code_or_url(url: &str) {
    if supports_unicode::on(Stream::Stderr) {
        match render_qr_code(url.as_bytes()) {
            Ok(qr) => log::info!(
                "please scan the QR code or visit the following link to auth corplink:\n{url}\n{qr}"
            ),
            Err(e) => {
                log::info!("please visit the following link to auth corplink:\n{url}");
                log::warn!("failed to generate qr code: {e}");
            }
        }
    } else {
        log::info!("please visit the following link to auth corplink:\n{url}");
        log::info!(
            "unicode QR code output is not supported by this terminal; use Windows Terminal or another Unicode-capable terminal for a better login experience"
        );
    }
}

fn render_qr_code<D: AsRef<[u8]>>(data: D) -> Result<String, anyhow::Error> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L)?;
    Ok(code.render::<Dense1x2>().build())
}
