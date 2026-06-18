use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

pub fn render_qr_code<D: AsRef<[u8]>>(data: D) -> Result<String, anyhow::Error> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L)?;
    Ok(code.render::<Dense1x2>().build())
}
