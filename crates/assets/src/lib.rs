//! The avatar pipeline. Every picture is decoded under strict limits and re-encoded from pixels, so nothing of the
//! uploaded file survives except the image itself: no metadata (EXIF, GPS, comments), no second payload hidden in a
//! polyglot file, no animation. Output: a square 400×400 image, JPEG (photographs) or PNG (pictures with
//! transparency), at most [`MAX_OUTPUT_BYTES`].

use std::io::Cursor;

use image::{DynamicImage, GenericImageView, ImageFormat, ImageReader, Limits, imageops::FilterType};
use sha2::{Digest, Sha256};

/// Longest upload accepted, before decoding.
pub const MAX_INPUT_BYTES: usize = 5 * 1024 * 1024;
/// Largest picture dimension accepted, before decoding (ten times the output side is plenty for a 400 × 400 picture).
pub const MAX_INPUT_SIDE: u32 = 4096;
/// The most memory one decode may allocate. Decoding and the square crop each hold a copy, so one picture costs at most
/// twice this: the app's pods (192 MiB) process one picture at a time (`link-in-bio-api`'s upload limit).
pub const MAX_DECODE_BYTES: u64 = 64 * 1024 * 1024;
/// Output side length.
pub const SIDE: u32 = 400;
/// Largest stored picture.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AvatarError {
    #[error("The picture is too large: at most 5 MiB.")]
    TooLarge,
    #[error("This is not a picture this service reads (PNG, JPEG, WebP or GIF).")]
    Unsupported,
    #[error("The picture could not be read.")]
    Corrupt,
    #[error("The picture is too large in pixels: at most 4096 on each side.")]
    TooManyPixels,
    #[error("The picture could not be made small enough.")]
    CannotShrink,
}

/// A normalised picture.
#[derive(Debug, Clone)]
pub struct Avatar {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
    pub ext: &'static str,
    pub width: u32,
    pub height: u32,
    /// Hex SHA-256 of `bytes` (the asset reference is `sha256:<this>`).
    pub sha256: String,
}

/// Normalises an uploaded raster picture (tenants and operators).
pub fn normalise_raster(input: &[u8]) -> Result<Avatar, AvatarError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(AvatarError::TooLarge);
    }
    let format = image::guess_format(input).map_err(|_| AvatarError::Unsupported)?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP | ImageFormat::Gif) {
        return Err(AvatarError::Unsupported);
    }
    let mut reader = ImageReader::with_format(Cursor::new(input), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_INPUT_SIDE);
    limits.max_image_height = Some(MAX_INPUT_SIDE);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    reader.limits(limits);
    let img = reader.decode().map_err(|e| match e {
        image::ImageError::Limits(_) => AvatarError::TooManyPixels,
        _ => AvatarError::Corrupt,
    })?;
    encode(square(img))
}

/// Rasterises the operator's own SVG (for example a brand mark). Never used for tenant uploads.
pub fn normalise_operator_svg(input: &[u8]) -> Result<Avatar, AvatarError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(AvatarError::TooLarge);
    }
    let opts = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_data(input, &opts).map_err(|_| AvatarError::Corrupt)?;
    let size = tree.size();
    let scale = SIDE as f32 / size.width().max(size.height());
    let mut pixmap = resvg::tiny_skia::Pixmap::new(SIDE, SIDE).ok_or(AvatarError::Corrupt)?;
    let dx = (SIDE as f32 - size.width() * scale) / 2.0;
    let dy = (SIDE as f32 - size.height() * scale) / 2.0;
    let transform = resvg::tiny_skia::Transform::from_row(scale, 0.0, 0.0, scale, dx, dy);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    // tiny-skia stores premultiplied RGBA; demultiply for the encoder.
    let mut rgba = Vec::with_capacity((SIDE * SIDE * 4) as usize);
    for p in pixmap.pixels() {
        let c = p.demultiply();
        rgba.extend_from_slice(&[c.red(), c.green(), c.blue(), c.alpha()]);
    }
    let img = image::RgbaImage::from_raw(SIDE, SIDE, rgba).ok_or(AvatarError::Corrupt)?;
    encode(DynamicImage::ImageRgba8(img))
}

/// Centre-crops to a square and resizes to [`SIDE`].
fn square(img: DynamicImage) -> DynamicImage {
    let (w, h) = img.dimensions();
    let side = w.min(h);
    let cropped = img.crop_imm((w - side) / 2, (h - side) / 2, side, side);
    cropped.resize_exact(SIDE, SIDE, FilterType::Lanczos3)
}

fn has_transparency(img: &DynamicImage) -> bool {
    img.color().has_alpha() && img.to_rgba8().pixels().any(|p| p.0[3] < 255)
}

fn encode(img: DynamicImage) -> Result<Avatar, AvatarError> {
    let (bytes, mime, ext) = if has_transparency(&img) {
        let mut out = Vec::new();
        img.to_rgba8().write_to(&mut Cursor::new(&mut out), ImageFormat::Png).map_err(|_| AvatarError::Corrupt)?;
        (out, "image/png", "png")
    } else {
        let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
        let mut found = None;
        for quality in [85u8, 75, 65, 55, 45] {
            let mut out = Vec::new();
            let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
            rgb.write_with_encoder(enc).map_err(|_| AvatarError::Corrupt)?;
            if out.len() <= MAX_OUTPUT_BYTES {
                found = Some(out);
                break;
            }
        }
        (found.ok_or(AvatarError::CannotShrink)?, "image/jpeg", "jpg")
    };
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(AvatarError::CannotShrink);
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(Avatar { bytes, mime, ext, width: SIDE, height: SIDE, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32, alpha: u8) -> Vec<u8> {
        let img = image::RgbaImage::from_fn(w, h, |x, y| image::Rgba([(x % 256) as u8, (y % 256) as u8, 90, alpha]));
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).unwrap();
        out
    }

    #[test]
    fn photographs_become_square_jpegs_without_metadata() {
        let a = normalise_raster(&png(1200, 800, 255)).unwrap();
        assert_eq!((a.width, a.height, a.mime), (400, 400, "image/jpeg"));
        assert!(a.bytes.len() <= MAX_OUTPUT_BYTES);
        // A JPEG straight from the encoder: SOI then the JFIF APP0 segment, no EXIF APP1.
        assert_eq!(&a.bytes[..2], &[0xFF, 0xD8]);
        assert!(!a.bytes.windows(4).any(|w| w == b"Exif"));
    }

    #[test]
    fn transparency_is_kept_as_png() {
        let a = normalise_raster(&png(300, 300, 128)).unwrap();
        assert_eq!(a.mime, "image/png");
    }

    #[test]
    fn refuses_non_images_svg_and_polyglots() {
        assert_eq!(
            normalise_raster(b"<svg xmlns='http://www.w3.org/2000/svg'/>").unwrap_err(),
            AvatarError::Unsupported
        );
        assert_eq!(normalise_raster(b"%PDF-1.7").unwrap_err(), AvatarError::Unsupported);
        // A PNG signature followed by garbage is not a picture.
        let mut fake = png(10, 10, 255)[..16].to_vec();
        fake.extend_from_slice(b"<script>alert(1)</script>");
        assert_eq!(normalise_raster(&fake).unwrap_err(), AvatarError::Corrupt);
        // Whatever trails a real PNG is dropped by re-encoding.
        let mut poly = png(50, 50, 255);
        poly.extend_from_slice(b"<html><script>alert(1)</script>");
        let a = normalise_raster(&poly).unwrap();
        assert!(!a.bytes.windows(8).any(|w| w == b"<script>"));
    }

    /// A PNG whose header claims `w` × `h` pixels of RGBA at `depth` bits (its image data is an empty zlib stream: only
    /// the header matters here).
    fn png_header(w: u32, h: u32, depth: u8) -> Vec<u8> {
        fn crc32(data: &[u8]) -> u32 {
            let mut c = 0xFFFF_FFFFu32;
            for b in data {
                c ^= u32::from(*b);
                for _ in 0..8 {
                    c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        }
        fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let mut body = kind.to_vec();
            body.extend_from_slice(data);
            out.extend_from_slice(&body);
            out.extend_from_slice(&crc32(&body).to_be_bytes());
        }
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut ihdr = w.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[depth, 6, 0, 0, 0]);
        chunk(&mut out, b"IHDR", &ihdr);
        chunk(&mut out, b"IDAT", &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        chunk(&mut out, b"IEND", &[]);
        out
    }

    #[test]
    fn pictures_too_large_to_decode_safely_are_refused_before_decoding() {
        // Over the side limit: refused from the header, before any pixel buffer exists.
        assert_eq!(normalise_raster(&png_header(MAX_INPUT_SIDE + 1, 10, 8)).unwrap_err(), AvatarError::TooManyPixels);
        assert_eq!(normalise_raster(&png_header(10, 8192, 8)).unwrap_err(), AvatarError::TooManyPixels);
        // Within each side but over the decode budget (4096 × 4096 RGBA at 16 bits is 128 MiB).
        let deep = png_header(MAX_INPUT_SIDE, MAX_INPUT_SIDE, 16);
        assert_eq!(normalise_raster(&deep).unwrap_err(), AvatarError::TooManyPixels);
        // The budget holds two copies of the largest 8-bit picture well inside the app pod's 192 MiB.
        const {
            assert!(MAX_INPUT_SIDE as u64 * MAX_INPUT_SIDE as u64 * 4 <= MAX_DECODE_BYTES);
            assert!(2 * MAX_DECODE_BYTES < 192 * 1024 * 1024);
        }
    }

    #[test]
    fn operator_svg_is_rasterised() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#86321d"/></svg>"##;
        let a = normalise_operator_svg(svg).unwrap();
        assert_eq!((a.width, a.mime), (400, "image/png"));
    }
}
