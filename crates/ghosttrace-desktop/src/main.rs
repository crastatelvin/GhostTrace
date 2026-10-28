//! GhostTrace desktop entry point.
//!
//! The application shell lives in the library crate so the workflow and job
//! tests can drive it headlessly (plan P6.1).

use eframe::Renderer;
use ghosttrace_desktop::app::DesktopApp;

/// Default renderer: glow when compiled in (smaller binary, widest Linux
/// driver coverage), else wgpu. See docs/adr/0001-native-rust-ui.md.
#[cfg(feature = "glow")]
const DEFAULT_RENDERER: Renderer = Renderer::Glow;
#[cfg(all(not(feature = "glow"), feature = "wgpu"))]
const DEFAULT_RENDERER: Renderer = Renderer::Wgpu;

struct Options {
    renderer: Renderer,
}

fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        renderer: DEFAULT_RENDERER,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--renderer" => {
                options.renderer = match args.next().as_deref() {
                    #[cfg(feature = "glow")]
                    Some("glow") => Renderer::Glow,
                    #[cfg(feature = "wgpu")]
                    Some("wgpu") => Renderer::Wgpu,
                    other => return Err(format!("unknown --renderer value: {other:?}")),
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(options)
}

fn main() -> eframe::Result<()> {
    let options = match parse_args() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}");
            // Exit 2 = invalid usage, per the CLI exit-code policy.
            std::process::exit(2);
        }
    };
    let native_options = eframe::NativeOptions {
        renderer: options.renderer,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_title("GhostTrace"),
        ..Default::default()
    };
    eframe::run_native(
        "GhostTrace",
        native_options,
        Box::new(|_cc| Ok(Box::new(DesktopApp::new()))),
    )
}
