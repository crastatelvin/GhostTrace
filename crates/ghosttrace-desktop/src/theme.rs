//! Design tokens: palettes, metrics, and the egui `Style` they build.
//!
//! The workbench look comes from one small token set per palette (surface,
//! border, text, accent) plus a shared metrics scale (radii, spacing, type
//! size). Widget chrome is styled once in [`style`] so every screen sees the
//! same colors; [`card`], [`section`], [`chip`], [`stat`], [`primary`],
//! [`quiet`], and [`muted`] are where screens consume the tokens.
//!
//! Nothing here encodes meaning in color alone: every state is also spelled
//! out in words (the job bar says "running", a chip says "failed"), so the
//! high-contrast palette keeps working and screen readers are unaffected.

use eframe::egui::{self, Color32, CornerRadius, Margin, Stroke, style::WidgetVisuals};

use crate::state::ThemeChoice;

/// Cards are rounder than the controls inside them.
pub const CARD_RADIUS: u8 = 10;
pub const CONTROL_RADIUS: u8 = 7;

/// Inner margin of a card.
pub const CARD_MARGIN: i8 = 12;
/// Vertical gap between cards and sections.
pub const SECTION_GAP: f32 = 14.0;

/// One complete palette. Screens never invent colors: they read them here or
/// inherit the widget chrome from [`style`].
#[derive(Clone, Copy)]
pub struct Palette {
    /// Application background (outside cards).
    pub window: Color32,
    /// Card / raised surface background.
    pub surface: Color32,
    /// Inset background (text fields, table interiors, code).
    pub inset: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    /// Accent as a line/icon/text color.
    pub accent: Color32,
    /// Accent as a filled background (primary buttons); pairs with
    /// [`Palette::accent_text`].
    pub accent_fill: Color32,
    pub accent_text: Color32,
    /// Accent-tinted background for selected / active chrome.
    pub accent_soft: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub error: Color32,
}

impl Palette {
    pub fn of(theme: ThemeChoice) -> Self {
        match theme {
            // Deep neutral base with a cool blue accent: high-contrast text,
            // quiet chrome, and an accent bright enough to read on the base.
            ThemeChoice::Dark => Self {
                window: Color32::from_rgb(0x0E, 0x14, 0x1B),
                surface: Color32::from_rgb(0x16, 0x1D, 0x26),
                inset: Color32::from_rgb(0x11, 0x18, 0x20),
                border: Color32::from_rgb(0x26, 0x30, 0x39),
                border_strong: Color32::from_rgb(0x37, 0x43, 0x4F),
                text: Color32::from_rgb(0xE7, 0xED, 0xF4),
                text_muted: Color32::from_rgb(0x97, 0xA3, 0xB2),
                accent: Color32::from_rgb(0x6F, 0xA8, 0xFF),
                accent_fill: Color32::from_rgb(0x2C, 0x6B, 0xD1),
                accent_text: Color32::WHITE,
                accent_soft: Color32::from_rgb(0x1B, 0x2E, 0x4A),
                ok: Color32::from_rgb(0x4C, 0xC3, 0x8A),
                warn: Color32::from_rgb(0xE0, 0xB3, 0x41),
                error: Color32::from_rgb(0xFF, 0x6B, 0x5E),
            },
            // Light gray app background so white cards read as raised.
            ThemeChoice::Light => Self {
                window: Color32::from_rgb(0xEE, 0xF1, 0xF5),
                surface: Color32::WHITE,
                inset: Color32::from_rgb(0xF7, 0xF9, 0xFB),
                border: Color32::from_rgb(0xDC, 0xE1, 0xE7),
                border_strong: Color32::from_rgb(0xC3, 0xCB, 0xD3),
                text: Color32::from_rgb(0x1B, 0x24, 0x30),
                text_muted: Color32::from_rgb(0x5D, 0x68, 0x73),
                accent: Color32::from_rgb(0x1F, 0x6F, 0xEB),
                accent_fill: Color32::from_rgb(0x1F, 0x6F, 0xEB),
                accent_text: Color32::WHITE,
                accent_soft: Color32::from_rgb(0xE6, 0xF0, 0xFE),
                ok: Color32::from_rgb(0x15, 0x7F, 0x3C),
                warn: Color32::from_rgb(0xB2, 0x6A, 0x00),
                error: Color32::from_rgb(0xC7, 0x35, 0x2B),
            },
            // Black base, maximum text/stroke contrast, opaque selection: no
            // state relies on hue, and every stroke stays visible.
            ThemeChoice::HighContrast => Self {
                window: Color32::BLACK,
                surface: Color32::BLACK,
                inset: Color32::BLACK,
                border: Color32::from_gray(200),
                border_strong: Color32::WHITE,
                text: Color32::WHITE,
                text_muted: Color32::from_gray(215),
                accent: Color32::from_rgb(0x8F, 0xC0, 0xFF),
                accent_fill: Color32::from_rgb(0x0A, 0x3E, 0x8F),
                accent_text: Color32::WHITE,
                accent_soft: Color32::from_rgb(0x0B, 0x25, 0x45),
                ok: Color32::from_rgb(0x7E, 0xE2, 0xB8),
                warn: Color32::from_rgb(0xFF, 0xD1, 0x66),
                error: Color32::from_rgb(0xFF, 0x8F, 0x85),
            },
        }
    }
}

/// Build the complete egui style for a palette. Widget chrome (buttons,
/// fields, check boxes, combo boxes, scroll bars, selection) is configured
/// here once; screens then only arrange content.
pub fn style(theme: ThemeChoice) -> egui::Style {
    let palette = Palette::of(theme);
    let mut style = match theme {
        ThemeChoice::Light => egui::Style {
            visuals: egui::Visuals::light(),
            ..Default::default()
        },
        _ => egui::Style::default(),
    };
    let high_contrast = matches!(theme, ThemeChoice::HighContrast);
    let stroke_width = if high_contrast { 1.5 } else { 1.0 };

    let visuals = &mut style.visuals;
    visuals.panel_fill = palette.window;
    visuals.window_fill = palette.surface;
    visuals.extreme_bg_color = palette.inset;
    visuals.faint_bg_color = palette.surface;
    visuals.code_bg_color = palette.inset;
    visuals.hyperlink_color = palette.accent;
    visuals.warn_fg_color = palette.warn;
    visuals.error_fg_color = palette.error;
    visuals.window_corner_radius = CornerRadius::same(12);
    visuals.menu_corner_radius = CornerRadius::same(8);

    // Neutral frames (labels, groups, separators).
    visuals.widgets.noninteractive = WidgetVisuals {
        bg_fill: palette.surface,
        weak_bg_fill: palette.surface,
        bg_stroke: Stroke::new(stroke_width, palette.border),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        fg_stroke: Stroke::new(1.0, palette.text_muted),
        expansion: 0.0,
    };
    // Resting controls: inset fill and a hairline border, so a text field
    // reads as a field and a button reads as a button without borders added
    // per widget.
    visuals.widgets.inactive = WidgetVisuals {
        bg_fill: palette.inset,
        weak_bg_fill: palette.surface,
        bg_stroke: Stroke::new(stroke_width, palette.border),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        fg_stroke: Stroke::new(1.0, palette.text),
        expansion: 0.0,
    };
    visuals.widgets.hovered = WidgetVisuals {
        bg_fill: palette.accent_soft,
        weak_bg_fill: palette.accent_soft,
        bg_stroke: Stroke::new(2.0, palette.accent),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        fg_stroke: Stroke::new(1.0, palette.text),
        expansion: 0.0,
    };
    visuals.widgets.active = WidgetVisuals {
        bg_fill: palette.accent_soft,
        weak_bg_fill: palette.accent_soft,
        bg_stroke: Stroke::new(2.0, palette.accent),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        fg_stroke: Stroke::new(1.0, palette.text),
        expansion: 0.0,
    };
    visuals.widgets.open = visuals.widgets.hovered;
    // Selection: an accent-tinted, opaque background with accent text (the
    // text color is what egui draws selected labels with).
    visuals.selection.bg_fill = palette.accent_soft;
    visuals.selection.stroke = Stroke::new(stroke_width, palette.accent);

    let spacing = &mut style.spacing;
    spacing.item_spacing = egui::vec2(7.0, 6.0);
    spacing.button_padding = egui::vec2(10.0, 5.0);
    spacing.window_margin = Margin::same(12);
    spacing.menu_margin = Margin::same(8);
    spacing.combo_width = 200.0;
    spacing.text_edit_width = 260.0;
    spacing.interact_size = egui::vec2(40.0, 22.0);

    // A slightly larger, calmer type scale than the egui defaults.
    let family = egui::FontFamily::Proportional;
    let body = egui::FontId::new(13.5, family.clone());
    if let Some(id) = style.text_styles.get_mut(&egui::TextStyle::Body) {
        *id = body.clone();
    }
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::new(11.5, family.clone()),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(13.0, family.clone()),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(12.0, egui::FontFamily::Monospace),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(17.0, family.clone()),
    );
    style
}

/// A chip tone. The color is a hint; the chip always carries its own text.
#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Neutral,
    Accent,
    Ok,
    Warn,
    Error,
}

impl Tone {
    fn colors(self, palette: &Palette) -> (Color32, Color32, Color32) {
        match self {
            Tone::Neutral => (palette.text_muted, palette.inset, palette.border),
            Tone::Accent => (palette.accent, palette.accent_soft, palette.accent),
            Tone::Ok => (palette.ok, palette.accent_soft, palette.ok),
            Tone::Warn => (palette.warn, palette.accent_soft, palette.warn),
            Tone::Error => (palette.error, palette.accent_soft, palette.error),
        }
    }
}

/// A raised card: surface fill, hairline border, generous inner margin.
pub(crate) fn card<R>(
    ui: &mut egui::Ui,
    theme: ThemeChoice,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let palette = Palette::of(theme);
    egui::Frame::group(ui.style())
        .fill(palette.surface)
        .stroke(Stroke::new(1.0, palette.border))
        .corner_radius(CARD_RADIUS)
        .inner_margin(Margin::same(CARD_MARGIN))
        .show(ui, add)
        .inner
}

/// A section title: same words as before, quieter and slightly smaller, with
/// a rule beneath it. Keeps the text intact so existing accessibility names
/// and search-for-text keep working.
pub(crate) fn section(ui: &mut egui::Ui, theme: ThemeChoice, title: &str) {
    let palette = Palette::of(theme);
    ui.label(
        egui::RichText::new(title)
            .color(palette.text_muted)
            .strong()
            .small(),
    );
    ui.separator();
}

/// A state pill. Not a control; carries words, never color alone.
pub(crate) fn chip(ui: &mut egui::Ui, theme: ThemeChoice, text: impl AsRef<str>, tone: Tone) {
    let palette = Palette::of(theme);
    let (text_color, fill, stroke) = tone.colors(&palette);
    egui::Frame::group(ui.style())
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .corner_radius(u8::MAX)
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(egui::RichText::new(text.as_ref()).color(text_color).small())
                    .selectable(false),
            );
        });
}

/// A metric tile: small muted caption over a large value.
pub(crate) fn stat(ui: &mut egui::Ui, theme: ThemeChoice, label: &str, value: impl Into<String>) {
    let palette = Palette::of(theme);
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(label).color(palette.text_muted).small());
        ui.label(
            egui::RichText::new(value.into())
                .color(palette.text)
                .size(19.0),
        );
    });
}

/// The primary action of a screen: filled accent button.
pub(crate) fn primary(ui: &mut egui::Ui, theme: ThemeChoice, text: &str) -> egui::Response {
    let palette = Palette::of(theme);
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(palette.accent_text))
            .fill(palette.accent_fill)
            .corner_radius(CONTROL_RADIUS),
    )
}

/// A secondary action: neutral surface button with a hairline border.
pub(crate) fn quiet(ui: &mut egui::Ui, theme: ThemeChoice, text: &str) -> egui::Response {
    let palette = Palette::of(theme);
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(palette.text))
            .fill(palette.surface)
            .stroke(Stroke::new(1.0, palette.border))
            .corner_radius(CONTROL_RADIUS),
    )
}

/// Muted explanatory text; same words, lower emphasis.
pub(crate) fn muted(ui: &mut egui::Ui, theme: ThemeChoice, text: impl Into<String>) {
    let palette = Palette::of(theme);
    ui.label(egui::RichText::new(text.into()).color(palette.text_muted));
}

/// Screen title: strong, primary text color.
pub(crate) fn title(ui: &mut egui::Ui, theme: ThemeChoice, text: impl Into<String>) {
    let palette = Palette::of(theme);
    ui.label(
        egui::RichText::new(text.into())
            .heading()
            .strong()
            .color(palette.text),
    );
}

/// The app-bar frame for the header and footer panels.
pub(crate) fn bar_frame(style: &egui::Style, theme: ThemeChoice, inner: f32) -> egui::Frame {
    let palette = Palette::of(theme);
    egui::Frame::side_top_panel(style)
        .fill(palette.surface)
        .inner_margin(Margin::symmetric(14, inner as i8))
}

/// A side panel (the detail/inspector panes) as a quiet surface.
pub(crate) fn side_frame(style: &egui::Style, theme: ThemeChoice) -> egui::Frame {
    let palette = Palette::of(theme);
    egui::Frame::side_top_panel(style)
        .fill(palette.surface)
        .inner_margin(Margin::same(CARD_MARGIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_palette_is_reachable_and_distinct() {
        for theme in ThemeChoice::ALL {
            let palette = Palette::of(theme);
            // Every palette must define real text and accent tokens.
            assert_ne!(palette.text, Color32::TRANSPARENT);
            assert_ne!(palette.accent, Color32::TRANSPARENT);
            assert_ne!(palette.accent_fill, Color32::TRANSPARENT);
        }
        let dark = Palette::of(ThemeChoice::Dark);
        let light = Palette::of(ThemeChoice::Light);
        assert_ne!(dark.surface, light.surface);
        assert_ne!(dark.text, light.text);
    }

    #[test]
    fn high_contrast_stays_opaque_and_white_on_black() {
        let palette = Palette::of(ThemeChoice::HighContrast);
        assert_eq!(palette.surface, Color32::BLACK);
        assert_eq!(palette.text, Color32::WHITE);
        assert!(palette.accent_soft.a() == 255, "selection must stay opaque");
        let style = style(ThemeChoice::HighContrast);
        assert!(style.visuals.selection.bg_fill.a() == 255);
        assert!(style.visuals.selection.stroke.width >= 1.5);
    }

    #[test]
    fn the_type_scale_is_complete() {
        for theme in ThemeChoice::ALL {
            let style = style(theme);
            for variant in [egui::TextStyle::Heading, egui::TextStyle::Body] {
                assert!(style.text_styles.contains_key(&variant), "{variant:?}");
            }
        }
    }
}
