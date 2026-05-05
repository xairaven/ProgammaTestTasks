use crate::context::Context;
use egui::{Color32, Panel, RichText, ScrollArea};

#[derive(Debug)]
pub struct SettingsComponent {
    pub width: f32,
    pub attacker_ip: String,
}

impl Default for SettingsComponent {
    fn default() -> Self {
        Self {
            width: 250.0,
            attacker_ip: String::new(),
        }
    }
}

impl SettingsComponent {
    pub fn show(&mut self, ui: &mut egui::Ui, context: &mut Context) {
        Panel::left("SETTINGS_PANEL")
            .resizable(false)
            .default_size(self.width)
            .min_size(self.width)
            .max_size(self.width)
            .show_separator_line(true)
            .show_inside(ui, |ui| {
                ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered_justified(|ui| {
                        ui.heading(RichText::new("Settings").color(Color32::WHITE));
                    });
                    ui.add_space(10.0);
                });
            });
    }
}
