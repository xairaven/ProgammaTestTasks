use crate::backend::info::InfectedHostInfo;
use crate::context::Context;
use egui::{CentralPanel, Panel, ScrollArea};

#[derive(Debug, Default)]
pub struct OutputComponent {
    buffer: String,
}

impl OutputComponent {
    pub fn show(&mut self, ui: &mut egui::Ui, _context: &mut Context) {
        Panel::bottom("CLEAR_OUTPUT")
            .show_separator_line(false)
            .show_inside(ui, |ui| {
                ui.vertical_centered_justified(|ui| {
                    if ui.button("Clear Output").clicked() {
                        self.buffer.clear();
                    }
                });
            });

        CentralPanel::default().show_inside(ui, |ui| {
            ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.label(&self.buffer);
                });
        });
    }

    pub fn add_info(&mut self, info: InfectedHostInfo) {
        let text = info.to_string();
        self.buffer.push_str(&text);
        self.buffer.push('\n')
    }

    pub fn add_progress(&mut self, progress: String) {
        self.buffer.push_str(&progress);
        self.buffer.push('\n');
    }
}
