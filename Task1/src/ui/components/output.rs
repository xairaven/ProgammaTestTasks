use crate::context::Context;
use egui::{CentralPanel, Panel};

#[derive(Debug, Default)]
pub struct OutputComponent {
    buffer: String,
}

impl OutputComponent {
    pub fn show(&mut self, ui: &mut egui::Ui, context: &mut Context) {
        self.update_buffer(context);

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
            ui.label(&self.buffer);
        });
    }

    fn update_buffer(&mut self, context: &mut Context) {
        while let Ok(message) = context.output_rx.try_recv() {
            self.buffer.push_str(&message);
            self.buffer.push('\n');
        }
    }
}
