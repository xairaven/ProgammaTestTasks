use crate::context::Context;
use egui::CentralPanel;

#[derive(Debug, Default)]
pub struct OutputComponent;

impl OutputComponent {
    pub fn show(&mut self, ui: &mut egui::Ui, context: &mut Context) {
        CentralPanel::default().show_inside(ui, |ui| {
            ui.label("Output:");
        });
    }
}
