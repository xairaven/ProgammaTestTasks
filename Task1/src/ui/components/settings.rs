use crate::backend::info::InitialInformation;
use crate::commands::UiCommand;
use crate::context::Context;
use crate::errors::ProjectError;
use crate::ui::errors::FrontendError;
use egui::{Color32, Panel, RichText, ScrollArea};
use rfd::FileDialog;
use std::path::PathBuf;

#[derive(Debug)]
pub struct SettingsComponent {
    pub width: f32,
    pub attacker_ip: String,
    pub pcap_path: Option<PathBuf>,
    pub pcap_buffer: String,
}

impl Default for SettingsComponent {
    fn default() -> Self {
        Self {
            width: 250.0,
            attacker_ip: String::new(),
            pcap_path: None,
            pcap_buffer: String::new(),
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

                    ui.horizontal(|ui| {
                        ui.label("PCAP File:");

                        ui.add_enabled(
                            false,
                            egui::TextEdit::singleline(&mut self.pcap_buffer)
                                .desired_width(110.0),
                        );
                        if ui.button(egui_phosphor::regular::FOLDER).clicked() {
                            self.pick_file();
                        }
                        if ui.button(egui_phosphor::regular::KEY_RETURN).clicked() {
                            self.clear_pcap();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Attacker IP:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.attacker_ip)
                                .hint_text("192.168.0.1"),
                        );
                        ui.end_row();
                    });

                    ui.add_space(10.0);

                    ui.vertical_centered_justified(|ui| {
                        if ui.button("RUN").clicked() {
                            self.run(context);
                        }
                    });
                });
            });
    }

    fn run(&mut self, context: &mut Context) {
        let path = match self.pcap_path.as_ref() {
            None => {
                let error = FrontendError::NoFile;
                let _ = context.errors_tx.try_send(ProjectError::Frontend(error));
                return;
            },
            Some(path) => path.clone(),
        };

        let initial_info = InitialInformation::new(self.attacker_ip.clone(), path);
        match initial_info {
            Ok(info) => {
                let _ = context.ui_command_tx.try_send(UiCommand::Start(info));
            },
            Err(error) => {
                let _ = context.errors_tx.try_send(ProjectError::Frontend(error));
            },
        }
    }

    fn pick_file(&mut self) {
        self.pcap_path = FileDialog::new()
            .add_filter("PCAP File", &["pcap"])
            .pick_file();
        self.pcap_buffer = self
            .pcap_path
            .as_ref()
            .map_or(String::new(), |path| path.to_string_lossy().to_string());
    }

    fn clear_pcap(&mut self) {
        self.pcap_path = None;
        self.pcap_buffer.clear();
    }
}
