use crate::context::Context;
use crate::ui::components::output::OutputComponent;
use crate::ui::components::settings::SettingsComponent;

pub struct Workspace {
    pub settings: SettingsComponent,
    pub output: OutputComponent,
}

impl Workspace {
    pub fn new(_context: &Context) -> Self {
        Self {
            settings: Default::default(),
            output: Default::default(),
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, context: &mut Context) {
        self.settings.show(ui, context);
        self.output.show(ui, context);
    }
}
