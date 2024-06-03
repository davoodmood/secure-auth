use fluent::{FluentBundle, FluentValue, FluentResource, FluentArgs};
use std::collections::HashMap;
use std::fs;
use unic_langid::LanguageIdentifier;

use unic_langid::langid;

pub struct Localization {
    bundles: HashMap<String, FluentBundle<FluentResource>>,
}

impl Localization {
    pub fn new() -> Self {
        let mut localization = Localization { bundles: HashMap::new() };

        // For each supported language, load the .ftl files and add them to the bundles
        localization.add_language("en-US", "locales/en-US.ftl");
        localization.add_language("es-ES", "locales/es-ES.ftl");
        localization.add_language("fa-IR", "locales/fa-IR.ftl");

        localization
    }

    fn add_language(&mut self, lang: &str, file_path: &str) {
        let ftl_contents = fs::read_to_string(file_path)
            .expect(&format!("Failed to read FTL file: {}", file_path));

        let res = FluentResource::try_new(ftl_contents).expect("Failed to parse FTL strings");

        let lang_id: LanguageIdentifier = lang.parse().expect("Failed to parse language identifier");
        let mut bundle = FluentBundle::new(vec![lang_id]);

        bundle.add_resource(res).expect("Failed to add FTL resource");
        self.bundles.insert(lang.to_string(), bundle);

    }

    pub fn get_message(&self, lang: &str, message_id: &str) -> String {
        if let Some(bundle) = self.bundles.get(lang) {
            if let Some(message) = bundle.get_message(message_id) {
                if let Some(value) = message.value() {
                    let mut errors = vec![];
                    return bundle.format_pattern(value, None, &mut errors).to_string();
                }
            }
        }

        format!("Missing translation for {}", message_id)
    }
}
