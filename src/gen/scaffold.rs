use std::collections::HashMap;

use lazy_static::lazy_static;
use rrgen::RRgen;
use serde_json::json;

const CONTROLLER_SCAFFOLD_T: &str = include_str!("templates/controller_scaffold.t");

use super::{collect_messages, model, CONTROLLER_TEST_T};
use crate::{errors::Error, Result};

lazy_static! {
    static ref PARAMS_MAPPING: HashMap<&'static str, &'static str> = HashMap::from([
        ("text", "Option<String>"),
        ("string", "Option<String>"),
        ("string!", "Option<String>"),
        ("string^", "Option<String>"),
        ("int", "Option<i32>"),
        ("int!", "Option<i32>"),
        ("int^", "Option<i32>"),
        ("bool", "Option<boolean>"),
        ("bool!", "Option<boolean>"),
        ("ts", "Option<DateTime>"),
        ("ts!", "Option<DateTime>"),
        ("uuid", "Option<Uuid>"),
    ]);
}

pub fn generate(rrgen: &RRgen, name: &str, fields: &[(String, String)]) -> Result<String> {
    let model_messages = model::generate(rrgen, name, fields)?;

    let mut columns = Vec::new();
    for (fname, ftype) in fields {
        if ftype != "references" {
            let schema_type = PARAMS_MAPPING.get(ftype.as_str()).ok_or_else(|| {
                Error::Message(format!(
                    "type: {} not found. try any of: {:?}",
                    ftype,
                    PARAMS_MAPPING.keys()
                ))
            })?;
            columns.push((fname.to_string(), *schema_type));
        }
    }

    let vars = json!({"name": name, "columns": columns});
    let res1 = rrgen.generate(CONTROLLER_SCAFFOLD_T, &vars)?;
    let res2 = rrgen.generate(CONTROLLER_TEST_T, &vars)?;
    let messages = collect_messages(vec![res1, res2]);

    Ok(format!("{model_messages}{messages}"))
}
