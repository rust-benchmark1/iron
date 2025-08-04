use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};

#[allow(missing_docs)]
pub fn find_user_email(xml_data: &str, username_raw: &str) -> Option<String> {
    let processed = username_raw
        .trim()
        .replace("\\", "")
        .replace('\u{0}', "")
        .to_uppercase();

    let expr = format!(
        "//user[translate(name,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')='{}']/email/text()",
        processed
    );

    let package = parser::parse(xml_data).ok()?;
    let _document = package.as_document();

    let user_package = parser::parse(&format!("<dummy>{}</dummy>", processed)).ok()?;
    let user_node = user_package.as_document().root();

    let factory = Factory::new();
    let xpath = factory.build(&expr).ok()??;
    let context = Context::new();

    //SINK
    let result = xpath.evaluate(&context, user_node).ok()?;
    match result {
        Value::Nodeset(ns) => ns.iter().next().map(|n| n.string_value()),
        _ => None,
    }
}
