use poem::web::Html as PoemHtml;
use std::time::{SystemTime, UNIX_EPOCH};

fn normalize_input(mut s: String) -> String {
    s = s.trim().to_string();
    s = s.replace("\r", "").replace('\n', " ");
    if s.is_empty() {
        s.push_str("anonymous");
    }
    s
}

fn enrich_with_metadata(content: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("{} | ts={}", content, ts)
}

fn maybe_prefix_user(mut s: String) -> String {
    if !s.contains(':') {
        s = format!("user:{}", s);
    }
    s
}

fn build_fragment(title: &str, body: &str) -> String {
    let header = format!("<header><h1>{}</h1></header>", title);
    let main = format!("<main>{}</main>", body);
    format!("<section>{}{}</section>", header, main)
}

/// Renders externally received dynamic content.
pub fn render_dynamic_page(input: String) -> PoemHtml<String> {
    let step1 = normalize_input(input);
    let step2 = maybe_prefix_user(step1);
    let enriched = enrich_with_metadata(&step2);

    let fragment = build_fragment("Welcome", &enriched);
    let page = format!("<!doctype html><html><body>{}</body></html>", fragment);

    //SINK
    PoemHtml(page)
}
