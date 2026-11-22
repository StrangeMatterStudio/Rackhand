//! The one way dashboard forms work (docs/designs/0002-dashboard-ui). A form is a table of fields, each saying what it
//! needs before anything goes wrong. On submit every field is checked, and the page comes back with all the problems,
//! each beside its field, and everything typed still there. Passwords and other secrets are never sent back: the hub
//! holds them in memory for a short while, so they needn't be typed again either. `static/forms.js` checks the same
//! rules as the form is filled in; without it the server's answer says the same.

use std::collections::HashMap;
use std::sync::Mutex;

use askama::Template;
use zeroize::Zeroizing;

use super::Ctx;
use super::csrf::Binding;
use super::session::random_token;

/// How long secrets typed into a refused form are held for its next try.
pub(crate) const HELD_MS: i64 = 30 * 60_000;
/// Forms held at once; the oldest goes first.
const MAX_HELD: usize = 256;

/// What a field takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    /// Never sent back to the browser.
    Secret,
    Select,
    Checkbox,
}

/// The fixed options of a select, as value and label.
pub(crate) type Choices = &'static [(&'static str, &'static str)];

/// A field of a form.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec {
    pub name: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    pub kind: Kind,
    pub required: bool,
    /// The whole value must match: checked here and by the browser. Escape `-` in a class as `\-` (browsers refuse a
    /// bare one, and then check nothing).
    pub pattern: &'static str,
    /// What is said when the pattern isn't met.
    pub rule: &'static str,
    pub min: usize,
    pub max: usize,
    pub choices: Choices,
    /// Only for this choice of another field, as `field=value`: shown with it, hidden without.
    pub when: &'static str,
    /// The same as another field, typed again.
    pub same: &'static str,
    /// The input's type: `text`, `time`.
    pub input: &'static str,
    /// Extra attributes, always fixed text: `autocomplete`, `inputmode`, `placeholder`.
    pub attrs: &'static str,
}

impl Spec {
    const fn new(kind: Kind, name: &'static str, label: &'static str) -> Spec {
        Spec {
            name,
            label,
            hint: "",
            kind,
            required: true,
            pattern: "",
            rule: "",
            min: 0,
            max: 1024,
            choices: &[],
            when: "",
            same: "",
            input: "text",
            attrs: "autocomplete=\"off\"",
        }
    }

    pub const fn text(name: &'static str, label: &'static str) -> Spec {
        Spec::new(Kind::Text, name, label)
    }

    pub const fn secret(name: &'static str, label: &'static str) -> Spec {
        Spec::new(Kind::Secret, name, label)
    }

    pub const fn select(name: &'static str, label: &'static str, choices: Choices) -> Spec {
        let mut s = Spec::new(Kind::Select, name, label);
        s.choices = choices;
        s.attrs = "";
        s
    }

    pub const fn checkbox(name: &'static str, label: &'static str) -> Spec {
        let mut s = Spec::new(Kind::Checkbox, name, label);
        s.required = false;
        s.attrs = "";
        s
    }

    pub const fn hint(mut self, hint: &'static str) -> Spec {
        self.hint = hint;
        self
    }

    pub const fn optional(mut self) -> Spec {
        self.required = false;
        self
    }

    pub const fn pattern(mut self, pattern: &'static str, rule: &'static str) -> Spec {
        self.pattern = pattern;
        self.rule = rule;
        self
    }

    pub const fn length(mut self, min: usize, max: usize) -> Spec {
        self.min = min;
        self.max = max;
        self
    }

    pub const fn when(mut self, when: &'static str) -> Spec {
        self.when = when;
        self
    }

    pub const fn same(mut self, same: &'static str) -> Spec {
        self.same = same;
        self
    }

    pub const fn input(mut self, input: &'static str) -> Spec {
        self.input = input;
        self
    }

    pub const fn attrs(mut self, attrs: &'static str) -> Spec {
        self.attrs = attrs;
        self
    }

    /// What's wrong with a value, by the field's own rules.
    fn problem(&self, value: &str) -> Option<String> {
        if value.is_empty() {
            return self.required.then(|| match self.kind {
                Kind::Select => "Choose one".to_string(),
                _ => "This is needed".to_string(),
            });
        }
        let n = value.chars().count();
        if n < self.min {
            return Some(format!("This needs at least {} characters; it has {n}", self.min));
        }
        // the pattern says the length too, and better
        if !self.pattern.is_empty() && !matches(self.pattern, value) {
            return Some(self.rule.to_string());
        }
        (n > self.max).then(|| format!("This can be at most {} characters; it has {n}", self.max))
    }
}

/// Whether the whole value matches, as the browser's `pattern` would have it.
fn matches(pattern: &str, value: &str) -> bool {
    regex::Regex::new(&format!(r"\A(?:{pattern})\z")).is_ok_and(|r| r.is_match(value))
}

/// A select's options in named groups; a group without a name is shown bare.
pub(crate) type Groups = Vec<(String, Vec<(String, String)>)>;

/// One form as a page shows it: its values, what's wrong with them, and the options of its selects.
#[derive(Debug)]
pub(crate) struct Form {
    id: &'static str,
    specs: &'static [Spec],
    values: HashMap<&'static str, Zeroizing<String>>,
    errors: Vec<(&'static str, String)>,
    /// A problem with the form as a whole.
    notice: Option<String>,
    options: HashMap<&'static str, Groups>,
    /// Secrets the hub has already, with what is said of them.
    kept: HashMap<&'static str, &'static str>,
    /// What's said of a field instead of asking for it.
    settled: HashMap<&'static str, &'static str>,
    /// Secrets taken from the last try: what was typed again then needn't be now.
    recalled: Vec<&'static str>,
    held: Option<String>,
}

#[derive(Template)]
#[template(path = "field.html")]
struct FieldView<'a> {
    id: String,
    spec: &'a Spec,
    value: &'a str,
    error: &'a str,
    kept: Option<&'a str>,
    settled: Option<&'a str>,
    groups: Vec<(&'a str, Vec<(&'a str, &'a str)>)>,
    zones: bool,
}

#[derive(Template)]
#[template(path = "problems.html")]
struct ProblemsView<'a> {
    notice: Option<&'a str>,
    errors: Vec<(String, &'a str, &'a str)>,
}

#[derive(Template)]
#[template(path = "hidden.html")]
struct HiddenView<'a> {
    fields: Vec<(&'a str, &'a str)>,
}

impl Form {
    /// An empty form.
    pub fn blank(id: &'static str, specs: &'static [Spec]) -> Form {
        Form {
            id,
            specs,
            values: HashMap::new(),
            errors: Vec::new(),
            notice: None,
            options: HashMap::new(),
            kept: HashMap::new(),
            settled: HashMap::new(),
            recalled: Vec::new(),
            held: None,
        }
    }

    /// The form as it was sent. An empty secret is the one held from the last try, if this is that form's next.
    pub fn sent(id: &'static str, specs: &'static [Spec], ctx: &Ctx, held: &HeldForms) -> Form {
        let mut form = Form::blank(id, specs);
        for s in specs {
            let raw = ctx.form.get(s.name).map(String::as_str).unwrap_or("");
            form.set(s.name, if s.kind == Kind::Secret { raw } else { raw.trim() });
        }
        let Some(token) = ctx.form.get("held") else { return form };
        let Some(secrets) = held.take(token, &ctx.binding, id, ctx.now_ms) else { return form };
        for s in specs.iter().filter(|s| s.kind == Kind::Secret) {
            if let (true, Some(v)) = (form.value(s.name).is_empty(), secrets.get(s.name)) {
                form.values.insert(s.name, v.clone());
                form.recalled.push(s.name);
            }
        }
        form
    }

    /// The form that was sent, if it is this one; on a page with several, the others stay as they are.
    pub fn or_sent(self, sent: &mut Option<Form>) -> Form {
        match sent.take_if(|s| s.id == self.id) {
            Some(mut s) => {
                for (name, groups) in self.options {
                    s.options.entry(name).or_insert(groups);
                }
                for (name, says) in self.kept {
                    s.kept.entry(name).or_insert(says);
                }
                s
            }
            None => self,
        }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn set(&mut self, name: &'static str, value: &str) {
        self.values.insert(name, Zeroizing::new(value.to_string()));
    }

    pub fn with(mut self, name: &'static str, value: &str) -> Form {
        self.set(name, value);
        self
    }

    pub fn value(&self, name: &str) -> &str {
        self.values.get(name).map(|v| v.as_str()).unwrap_or("")
    }

    /// Whether a checkbox is ticked.
    pub fn on(&self, name: &str) -> bool {
        self.value(name) == "on"
    }

    /// A select's options, when they aren't fixed.
    pub fn options(mut self, name: &'static str, groups: Groups) -> Form {
        self.options.insert(name, groups);
        self
    }

    /// The hub already has this secret, so it can be left empty: `KEPT` or `STORED`.
    pub fn keep(&mut self, name: &'static str, says: &'static str) {
        self.kept.insert(name, says);
    }

    /// The hub doesn't have it after all.
    pub fn forget(&mut self, name: &'static str) {
        self.kept.remove(name);
    }

    /// The field has been dealt with; it's replaced with what is said of it.
    pub fn settle(&mut self, name: &'static str, says: &'static str) {
        self.settled.insert(name, says);
    }

    /// Checks every field by its own rules; more can be refused after.
    pub fn check(&mut self) {
        for s in self.specs {
            if self.settled.contains_key(s.name) || self.has_error(s.name) {
                continue;
            }
            if !self.wanted(s) {
                continue;
            }
            let value = self.value(s.name);
            // typed again: needed whenever the first one was typed
            if !s.same.is_empty() {
                let first = self.value(s.same).to_string();
                if value.is_empty() && (self.kept.contains_key(s.same) && first.is_empty() || self.recalled.contains(&s.same)) {
                    continue;
                }
                if !first.is_empty() && value.is_empty() {
                    self.errors.push((s.name, "Type it again".into()));
                } else if value != first {
                    self.errors.push((s.name, "It isn't the same as the first".into()));
                }
                continue;
            }
            if value.is_empty() && self.kept.contains_key(s.name) {
                continue;
            }
            if let Some(p) = s.problem(value).or_else(|| self.choice_problem(s, value)) {
                self.errors.push((s.name, p));
            }
        }
        if self.specs.iter().any(|s| s.name == ZONE) {
            self.check_timezone();
        }
    }

    /// Whether the choice a field depends on is the one made.
    fn wanted(&self, s: &Spec) -> bool {
        match s.when.split_once('=') {
            Some((field, value)) => self.value(field) == value,
            None => true,
        }
    }

    fn choice_problem(&self, s: &Spec, value: &str) -> Option<String> {
        if s.kind != Kind::Select || value.is_empty() || s.name == ZONE {
            return None;
        }
        let known = match self.options.get(s.name) {
            Some(groups) => groups.iter().any(|(_, o)| o.iter().any(|(v, _)| v == value)),
            None => s.choices.iter().any(|(v, _)| *v == value),
        };
        (!known).then(|| format!("`{value}` isn't one of the choices"))
    }

    /// The zone's own spelling is kept (`europe/berlin` is `Europe/Berlin`).
    fn check_timezone(&mut self) {
        let given = self.value(ZONE).to_string();
        if given.is_empty() {
            return;
        }
        match jiff::tz::TimeZone::get(&given) {
            Ok(zone) => self.set(ZONE, zone.iana_name().unwrap_or(&given)),
            Err(_) => self.refuse(ZONE, format!("There is no timezone `{given}`; pick one from the list")),
        }
    }

    /// Refuses a field; the first reason stands.
    pub fn refuse(&mut self, name: &'static str, why: impl Into<String>) {
        if !self.has_error(name) {
            self.errors.push((name, why.into()));
        }
    }

    /// Refuses a field that has a value unless `ok`.
    pub fn require(&mut self, name: &'static str, ok: bool, why: &str) {
        if !ok && !self.value(name).is_empty() {
            self.refuse(name, why);
        }
    }

    /// Says what is wrong with the form as a whole.
    pub fn notice(&mut self, text: impl Into<String>) {
        self.notice = Some(text.into());
    }

    pub fn has_error(&self, name: &str) -> bool {
        self.errors.iter().any(|(n, _)| *n == name)
    }

    pub fn ok(&self) -> bool {
        self.errors.is_empty() && self.notice.is_none()
    }

    /// Keeps the secrets that were typed and weren't what was wrong, for the form's next try.
    pub fn hold(&mut self, held: &HeldForms, ctx: &Ctx) {
        let secrets: HeldSecrets = self
            .specs
            .iter()
            .filter(|s| s.kind == Kind::Secret && !self.has_error(s.name) && s.same.is_empty())
            // the first of two that differ isn't known to be the right one
            .filter(|s| !self.specs.iter().any(|o| o.same == s.name && self.has_error(o.name)))
            .filter_map(|s| self.values.get(s.name).filter(|v| !v.is_empty()).map(|v| (s.name, v.clone())))
            .collect();
        if secrets.is_empty() {
            return;
        }
        let names: Vec<&'static str> = secrets.keys().copied().collect();
        self.held = held.put(&ctx.binding, self.id, secrets, ctx.now_ms);
        if self.held.is_some() {
            self.kept.extend(names.into_iter().map(|n| (n, KEPT)));
        }
    }

    // What templates call.

    /// The hidden fields every form carries.
    pub fn hidden(&self, csrf: &str) -> String {
        let mut fields = vec![("csrf", csrf)];
        if let Some(h) = &self.held {
            fields.push(("held", h));
        }
        HiddenView { fields }.render().unwrap_or_default()
    }

    /// Every problem in one place, at the top of the form.
    pub fn problems(&self) -> String {
        if self.ok() {
            return String::new();
        }
        let at = |name: &str| self.specs.iter().position(|s| s.name == name);
        // in the order of the fields on the page
        let mut errors: Vec<&(&'static str, String)> = self.errors.iter().collect();
        errors.sort_by_key(|(n, _)| at(n));
        let errors = errors
            .into_iter()
            .map(|(n, e)| (format!("{}-{n}", self.id), at(n).map_or("", |i| self.specs[i].label), e.as_str()))
            .collect();
        ProblemsView { notice: self.notice.as_deref(), errors }.render().unwrap_or_default()
    }

    /// Every field, in order.
    pub fn all_fields(&self) -> String {
        self.specs.iter().map(|s| self.field(s.name)).collect()
    }

    /// A field: its label, hint, control and what's wrong with it.
    pub fn field(&self, name: &str) -> String {
        let Some(spec) = self.specs.iter().find(|s| s.name == name) else { return String::new() };
        let groups = match self.options.get(name) {
            Some(g) => {
                g.iter().map(|(n, o)| (n.as_str(), o.iter().map(|(v, l)| (v.as_str(), l.as_str())).collect())).collect()
            }
            None => vec![("", spec.choices.to_vec())],
        };
        FieldView {
            id: format!("{}-{name}", self.id),
            spec,
            value: if spec.kind == Kind::Secret { "" } else { self.value(name) },
            error: self.errors.iter().find(|(n, _)| *n == name).map_or("", |(_, e)| e.as_str()),
            kept: self.kept.get(name).copied(),
            settled: self.settled.get(name).copied(),
            groups,
            zones: name == ZONE,
        }
        .render()
        .unwrap_or_default()
    }
}

impl FieldView<'_> {
    fn text(&self) -> bool {
        self.spec.kind == Kind::Text
    }

    fn select(&self) -> bool {
        self.spec.kind == Kind::Select
    }

    fn checkbox(&self) -> bool {
        self.spec.kind == Kind::Checkbox
    }

    /// Nothing chosen yet, and nothing to choose by default.
    fn unchosen(&self) -> bool {
        self.value.is_empty() && (self.zones || self.groups.iter().all(|(_, o)| o.is_empty()))
    }

    /// A value the list doesn't have (a timezone's other name, or what was refused) is still shown as chosen.
    fn unlisted(&self) -> bool {
        !self.value.is_empty() && !self.groups.iter().any(|(_, o)| o.iter().any(|(v, _)| *v == self.value))
    }

    fn needed(&self) -> bool {
        self.spec.required && self.kept.is_none()
    }
}

/// A secret typed on an earlier try of the form.
pub(crate) const KEPT: &str = "Kept from your last try. Leave it empty to use that one, or type a new one.";
/// A secret in the Vault.
pub(crate) const STORED: &str = "One is stored. Leave it empty to keep it, or type a new one.";

/// The name of a timezone field, wherever one is.
pub(crate) const ZONE: &str = "timezone";

/// A timezone field: picked from the known list, preselected from the browser.
pub(crate) const TIMEZONE: Spec = Spec::select(ZONE, "Timezone", &[])
    .hint("The timezone its schedules, windows and backups follow. Your browser's is chosen for you.");

/// The known timezones by area, UTC first. Names without an area (`EST5EDT` and such) are left out.
pub(crate) fn timezones() -> Groups {
    const AREAS: [&str; 10] =
        ["Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia", "Europe", "Indian", "Pacific"];
    let mut names: Vec<String> = jiff::tz::db().available().map(|n| n.as_str().to_string()).collect();
    names.sort();
    let mut groups = vec![(String::new(), vec![("UTC".to_string(), "UTC".to_string())])];
    for area in AREAS {
        let prefix = format!("{area}/");
        let zones = names
            .iter()
            .filter(|n| n.starts_with(&prefix))
            .map(|n| (n.clone(), n[prefix.len()..].replace('_', " ")))
            .collect();
        groups.push((area.to_string(), zones));
    }
    groups
}

type HeldSecrets = HashMap<&'static str, Zeroizing<String>>;

struct HeldForm {
    binding: Binding,
    form: &'static str,
    secrets: HeldSecrets,
    at_ms: i64,
}

/// Secrets typed into refused forms, held for their next try: in memory only, for the same browser and form, once.
#[derive(Default)]
pub(crate) struct HeldForms(Mutex<HashMap<String, HeldForm>>);

impl HeldForms {
    fn put(&self, binding: &Binding, form: &'static str, secrets: HeldSecrets, now_ms: i64) -> Option<String> {
        let token = random_token().ok()?;
        let mut held = self.0.lock().ok()?;
        held.retain(|_, h| now_ms - h.at_ms < HELD_MS);
        while held.len() >= MAX_HELD {
            let oldest = held.iter().min_by_key(|(_, h)| h.at_ms).map(|(k, _)| k.clone())?;
            held.remove(&oldest);
        }
        held.insert(token.clone(), HeldForm { binding: binding.clone(), form, secrets, at_ms: now_ms });
        Some(token)
    }

    fn take(&self, token: &str, binding: &Binding, form: &str, now_ms: i64) -> Option<HeldSecrets> {
        let mut held = self.0.lock().ok()?;
        let h = held.get(token)?;
        if h.binding != *binding || h.form != form || now_ms - h.at_ms >= HELD_MS {
            return None;
        }
        held.remove(token).map(|h| h.secrets)
    }
}

/// A QR code as inline SVG: a white ground with its quiet zone, dark modules, and no style (the policy allows none).
pub(crate) fn qr_svg(text: &str, label: &'static str) -> String {
    use qrcodegen::{QrCode, QrCodeEcc};
    const QUIET: i32 = 4;
    let Ok(code) = QrCode::encode_text(text, QrCodeEcc::Medium) else { return String::new() };
    let n = code.size();
    let side = n + 2 * QUIET;
    let mut d = String::new();
    for y in 0..n {
        for x in (0..n).filter(|x| code.get_module(*x, y)) {
            d.push_str(&format!("M{} {}h1v1h-1z", x + QUIET, y + QUIET));
        }
    }
    format!(
        "<svg class=\"qr\" viewBox=\"0 0 {side} {side}\" width=\"220\" height=\"220\" shape-rendering=\"crispEdges\" \
         role=\"img\" aria-label=\"{label}\"><rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/>\
         <path fill=\"#000\" d=\"{d}\"/></svg>"
    )
}
