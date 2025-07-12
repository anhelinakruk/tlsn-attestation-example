use pest::{RuleType, iterators::Pair};
use std::{collections::HashMap, ops::Range};

#[derive(Debug, Clone, Default)]
pub struct RangedHeader {
    pub range: Range<usize>,
    pub _value: String,
}

#[derive(Debug, Clone)]
pub enum RangedValue {
    Null,
    Bool {
        range: Range<usize>,
        _value: bool,
    },
    Number {
        range: Range<usize>,
        _value: f64,
    },
    String {
        range: Range<usize>,
        _value: String,
    },
    Array {
        range: Range<usize>,
        value: Vec<RangedValue>,
    },
    Object {
        range: Range<usize>,
        value: HashMap<String, RangedValue>,
    },
}
impl Default for RangedValue {
    fn default() -> Self {
        RangedValue::Object {
            range: Default::default(),
            value: Default::default(),
        }
    }
}
/// Extend RangedValue to provide a method for retrieving its range.
impl RangedValue {
    /// Get the range of the current RangedValue.
    pub fn get_range(&self) -> Range<usize> {
        match self {
            RangedValue::Null => 0..0, // Or handle it differently if needed
            RangedValue::Bool { range, .. }
            | RangedValue::Number { range, .. }
            | RangedValue::String { range, .. }
            | RangedValue::Array { range, .. }
            | RangedValue::Object { range, .. } => range.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommonRuleType {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
    Other,
}

pub trait CommonRule: RuleType {
    fn rule_type(&self) -> CommonRuleType;
}

pub struct CommonParser;

impl CommonParser {
    pub fn parse_header<R: CommonRule>(
        pair: Pair<R>,
    ) -> Result<(String, RangedHeader), &'static str> {
        let range = pair.as_span().start()..pair.as_span().end();
        let mut inner = pair.into_inner();

        let key = inner
            .next()
            .ok_or("Missing key in header")?
            .as_str()
            .to_string();
        let value = inner
            .next()
            .ok_or("Missing value in header")?
            .as_str()
            .to_string();

        Ok((
            key,
            RangedHeader {
                range,
                _value: value,
            },
        ))
    }

    pub fn parse_value<R: CommonRule>(pair: Pair<R>) -> RangedValue {
        let range = pair.as_span().start()..pair.as_span().end();

        match pair.as_rule().rule_type() {
            CommonRuleType::Object => RangedValue::Object {
                range,
                value: pair
                    .into_inner()
                    .map(|p| Self::parse_object_entry(p))
                    .collect::<HashMap<_, _>>(),
            },
            CommonRuleType::Array => RangedValue::Array {
                range,
                value: pair.into_inner().map(|p| Self::parse_value(p)).collect(),
            },
            CommonRuleType::String => RangedValue::String {
                range,
                _value: pair.into_inner().next().unwrap().as_str().to_string(),
            },
            CommonRuleType::Number => RangedValue::Number {
                range,
                _value: pair.as_str().parse().unwrap_or_default(),
            },
            CommonRuleType::Boolean => RangedValue::Bool {
                range,
                _value: pair.as_str().parse().unwrap_or_default(),
            },
            CommonRuleType::Null => RangedValue::Null,
            CommonRuleType::Other => unreachable!("Unexpected rule in parse_value"),
        }
    }

    fn parse_object_entry<R: CommonRule>(pair: Pair<R>) -> (String, RangedValue) {
        let mut inner_rules = pair.into_inner();
        let key = inner_rules
            .next()
            .expect("Missing key in object entry")
            .into_inner()
            .next()
            .expect("Missing key in object entry")
            .as_str()
            .to_string();
        let value = Self::parse_value(inner_rules.next().expect("Missing value in object entry"));
        (key, value)
    }
}

pub trait Searchable {
    fn get_headers(&self) -> &HashMap<String, RangedHeader>;
    fn get_content(&self) -> Option<&RangedValue>;
    fn get_additional_ranges(&self) -> Vec<Range<usize>> {
        Vec::new()
    }

    fn get_all_ranges_for_keypaths(
        &self,
        keypaths: &[&str],
        headers: &[&str],
    ) -> Vec<Range<usize>> {
        let mut ranges = Vec::new();

        // Add any additional ranges specific to the type
        ranges.extend(self.get_additional_ranges());

        // Check headers for matching keys
        for (key, header) in self.get_headers() {
            if headers.contains(&key.as_str()) {
                ranges.push(header.range.clone());
            }
        }

        // Recursively search in content for matching key paths
        if let Some(content) = self.get_content() {
            Self::search_content_by_path(keypaths, content, Vec::new(), &mut ranges);
        }

        ranges
    }

    fn search_content_by_path(
        keypaths: &[&str],
        content: &RangedValue,
        current_path: Vec<String>,
        ranges: &mut Vec<Range<usize>>,
    ) {
        match content {
            RangedValue::Object { value, .. } => {
                for (key, val) in value {
                    let mut new_path = current_path.clone();
                    new_path.push(key.clone());
                    let path_str = new_path.join(".");

                    if keypaths.contains(&path_str.as_str()) {
                        let start = val.get_range().start;
                        let end = val.get_range().end;
                        ranges.push((start - key.len() - 3)..end);
                    }
                    Self::search_content_by_path(keypaths, val, new_path, ranges);
                }
            }
            RangedValue::Array { value, .. } => {
                for item in value {
                    Self::search_content_by_path(keypaths, item, current_path.clone(), ranges);
                }
            }
            _ => {}
        }
    }
}

// #[derive(Debug, Clone, Default)]
// pub struct Response {
//     pub headers: HashMap<String, RangedHeader>,
//     pub content: RangedValue,
// }
// impl Response {
//     /// Get all values associated with a list of keys from both headers and content.
//     pub fn get_all_values_for_keys(&self, keys: &[&str]) -> Vec<RangedValue> {
//         let mut results = Vec::new();

//         // Convert the list of keys into a HashSet for efficient lookups
//         let key_set: std::collections::HashSet<&str> = keys.iter().cloned().collect();

//         // Check headers for matching keys
//         for (key, header) in &self.headers {
//             if key_set.contains(key.as_str()) {
//                 results.push(RangedValue::String {
//                     range: header.range.clone(),
//                     value: header.value.clone(),
//                 });
//             }
//         }

//         // Recursively search in content for matching keys
//         fn search_content(
//             keys: &std::collections::HashSet<&str>,
//             content: &RangedValue,
//             results: &mut Vec<RangedValue>,
//         ) {
//             match content {
//                 RangedValue::Object { value, .. } => {
//                     for (key, val) in value {
//                         if keys.contains(key.as_str()) {
//                             results.push(val.to_owned());
//                         }
//                         search_content(keys, val, results);
//                     }
//                 }
//                 RangedValue::Array { value, .. } => {
//                     for item in value {
//                         search_content(keys, item, results);
//                     }
//                 }
//                 _ => {}
//             }
//         }

//         search_content(&key_set, &self.content, &mut results);

//         results
//     }

//     /// Get all ranges associated with a list of keys from both headers and content.
//     pub fn get_all_ranges_for_keys(&self, keys: &[&str]) -> Vec<Range<usize>> {
//         let mut ranges = Vec::new();

//         // Convert the list of keys into a HashSet for efficient lookups
//         let key_set: std::collections::HashSet<&str> = keys.iter().cloned().collect();

//         // Check headers for matching keys and collect ranges
//         for (key, header) in &self.headers {
//             if key_set.contains(key.as_str()) {
//                 ranges.push(header.range.clone());
//             }
//         }

//         // Recursively search in content for matching keys and collect ranges
//         fn search_content(
//             keys: &std::collections::HashSet<&str>,
//             content: &RangedValue,
//             ranges: &mut Vec<Range<usize>>,
//         ) {
//             match content {
//                 RangedValue::Object { value, range: _ } => {
//                     for (key, val) in value {
//                         if keys.contains(key.as_str()) {
//                             let start = val.get_range().start;
//                             let end = val.get_range().end;
//                             ranges.push((start - key.len() - 3)..end);
//                         }
//                         search_content(keys, val, ranges);
//                     }
//                 }
//                 RangedValue::Array { value, range: _ } => {
//                     for item in value {
//                         search_content(keys, item, ranges);
//                     }
//                 }
//                 _ => {}
//             }
//         }

//         search_content(&key_set, &self.content, &mut ranges);

//         ranges
//     }
// }

// impl TryFrom<Pairs<'_, Rule>> for Response {
//     type Error = &'static str;

//     fn try_from(pairs: Pairs<Rule>) -> Result<Self, Self::Error> {
//         let mut headers = HashMap::new();
//         let mut content = RangedValue::default();

//         for pair in pairs {
//             match pair.as_rule() {
//                 Rule::header => {
//                     let header = parse_header(pair)?;
//                     headers.insert(header.0, header.1);
//                 }
//                 Rule::object | Rule::array => {
//                     content = parse_value(pair);
//                 }
//                 _ => continue, // Ignore irrelevant rules
//             }
//         }

//         Ok(Self { headers, content })
//     }
// }

// /// Parses a `header` rule and returns its key-value pair with range.
// fn parse_header(pair: Pair<Rule>) -> Result<(String, RangedHeader), &'static str> {
//     let range = pair.as_span().start()..pair.as_span().end();
//     let mut inner = pair.into_inner();

//     let key = inner
//         .next()
//         .ok_or("Missing key in header")?
//         .as_str()
//         .to_string();
//     let value = inner
//         .next()
//         .ok_or("Missing value in header")?
//         .as_str()
//         .to_string();

//     Ok((key, RangedHeader { range, value }))
// }

// /// Parses a `value` rule into a `RangedValue`.
// fn parse_value(pair: Pair<Rule>) -> RangedValue {
//     let range = pair.as_span().start()..pair.as_span().end();

//     match pair.as_rule() {
//         Rule::object => RangedValue::Object {
//             range,
//             value: pair
//                 .into_inner()
//                 .map(parse_object_entry)
//                 .collect::<HashMap<_, _>>(),
//         },
//         Rule::array => RangedValue::Array {
//             range,
//             value: pair.into_inner().map(parse_value).collect(),
//         },
//         Rule::string => RangedValue::String {
//             range,
//             value: pair.into_inner().next().unwrap().as_str().to_string(),
//         },
//         Rule::number => RangedValue::Number {
//             range,
//             value: pair.as_str().parse().unwrap_or_default(),
//         },
//         Rule::boolean => RangedValue::Bool {
//             range,
//             value: pair.as_str().parse().unwrap_or_default(),
//         },
//         Rule::null => RangedValue::Null,
//         _ => unreachable!("Unexpected rule in parse_value"),
//     }
// }

// /// Parses a single entry in an object rule and returns its key-value pair.
// fn parse_object_entry(pair: Pair<Rule>) -> (String, RangedValue) {
//     let mut inner_rules = pair.into_inner();
//     let key = inner_rules
//         .next()
//         .expect("Missing key in object entry")
//         .into_inner()
//         .next()
//         .expect("Missing key in object entry")
//         .as_str()
//         .to_string();
//     let value = parse_value(inner_rules.next().expect("Missing value in object entry"));
//     (key, value)
// }
