use crate::ast::{CommonParser, CommonRule, CommonRuleType, RangedHeader, RangedValue, Searchable};
use pest::iterators::Pair;
use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;
use std::{collections::HashMap, ops::Range};

#[derive(Parser)]
#[grammar = "request.pest"]
pub struct RequestParser;

#[derive(Debug)]
pub struct Request {
    pub request_line: RangedHeader,
    pub headers: HashMap<String, RangedHeader>,
    pub content: Option<RangedValue>,
}

impl TryFrom<Pairs<'_, Rule>> for Request {
    type Error = &'static str;

    fn try_from(pairs: Pairs<Rule>) -> Result<Self, Self::Error> {
        let mut request_line = None;
        let mut headers = HashMap::new();
        let mut content = RangedValue::default();

        for pair in pairs {
            match pair.as_rule() {
                Rule::request_line => {
                    let range = pair.as_span().start()..pair.as_span().end();
                    request_line = Some(RangedHeader {
                        range,
                        _value: pair.as_str().to_string(),
                    });
                }
                Rule::header => {
                    let header = parse_request_header(pair)?;
                    headers.insert(header.0, header.1);
                }
                Rule::object | Rule::array => {
                    content = parse_request_value(pair);
                }
                _ => continue,
            }
        }

        Ok(Self {
            request_line: request_line.ok_or("Missing request line")?,
            headers,
            content: Some(content),
        })
    }
}

pub fn _parse_request(input: &str) -> Result<Request, &'static str> {
    let pairs =
        RequestParser::parse(Rule::request, input).map_err(|_| "Failed to parse request")?;
    Request::try_from(pairs)
}

/// Parses a `header` rule and returns its key-value pair with range for request.
pub fn parse_request_header(pair: Pair<Rule>) -> Result<(String, RangedHeader), &'static str> {
    CommonParser::parse_header(pair)
}

/// Parses a `value` rule into a `RangedValue` for request.
pub fn parse_request_value(pair: Pair<Rule>) -> RangedValue {
    CommonParser::parse_value(pair)
}

impl CommonRule for Rule {
    fn rule_type(&self) -> CommonRuleType {
        match self {
            Rule::object => CommonRuleType::Object,
            Rule::array => CommonRuleType::Array,
            Rule::string => CommonRuleType::String,
            Rule::number => CommonRuleType::Number,
            Rule::boolean => CommonRuleType::Boolean,
            Rule::null => CommonRuleType::Null,
            _ => CommonRuleType::Other,
        }
    }
}

impl Searchable for Request {
    fn get_headers(&self) -> &HashMap<String, RangedHeader> {
        &self.headers
    }

    fn get_content(&self) -> Option<&RangedValue> {
        self.content.as_ref()
    }

    fn get_additional_ranges(&self) -> Vec<Range<usize>> {
        vec![self.request_line.range.clone()]
    }
}
