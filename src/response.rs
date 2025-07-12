use crate::ast::{CommonParser, CommonRule, CommonRuleType, RangedHeader, RangedValue, Searchable};
use pest::iterators::Pair;
use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "response.pest"]
pub struct ResponseParser;

#[derive(Debug)]
pub struct Response {
    pub headers: HashMap<String, RangedHeader>,
    pub content: RangedValue,
}

impl TryFrom<Pairs<'_, Rule>> for Response {
    type Error = &'static str;

    fn try_from(pairs: Pairs<Rule>) -> Result<Self, Self::Error> {
        let mut headers = HashMap::new();
        let mut content = RangedValue::default();

        for pair in pairs {
            match pair.as_rule() {
                Rule::header => {
                    let header = parse_response_header(pair)?;
                    headers.insert(header.0, header.1);
                }
                Rule::object | Rule::array => {
                    content = parse_response_value(pair);
                }
                _ => continue,
            }
        }

        Ok(Self { headers, content })
    }
}

pub fn _parse_response(input: &str) -> Result<Response, &'static str> {
    let pairs =
        ResponseParser::parse(Rule::response, input).map_err(|_| "Failed to parse response")?;
    Response::try_from(pairs)
}

/// Parses a `header` rule and returns its key-value pair with range.
pub fn parse_response_header(pair: Pair<Rule>) -> Result<(String, RangedHeader), &'static str> {
    CommonParser::parse_header(pair)
}

/// Parses a `value` rule into a `RangedValue` for response.
pub fn parse_response_value(pair: Pair<Rule>) -> RangedValue {
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

impl Searchable for Response {
    fn get_headers(&self) -> &HashMap<String, RangedHeader> {
        &self.headers
    }

    fn get_content(&self) -> Option<&RangedValue> {
        Some(&self.content)
    }
}
