#![allow(dead_code)]

pub mod parser;
pub mod evaluator;

use serde::{Deserialize, Serialize};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterExpr {
    Compare {
        field: String,
        op: CompareOp,
        value: Value,
    },
    StringOp {
        field: String,
        op: StringOp,
        value: String,
    },
    Logical {
        op: LogicalOp,
        exprs: Vec<FilterExpr>,
    },
    Not(Box<FilterExpr>),
    Exists {
        field: String,
        check: ExistenceCheck,
    },
    In {
        field: String,
        values: Vec<Value>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Equal,
    NotEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringOp {
    Contains,      // ~
    StartsWith,    // ^
    EndsWith,      // $
    Regex,         // =~
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExistenceCheck {
    Exists,
    Empty,
    Null,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
    Hex(u64),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            Value::Integer(i) => Some(*i as f64),
            Value::Hex(h) => Some(*h as f64),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::Number(n) => Some(*n as i64),
            Value::Hex(h) => Some(*h as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

pub struct Filter {
    pub expr: FilterExpr,
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self> {
        parser::parse_filter(input)
    }

    pub fn evaluate(&self, data: &serde_json::Value) -> Result<bool> {
        evaluator::evaluate(&self.expr, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_filter() {
        let filter = Filter::parse("name=test").unwrap();
        assert!(matches!(filter.expr, FilterExpr::Compare { .. }));
    }

    #[test]
    fn test_parse_logical_filter() {
        let filter = Filter::parse("name=test AND size>100").unwrap();
        assert!(matches!(filter.expr, FilterExpr::Logical { .. }));
    }
}
