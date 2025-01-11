//! The `Query` struct used to parse and store the URL query parameters.
//!
/// ```text
/// URI = scheme ":" ["//" authority] path ["?" query] ["#" fragment]
/// ```
use std::panic::Location;
use std::str::FromStr;

use multimap::MultiMap;
use thiserror::Error;

type ParamName = String;
type ParamValue = String;

/// It represents a URL query component.
///
/// ```text
/// URI = scheme ":" ["//" authority] path ["?" query] ["#" fragment]
/// ```
#[derive(Debug)]
pub struct Query {
    /* code-review:
        - Consider using a third-party crate.
        - Conversion from/to string is not deterministic. Params can be in a different order in the query string.
    */
    params: MultiMap<ParamName, NameValuePair>,
}

impl Query {
    /// It return `Some(value)` for a URL query param if the param with the
    /// input `name` exists. For example:
    ///
    /// ```text
    /// use torrust_tracker_lib::servers::http::v1::query::Query;
    ///
    /// let raw_query = "param1=value1&param2=value2";
    ///
    /// let query = raw_query.parse::<Query>().unwrap();
    ///
    /// assert_eq!(query.get_param("param1").unwrap(), "value1");
    /// assert_eq!(query.get_param("param2").unwrap(), "value2");
    /// ```
    ///
    /// It returns only the first param value even if it has multiple values:
    ///
    /// ```text
    /// use torrust_tracker_lib::servers::http::v1::query::Query;
    ///
    /// let raw_query = "param1=value1&param1=value2";
    ///
    /// let query = raw_query.parse::<Query>().unwrap();
    ///
    /// assert_eq!(query.get_param("param1").unwrap(), "value1");
    /// ```
    #[must_use]
    pub fn get_param(&self, name: &str) -> Option<String> {
        self.params.get(name).map(|pair| pair.value.clone())
    }

    /// Returns all the param values as a vector.
    ///
    /// ```text
    /// use torrust_tracker_lib::servers::http::v1::query::Query;
    ///
    /// let query = "param1=value1&param1=value2".parse::<Query>().unwrap();
    ///
    /// assert_eq!(
    ///     query.get_param_vec("param1"),
    ///     Some(vec!["value1".to_string(), "value2".to_string()])
    /// );
    /// ```
    ///
    /// Returns all the param values as a vector even if it has only one value.
    ///
    /// ```text
    /// use torrust_tracker_lib::servers::http::v1::query::Query;
    ///
    /// let query = "param1=value1".parse::<Query>().unwrap();
    ///
    /// assert_eq!(
    ///     query.get_param_vec("param1"), Some(vec!["value1".to_string()])
    /// );
    /// ```
    #[must_use]
    pub fn get_param_vec(&self, name: &str) -> Option<Vec<String>> {
        self.params.get_vec(name).map(|pairs| {
            let mut param_values = vec![];
            for pair in pairs {
                param_values.push(pair.value.to_string());
            }
            param_values
        })
    }
}

/// This error can be returned when parsing a [`Query`]
/// from a string.
#[derive(Error, Debug)]
pub enum ParseQueryError {
    /// Invalid URL query param. For example: `"name=value=value"`. It contains
    /// an unescaped `=` character.
    #[error("invalid param {raw_param} in {location}")]
    InvalidParam {
        location: &'static Location<'static>,
        raw_param: String,
    },
}

impl FromStr for Query {
    type Err = ParseQueryError;

    fn from_str(raw_query: &str) -> Result<Self, Self::Err> {
        let mut params: MultiMap<ParamName, NameValuePair> = MultiMap::new();

        let raw_params = raw_query.trim().trim_start_matches('?').split('&').collect::<Vec<&str>>();

        for raw_param in raw_params {
            let pair: NameValuePair = raw_param.parse()?;
            let param_name = pair.name.clone();
            params.insert(param_name, pair);
        }

        Ok(Self { params })
    }
}

impl From<Vec<(&str, &str)>> for Query {
    fn from(raw_params: Vec<(&str, &str)>) -> Self {
        let mut params: MultiMap<ParamName, NameValuePair> = MultiMap::new();

        for raw_param in raw_params {
            params.insert(raw_param.0.to_owned(), NameValuePair::new(raw_param.0, raw_param.1));
        }

        Self { params }
    }
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query = self
            .params
            .iter_all()
            .map(|param| format!("{}", FieldValuePairSet::from_vec(param.1)))
            .collect::<Vec<String>>()
            .join("&");

        write!(f, "{query}")
    }
}

#[derive(Debug, PartialEq, Clone)]
struct NameValuePair {
    name: ParamName,
    value: ParamValue,
}

impl NameValuePair {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }
}

impl FromStr for NameValuePair {
    type Err = ParseQueryError;

    fn from_str(raw_param: &str) -> Result<Self, Self::Err> {
        let pair = raw_param.split('=').collect::<Vec<&str>>();

        if pair.len() != 2 {
            return Err(ParseQueryError::InvalidParam {
                location: Location::caller(),
                raw_param: raw_param.to_owned(),
            });
        }

        Ok(Self {
            name: pair[0].to_owned(),
            value: pair[1].to_owned(),
        })
    }
}

impl std::fmt::Display for NameValuePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

#[derive(Debug, PartialEq)]
struct FieldValuePairSet {
    pairs: Vec<NameValuePair>,
}

impl FieldValuePairSet {
    fn from_vec(pair_vec: &Vec<NameValuePair>) -> Self {
        let mut pairs: Vec<NameValuePair> = vec![];

        for pair in pair_vec {
            pairs.push(pair.clone());
        }

        Self { pairs }
    }
}

impl std::fmt::Display for FieldValuePairSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query = self
            .pairs
            .iter()
            .map(|pair| format!("{pair}"))
            .collect::<Vec<String>>()
            .join("&");

        write!(f, "{query}")
    }
}

#[cfg(test)]
mod tests {

    mod url_query {
        use crate::v1::query::Query;

        #[test]
        fn should_parse_the_query_params_from_an_url_query_string() {
            let raw_query =
                "info_hash=%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0&peer_id=-qB00000000000000001&port=17548";

            let query = raw_query.parse::<Query>().unwrap();

            assert_eq!(
                query.get_param("info_hash").unwrap(),
                "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"
            );
            assert_eq!(query.get_param("peer_id").unwrap(), "-qB00000000000000001");
            assert_eq!(query.get_param("port").unwrap(), "17548");
        }

        #[test]
        fn should_be_instantiated_from_a_string_pair_vector() {
            let query = Query::from(vec![("param1", "value1"), ("param2", "value2")]);

            assert_eq!(query.get_param("param1"), Some("value1".to_string()));
            assert_eq!(query.get_param("param2"), Some("value2".to_string()));
        }

        #[test]
        fn should_fail_parsing_an_invalid_query_string() {
            let invalid_raw_query = "name=value=value";

            let query = invalid_raw_query.parse::<Query>();

            assert!(query.is_err());
        }

        #[test]
        fn should_ignore_the_preceding_question_mark_if_it_exists() {
            let raw_query = "?name=value";

            let query = raw_query.parse::<Query>().unwrap();

            assert_eq!(query.get_param("name"), Some("value".to_string()));
        }

        #[test]
        fn should_trim_whitespaces() {
            let raw_query = " name=value ";

            let query = raw_query.parse::<Query>().unwrap();

            assert_eq!(query.get_param("name"), Some("value".to_string()));
        }

        mod should_allow_more_than_one_value_for_the_same_param {
            use crate::v1::query::Query;

            #[test]
            fn instantiated_from_a_vector() {
                let query1 = Query::from(vec![("param1", "value1"), ("param1", "value2")]);
                assert_eq!(
                    query1.get_param_vec("param1"),
                    Some(vec!["value1".to_string(), "value2".to_string()])
                );
            }

            #[test]
            fn parsed_from_an_string() {
                let query2 = "param1=value1&param1=value2".parse::<Query>().unwrap();
                assert_eq!(
                    query2.get_param_vec("param1"),
                    Some(vec!["value1".to_string(), "value2".to_string()])
                );
            }
        }

        mod should_be_displayed {
            use crate::v1::query::Query;

            #[test]
            fn with_one_param() {
                assert_eq!("param1=value1".parse::<Query>().unwrap().to_string(), "param1=value1");
            }

            #[test]
            fn with_multiple_params() {
                let query = "param1=value1&param2=value2".parse::<Query>().unwrap().to_string();
                assert!(query == "param1=value1&param2=value2" || query == "param2=value2&param1=value1");
            }

            #[test]
            fn with_multiple_values_for_the_same_param() {
                let query = "param1=value1&param1=value2".parse::<Query>().unwrap().to_string();
                assert!(query == "param1=value1&param1=value2" || query == "param1=value2&param1=value1");
            }
        }

        mod param_name_value_pair {
            use crate::v1::query::NameValuePair;

            #[test]
            fn should_parse_a_single_query_param() {
                let raw_param = "name=value";

                let param = raw_param.parse::<NameValuePair>().unwrap();

                assert_eq!(
                    param,
                    NameValuePair {
                        name: "name".to_string(),
                        value: "value".to_string(),
                    }
                );
            }

            #[test]
            fn should_fail_parsing_an_invalid_query_param() {
                let invalid_raw_param = "name=value=value";

                let query = invalid_raw_param.parse::<NameValuePair>();

                assert!(query.is_err());
            }

            #[test]
            fn should_be_displayed() {
                assert_eq!("name=value".parse::<NameValuePair>().unwrap().to_string(), "name=value");
            }
        }
    }
}
