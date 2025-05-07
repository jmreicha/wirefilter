use wasm_bindgen::prelude::*;
use wirefilter::{Scheme, Type, LhsValue, FunctionArgs, SimpleFunctionDefinition, SimpleFunctionParam, FunctionArgKind, SimpleFunctionImpl, SimpleFunctionOptParam};
use std::borrow::Cow;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose};

#[wasm_bindgen]
pub struct WasmScheme(Scheme);

#[allow(clippy::needless_pass_by_value)]
fn into_js_error(err: impl std::error::Error) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

// Transform functions implementations

fn lower<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Bytes(mut b)) => {
            let mut text: Vec<u8> = b.to_mut().to_vec();
            text.make_ascii_lowercase();
            Some(LhsValue::Bytes(Cow::Owned(text)))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

fn upper<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Bytes(mut b)) => {
            let mut text: Vec<u8> = b.to_mut().to_vec();
            text.make_ascii_uppercase();
            Some(LhsValue::Bytes(Cow::Owned(text)))
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

fn concat<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let mut result: Vec<u8> = Vec::new();

    for arg in args {
        if let Ok(LhsValue::Bytes(value)) = arg {
            result.extend_from_slice(&value);
        }
    }

    Some(LhsValue::Bytes(Cow::Owned(result)))
}

fn decode_base64<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            if let Ok(decoded) = general_purpose::STANDARD.decode(&*b) {
                Some(LhsValue::Bytes(Cow::Owned(decoded)))
            } else {
                // Return empty bytes on invalid base64 input
                Some(LhsValue::Bytes(Cow::Owned(Vec::new())))
            }
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

fn starts_with<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let haystack = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let needle = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    Some(LhsValue::Bool(haystack.starts_with(&*needle)))
}

fn ends_with<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let haystack = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let needle = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    Some(LhsValue::Bool(haystack.ends_with(&*needle)))
}

fn len<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Bytes(b)) => Some(LhsValue::Int(b.len() as i64)),
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

fn regex_replace<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let haystack = match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            // Convert to owned string to avoid lifetime issues
            String::from_utf8_lossy(&b).to_string()
        },
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let pattern = match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            String::from_utf8_lossy(&b).to_string()
        },
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let replacement = match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            String::from_utf8_lossy(&b).to_string()
        },
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    if let Ok(re) = Regex::new(&pattern) {
        let result = re.replace_all(&haystack, replacement.as_str()).into_owned();
        Some(LhsValue::Bytes(Cow::Owned(result.into_bytes())))
    } else {
        // Return the original string on regex error
        Some(LhsValue::Bytes(Cow::Owned(haystack.into_bytes())))
    }
}

fn substring<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let haystack = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let start_idx = match args.next()? {
        Ok(LhsValue::Int(i)) => i as usize,
        Err(Type::Int) => return None,
        _ => unreachable!(),
    };

    let length = match args.next()? {
        Ok(LhsValue::Int(i)) => i as usize,
        Err(Type::Int) => return None,
        _ => unreachable!(),
    };

    let end_idx = std::cmp::min(start_idx + length, haystack.len());
    if start_idx >= haystack.len() || start_idx >= end_idx {
        return Some(LhsValue::Bytes(Cow::Owned(Vec::new())));
    }

    Some(LhsValue::Bytes(Cow::Owned(haystack[start_idx..end_idx].to_vec())))
}

fn to_string<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Int(i)) => {
            let s = i.to_string();
            Some(LhsValue::Bytes(Cow::Owned(s.into_bytes())))
        },
        Ok(LhsValue::Bool(b)) => {
            let s = b.to_string();
            Some(LhsValue::Bytes(Cow::Owned(s.into_bytes())))
        },
        Ok(LhsValue::Ip(ip)) => {
            let s = ip.to_string();
            Some(LhsValue::Bytes(Cow::Owned(s.into_bytes())))
        },
        Ok(LhsValue::Bytes(b)) => Some(LhsValue::Bytes(b)),
        Err(_) => None,
        _ => unreachable!(),
    }
}

fn remove_bytes<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let haystack = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let to_remove = match args.next()? {
        Ok(LhsValue::Bytes(b)) => b,
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    let result: Vec<u8> = haystack.iter()
        .filter(|&&b| !to_remove.contains(&b))
        .cloned()
        .collect();

    Some(LhsValue::Bytes(Cow::Owned(result)))
}

fn url_decode<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            let s = String::from_utf8_lossy(&b);
            if let Ok(decoded) = urlencoding::decode(&s) {
                Some(LhsValue::Bytes(Cow::Owned(decoded.into_owned().into_bytes())))
            } else {
                // Return the original string on decode error
                Some(LhsValue::Bytes(Cow::Owned(s.to_string().into_bytes())))
            }
        }
        Err(Type::Bytes) => None,
        _ => unreachable!(),
    }
}

fn cidr<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let ip = match args.next()? {
        Ok(LhsValue::Ip(ip)) => ip,
        Err(Type::Ip) => return None,
        _ => unreachable!(),
    };

    let network = match args.next()? {
        Ok(LhsValue::Bytes(b)) => {
            let s = String::from_utf8_lossy(&b);
            match s.parse::<ipnet::IpNet>() {
                Ok(net) => net,
                Err(_) => return Some(LhsValue::Bool(false)),
            }
        },
        Err(Type::Bytes) => return None,
        _ => unreachable!(),
    };

    Some(LhsValue::Bool(network.contains(&ip)))
}

fn any<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    for arg in args {
        match arg {
            Ok(LhsValue::Bool(true)) => return Some(LhsValue::Bool(true)),
            Err(_) => continue,
            _ => continue, // Treat non-boolean values as false
        }
    }
    Some(LhsValue::Bool(false))
}

fn all<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    for arg in args {
        match arg {
            Ok(LhsValue::Bool(false)) => return Some(LhsValue::Bool(false)),
            Err(_) => return None, // If any arg is missing, result is undefined
            _ => continue, // Treat non-boolean values as true
        }
    }
    Some(LhsValue::Bool(true))
}

#[wasm_bindgen]
impl WasmScheme {
    #[wasm_bindgen(constructor)]
    pub fn try_from(fields: JsValue) -> Result<WasmScheme, JsValue> {
        let mut builder = wirefilter::SchemeBuilder::new();

        // Add the lower transformation function to the scheme
        builder.add_function(
            "lower",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: FunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(lower),
            },
        ).unwrap();

        // Add the upper transformation function
        builder.add_function(
            "upper",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: FunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(upper),
            },
        ).unwrap();

        // Add concat function
        builder.add_function(
            "concat",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: FunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![SimpleFunctionOptParam {
                    arg_kind: FunctionArgKind::Field,
                    default_value: LhsValue::Bytes(Cow::Borrowed(b"")),
                }],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(concat),
            },
        ).unwrap();

        // Add decode_base64 function
        builder.add_function(
            "decode_base64",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: FunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(decode_base64),
            },
        ).unwrap();

        // Add starts_with function
        builder.add_function(
            "starts_with",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                ],
                opt_params: vec![],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(starts_with),
            },
        ).unwrap();

        // Add ends_with function
        builder.add_function(
            "ends_with",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                ],
                opt_params: vec![],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(ends_with),
            },
        ).unwrap();

        // Add len function
        builder.add_function(
            "len",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes }],
                opt_params: vec![],
                return_type: Type::Int,
                implementation: SimpleFunctionImpl::new(len),
            },
        ).unwrap();

        // Add regex_replace function
        builder.add_function(
            "regex_replace",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(regex_replace),
            },
        ).unwrap();

        // Add substring function
        builder.add_function(
            "substring",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Int },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Int },
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(substring),
            },
        ).unwrap();

        // Add to_string function
        builder.add_function(
            "to_string",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Int }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(to_string),
            },
        ).unwrap();

        // Add remove_bytes function
        builder.add_function(
            "remove_bytes",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                ],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(remove_bytes),
            },
        ).unwrap();

        // Add url_decode function
        builder.add_function(
            "url_decode",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bytes }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(url_decode),
            },
        ).unwrap();

        // Add cidr function
        builder.add_function(
            "cidr",
            SimpleFunctionDefinition {
                params: vec![
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Ip },
                    SimpleFunctionParam { arg_kind: FunctionArgKind::Literal, val_type: Type::Bytes },
                ],
                opt_params: vec![],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(cidr),
            },
        ).unwrap();

        // Add any function
        builder.add_function(
            "any",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bool }],
                opt_params: vec![SimpleFunctionOptParam {
                    arg_kind: FunctionArgKind::Field,
                    default_value: LhsValue::Bool(false),
                }],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(any),
            },
        ).unwrap();

        // Add all function
        builder.add_function(
            "all",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam { arg_kind: FunctionArgKind::Field, val_type: Type::Bool }],
                opt_params: vec![SimpleFunctionOptParam {
                    arg_kind: FunctionArgKind::Field,
                    default_value: LhsValue::Bool(true),
                }],
                return_type: Type::Bool,
                implementation: SimpleFunctionImpl::new(all),
            },
        ).unwrap();

        // Standard field definitions
        // HTTP Fields
        builder.add_field("http.cookie", Type::Bytes).unwrap();
        builder.add_field("http.host", Type::Bytes).unwrap();
        builder.add_field("http.method", Type::Bytes).unwrap();
        builder.add_field("http.referer", Type::Bytes).unwrap();
        builder.add_field("http.request.uri.path", Type::Bytes).unwrap();
        builder.add_field("http.request.uri.query", Type::Bytes).unwrap();
        builder.add_field("http.request.uri.args", Type::Map(Type::Bytes.into())).unwrap();
        builder.add_field("http.request.uri.full", Type::Bytes).unwrap();
        builder.add_field("http.request.uri", Type::Bytes).unwrap();
        builder.add_field("http.request.headers", Type::Map(Type::Bytes.into())).unwrap();
        builder.add_field("http.request.accepted_languages", Type::Bytes).unwrap();
        builder.add_field("http.request.version", Type::Bytes).unwrap();
        builder.add_field("http.request.timestamp.sec", Type::Int).unwrap();
        builder.add_field("http.request.timestamp.msec", Type::Int).unwrap();
        builder.add_field("http.request.raw.full_uri", Type::Bytes).unwrap();
        builder.add_field("http.request.raw.uri", Type::Bytes).unwrap();
        builder.add_field("http.response.code", Type::Int).unwrap();
        builder.add_field("http.response.headers", Type::Map(Type::Bytes.into())).unwrap();
        builder.add_field("http.response.raw.headers", Type::Map(Type::Bytes.into())).unwrap();
        builder.add_field("http.response.content_type", Type::Bytes).unwrap();
        builder.add_field("http.response.server", Type::Bytes).unwrap();
        builder.add_field("http.ua", Type::Bytes).unwrap();
        builder.add_field("http.user_agent", Type::Bytes).unwrap();
        builder.add_field("http.x_forwarded_for", Type::Bytes).unwrap();

        // IP Fields
        builder.add_field("ip.src", Type::Ip).unwrap();
        builder.add_field("ip.dst", Type::Ip).unwrap();
        builder.add_field("ip.src.lat", Type::Bytes).unwrap();
        builder.add_field("ip.src.lon", Type::Bytes).unwrap();
        builder.add_field("ip.geoip.country", Type::Bytes).unwrap();
        builder.add_field("ip.geoip.continent", Type::Bytes).unwrap();
        builder.add_field("ip.geoip.asnum", Type::Int).unwrap();
        builder.add_field("ip.geoip.asorg", Type::Bytes).unwrap();
        builder.add_field("ip.src.city", Type::Bytes).unwrap();
        builder.add_field("ip.src.is_in_european_union", Type::Bool).unwrap();
        builder.add_field("ip.src.subdivision_1_iso_code", Type::Bytes).unwrap();
        builder.add_field("ip.src.subdivision_2_iso_code", Type::Bytes).unwrap();

        // Cloudflare Specific
        builder.add_field("cf.bot_management.score", Type::Int).unwrap();
        builder.add_field("cf.bot_management.verified_bot", Type::Bool).unwrap();
        builder.add_field("cf.bot_management.js_detection.passed", Type::Bool).unwrap();
        builder.add_field("cf.threat_score", Type::Int).unwrap();
        builder.add_field("cf.worker.upstream_zone", Type::Bytes).unwrap();
        builder.add_field("cf.colo.id", Type::Int).unwrap();
        builder.add_field("cf.colo.region", Type::Bytes).unwrap();
        builder.add_field("cf.client.bot", Type::Bool).unwrap();
        builder.add_field("cf.client.browser", Type::Bytes).unwrap();
        builder.add_field("cf.client.device_type", Type::Bytes).unwrap();
        builder.add_field("cf.client.os", Type::Bytes).unwrap();
        builder.add_field("cf.edge.server_port", Type::Int).unwrap();
        builder.add_field("cf.edge.server_ip", Type::Bytes).unwrap();
        builder.add_field("cf.edge.client_port", Type::Int).unwrap();
        builder.add_field("cf.zone.name", Type::Bytes).unwrap();
        builder.add_field("cf.metal.id", Type::Bytes).unwrap();
        builder.add_field("cf.waf.score", Type::Int).unwrap();
        builder.add_field("cf.waf.action", Type::Bytes).unwrap();
        builder.add_field("cf.ray_id", Type::Bytes).unwrap();

        let scheme = builder.build();

        serde_wasm_bindgen::from_value::<()>(fields)
            .map(|_| WasmScheme(scheme))
            .map_err(into_js_error)
    }

    pub fn parse(&self, s: &str) -> Result<JsValue, JsValue> {
        let filter = self.0.parse(s).map_err(into_js_error)?;
        serde_wasm_bindgen::to_value(&filter).map_err(into_js_error)
    }
}
