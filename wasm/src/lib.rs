use wasm_bindgen::prelude::*;
use wirefilter::{Scheme, Type, LhsValue, FunctionArgs, SimpleFunctionDefinition, SimpleFunctionParam, FunctionArgKind, SimpleFunctionImpl};

#[wasm_bindgen]
pub struct WasmScheme(Scheme);

#[allow(clippy::needless_pass_by_value)]
fn into_js_error(err: impl std::error::Error) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

fn lower<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    use std::borrow::Cow;

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

        // SSL/TLS Fields
        builder.add_field("ssl", Type::Bool).unwrap();
        builder.add_field("ssl.protocol", Type::Bytes).unwrap();
        builder.add_field("ssl.cipher", Type::Bytes).unwrap();

        // TCP Fields
        builder.add_field("tcp.port", Type::Int).unwrap();
        builder.add_field("tcp.flags", Type::Int).unwrap();
        builder.add_field("tcp.ports", Type::Int).unwrap();

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

        // Rate Limiting
        builder.add_field("rate_limiting.count", Type::Int).unwrap();
        builder.add_field("rate_limiting.period", Type::Int).unwrap();

        // Cache
        builder.add_field("cache.status", Type::Bytes).unwrap();
        builder.add_field("cache.ttl", Type::Int).unwrap();

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
