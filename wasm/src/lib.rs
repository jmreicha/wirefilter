use wasm_bindgen::prelude::*;
use wirefilter::Scheme;

#[wasm_bindgen]
pub struct WasmScheme(Scheme);

#[allow(clippy::needless_pass_by_value)]
fn into_js_error(err: impl std::error::Error) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

#[wasm_bindgen]
impl WasmScheme {
    #[wasm_bindgen(constructor)]
    pub fn try_from(fields: JsValue) -> Result<WasmScheme, JsValue> {
        let scheme = Scheme! {
            // HTTP Fields
            http.cookie: Bytes,
            http.host: Bytes,
            http.method: Bytes,
            http.referer: Bytes,
            http.request.uri.path: Bytes,
            http.request.uri.query: Bytes,
            http.request.uri.args: Map(Bytes),
            http.request.headers: Map(Bytes),
            http.response.code: Int,
            http.response.headers: Map(Bytes),
            http.ua: Bytes,
            http.x_forwarded_for: Bytes,

            // IP Fields
            ip.src: Ip,
            ip.dst: Ip,
            ip.geoip.country: Bytes,
            ip.geoip.continent: Bytes,
            ip.geoip.asnum: Int,
            ip.geoip.asorg: Bytes,

            // SSL/TLS Fields
            ssl: Bool,
            ssl.protocol: Bytes,
            ssl.cipher: Bytes,

            // TCP Fields
            tcp.port: Int,
            tcp.flags: Int,
            tcp.ports: Int,

            // Cloudflare Specific
            cf.bot_management.score: Int,
            cf.bot_management.verified_bot: Bool,
            cf.bot_management.js_detection.passed: Bool,
            cf.threat_score: Int,
            cf.worker.upstream_zone: Bytes,
            cf.colo.id: Int,
            cf.colo.region: Bytes,
            cf.client.bot: Bool,
            cf.client.browser: Bytes,
            cf.client.device_type: Bytes,
            cf.client.os: Bytes,
            cf.edge.server_port: Int,
            cf.waf.score: Int,
            cf.waf.action: Bytes,
            cf.ray_id: Bytes,

            // Rate Limiting
            rate_limiting.count: Int,
            rate_limiting.period: Int,

            // Cache
            cache.status: Bytes,
            cache.ttl: Int
        }.build();

        serde_wasm_bindgen::from_value::<()>(fields)
            .map(|_| WasmScheme(scheme))
            .map_err(into_js_error)
    }

    pub fn parse(&self, s: &str) -> Result<JsValue, JsValue> {
        let filter = self.0.parse(s).map_err(into_js_error)?;
        serde_wasm_bindgen::to_value(&filter).map_err(into_js_error)
    }
}
