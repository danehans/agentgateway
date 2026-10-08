use std::collections::HashSet;

use itertools::Itertools;
use serde_json::{Value, json};

use super::{JWTValidationOptions, JwkError, Jwt, LocalJwtConfig, Mode, Provider, TokenError};
use crate::telemetry::log::MetricsConfig;

type ProviderInfo = (&'static str, &'static str, &'static str);

fn bearer_location() -> crate::http::auth::AuthorizationLocation {
	crate::http::auth::AuthorizationLocation::bearer_header()
}

// Deserialization: missing jwtValidationOptions defaults required_claims to ["exp"]
#[test]
fn test_deserialize_missing_jwt_validation_options_defaults_to_exp() {
	let json = r#"{
		"issuer": "https://example.com",
		"jwks": { "url": "https://example.com/.well-known/jwks.json" }
	}"#;
	let config: LocalJwtConfig = serde_json::from_str(json).unwrap();
	match config {
		LocalJwtConfig::Single {
			jwt_validation_options,
			..
		} => {
			assert_eq!(
				jwt_validation_options.required_claims,
				HashSet::from(["exp".to_owned()]),
				"missing jwtValidationOptions should default required_claims to [\"exp\"]"
			);
		},
		_ => panic!("expected Single variant"),
	}
}

// Deserialization: jwtValidationOptions present but requiredClaims omitted defaults to ["exp"]
#[test]
fn test_deserialize_jwt_validation_options_without_required_claims_defaults_to_exp() {
	let json = r#"{
		"issuer": "https://example.com",
		"jwks": { "url": "https://example.com/.well-known/jwks.json" },
		"jwtValidationOptions": {}
	}"#;
	let config: LocalJwtConfig = serde_json::from_str(json).unwrap();
	match config {
		LocalJwtConfig::Single {
			jwt_validation_options,
			..
		} => {
			assert_eq!(
				jwt_validation_options.required_claims,
				HashSet::from(["exp".to_owned()]),
				"omitted requiredClaims should default to [\"exp\"]"
			);
		},
		_ => panic!("expected Single variant"),
	}
}

// Deserialization: explicit empty requiredClaims results in empty set
#[test]
fn test_deserialize_empty_required_claims() {
	let json = r#"{
		"issuer": "https://example.com",
		"jwks": { "url": "https://example.com/.well-known/jwks.json" },
		"jwtValidationOptions": { "requiredClaims": [] }
	}"#;
	let config: LocalJwtConfig = serde_json::from_str(json).unwrap();
	match config {
		LocalJwtConfig::Single {
			jwt_validation_options,
			..
		} => {
			assert!(
				jwt_validation_options.required_claims.is_empty(),
				"explicit empty requiredClaims should be empty"
			);
		},
		_ => panic!("expected Single variant"),
	}
}

// Deserialization: Multi variant with jwtValidationOptions per provider
#[test]
fn test_deserialize_multi_provider_with_jwt_validation_options() {
	let json = r#"{
		"providers": [
			{
				"issuer": "https://idp-1.example.com",
				"jwks": { "url": "https://idp-1.example.com/.well-known/jwks.json" },
				"jwtValidationOptions": { "requiredClaims": [] }
			},
			{
				"issuer": "https://idp-2.example.com",
				"jwks": { "url": "https://idp-2.example.com/.well-known/jwks.json" },
				"jwtValidationOptions": { "requiredClaims": ["exp", "nbf"] }
			}
		]
	}"#;
	let config: LocalJwtConfig = serde_json::from_str(json).unwrap();
	match config {
		LocalJwtConfig::Multi { providers, .. } => {
			assert_eq!(providers.len(), 2);
			assert!(
				providers[0]
					.jwt_validation_options
					.required_claims
					.is_empty(),
				"first provider should have empty required_claims"
			);
			assert_eq!(
				providers[1].jwt_validation_options.required_claims,
				HashSet::from(["exp".to_owned(), "nbf".to_owned()]),
				"second provider should require exp and nbf"
			);
		},
		_ => panic!("expected Multi variant"),
	}
}

// Deserialization: the old key name "validationOptions" is rejected
#[test]
fn test_deserialize_rejects_old_validation_options_key() {
	let json = r#"{
		"issuer": "https://example.com",
		"jwks": { "url": "https://example.com/.well-known/jwks.json" },
		"validationOptions": { "requiredClaims": [] }
	}"#;
	let result = serde_json::from_str::<LocalJwtConfig>(json);
	assert!(
		result.is_err(),
		"old key 'validationOptions' should be rejected by deny_unknown_fields"
	);
}

#[test]
pub fn test_azure_jwks() {
	// Regression test for https://github.com/agentgateway/agentgateway/issues/477
	let azure_ad = json!({
		"keys": [{
			"kty": "RSA",
			"use": "sig",
			"kid": "PoVKeirIOvmTyLQ9G9BenBwos7k",
			"x5t": "PoVKeirIOvmTyLQ9G9BenBwos7k",
			"n": "ruYyUq1ElSb8QCCt0XWWRSFpUq0JkyfEvvlCa4fPDi0GZbSGgJg3qYa0co2RsBIYHczXkc71kHVpktySAgYK1KMK264e-s7Vymeq-ypHEDpRsaWric_kKEIvKZzRsyUBUWf0CUhtuUvAbDTuaFnQ4g5lfoa7u3vtsv1za5Gmn6DUPirrL_-xqijP9IsHGUKaTmB4M_qnAu6vUHCpXZnN0YTJDoK7XrVJFaKj8RrTdJB89GFJeTFHA2OX472ToyLdCDn5UatYwmht62nXGlH7_G1kW1YMpeSSwzpnMEzUUk7A8UXrvFTHXEpfXhsv0LA59dm9Hi1mIXaOe1w-icA_rQ",
			"e": "AQAB",
			"x5c": [
				"MIIC/jCCAeagAwIBAgIJAM52mWWK+FEeMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjUwMzIwMDAwNTAyWhcNMzAwMzIwMDAwNTAyWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAruYyUq1ElSb8QCCt0XWWRSFpUq0JkyfEvvlCa4fPDi0GZbSGgJg3qYa0co2RsBIYHczXkc71kHVpktySAgYK1KMK264e+s7Vymeq+ypHEDpRsaWric/kKEIvKZzRsyUBUWf0CUhtuUvAbDTuaFnQ4g5lfoa7u3vtsv1za5Gmn6DUPirrL/+xqijP9IsHGUKaTmB4M/qnAu6vUHCpXZnN0YTJDoK7XrVJFaKj8RrTdJB89GFJeTFHA2OX472ToyLdCDn5UatYwmht62nXGlH7/G1kW1YMpeSSwzpnMEzUUk7A8UXrvFTHXEpfXhsv0LA59dm9Hi1mIXaOe1w+icA/rQIDAQABoyEwHzAdBgNVHQ4EFgQUcZ2MLLOas+d9WbkFSnPdxag09YIwDQYJKoZIhvcNAQELBQADggEBABPXBmwv703IlW8Zc9Kj7W215+vyM5lrJjUubnl+s8vQVXvyN7bh5xP2hzEKWb+u5g/brSIKX/A7qP3m/z6C8R9GvP5WRtF2w1CAxYZ9TWTzTS1La78edME546QejjveC1gX9qcLbEwuLAbYpau2r3vlIqgyXo+8WLXA0neGIRa2JWTNy8FJo0wnUttGJz9LQE4L37nR3HWIxflmOVgbaeyeaj2VbzUE7MIHIkK1bqye2OiKU82w1QWLV/YCny0xdLipE1g2uNL8QVob8fTU2zowd2j54c1YTBDy/hTsxpXfCFutKwtELqWzYxKTqYfrRCc1h0V4DGLKzIjtggTC+CY="
			],
			"cloud_instance_name": "microsoftonline.com",
			"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
	}]});
	let jwks = serde_json::from_value(azure_ad).unwrap();
	let p = Provider::from_jwks(
		jwks,
		"https://login.microsoftonline.com/test/v2.0".to_string(),
		Some(vec!["test-aud".to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	assert_eq!(
		p.keys.keys().collect_vec(),
		vec!["PoVKeirIOvmTyLQ9G9BenBwos7k"]
	);
}

#[test]
pub fn test_basic_jwks() {
	let azure_ad = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "XhO06x8JjWH1wwkWkyeEUxsooGEWoEdidEpwyd_hmuI",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(azure_ad).unwrap();
	let p = Provider::from_jwks(
		jwks,
		"https://example.com".to_string(),
		Some(vec!["test-aud".to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	assert_eq!(
		p.keys.keys().collect_vec(),
		vec!["XhO06x8JjWH1wwkWkyeEUxsooGEWoEdidEpwyd_hmuI"]
	);
}

#[test]
pub fn test_ed25519_jwks() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "OKP",
				"kid": "ed25519-kid",
				"crv": "Ed25519",
				"alg": "EdDSA",
				"x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let p = Provider::from_jwks(
		jwks,
		"https://example.com".to_string(),
		Some(vec!["test-aud".to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	assert_eq!(p.keys.keys().collect_vec(), vec!["ed25519-kid"]);
	assert_eq!(
		p.keys["ed25519-kid"].validation.algorithms,
		vec![jsonwebtoken::Algorithm::EdDSA]
	);
}

#[test]
pub fn test_ed25519_jwt_validation() {
	// Test fixture from jsonwebtoken 10.3.0 tests/eddsa/private_ed25519_key.pk8.
	const ED25519_PRIVATE_KEY: &[u8] = &[
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
		0x6a, 0xc3, 0xfd, 0xee, 0xee, 0x29, 0x8a, 0x92, 0x63, 0x8b, 0x70, 0x0c, 0x4b, 0x11, 0x7c, 0xc3,
		0x2e, 0x2d, 0x2a, 0xce, 0x0d, 0xfd, 0x78, 0x76, 0x94, 0xe2, 0x4c, 0xae, 0x8a, 0xd5, 0x82, 0x34,
	];

	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "OKP",
				"kid": "ed25519-kid",
				"crv": "Ed25519",
				"x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let issuer = "https://example.com";
	let aud = "test-aud";
	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![aud.to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![provider],
		location: bearer_location(),
		preserve_token: false,
	};
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let claims = json!({
		"iss": issuer,
		"aud": aud,
		"sub": "test-user",
		"exp": now + 600,
	});
	let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
	header.kid = Some("ed25519-kid".to_string());
	let token = jsonwebtoken::encode(
		&header,
		&claims,
		&jsonwebtoken::EncodingKey::from_ed_der(ED25519_PRIVATE_KEY),
	)
	.unwrap();

	let claims = jwt.validate_claims(&token).unwrap();
	assert_eq!(
		claims.inner.get("sub"),
		Some(&serde_json::Value::String("test-user".to_string()))
	);
}

#[test]
pub fn test_okp_non_ed25519_curve_rejected() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "OKP",
				"kid": "okp-p256-kid",
				"crv": "P-256",
				"x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let result = Provider::from_jwks(
		jwks,
		"https://example.com".to_string(),
		Some(vec!["test-aud".to_string()]),
		JWTValidationOptions::default(),
	);
	assert!(matches!(result, Err(JwkError::UnsupportedCurve { .. })));
}

fn setup_test_jwt() -> (Jwt, &'static str, &'static str, &'static str) {
	setup_test_jwt_with_required_claims(JWTValidationOptions::default().required_claims)
}

fn setup_test_jwt_with_required_claims(
	required_claims: HashSet<String>,
) -> (Jwt, &'static str, &'static str, &'static str) {
	setup_test_jwt_with_options(JWTValidationOptions {
		required_claims,
		..Default::default()
	})
}

fn setup_test_jwt_with_options(
	options: JWTValidationOptions,
) -> (Jwt, &'static str, &'static str, &'static str) {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "XhO06x8JjWH1wwkWkyeEUxsooGEWoEdidEpwyd_hmuI",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();

	let issuer = "https://example.com";
	let allowed_aud = "allowed-aud";
	let kid = "XhO06x8JjWH1wwkWkyeEUxsooGEWoEdidEpwyd_hmuI";

	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![allowed_aud.to_string()]),
		options,
	)
	.unwrap();

	(
		Jwt {
			mode: Mode::Strict,
			providers: vec![provider],
			location: bearer_location(),
			preserve_token: false,
		},
		kid,
		issuer,
		allowed_aud,
	)
}

fn build_signed_token(kid: &str, iss: &str, aud: &str, exp: u64) -> String {
	build_signed_token_with_payload(kid, json!({ "iss": iss, "aud": aud, "exp": exp }))
}

fn build_signed_token_with_payload(kid: &str, payload: serde_json::Value) -> String {
	build_signed_token_with_type(kid, payload, Some("JWT"))
}

fn build_signed_token_with_type(
	kid: &str,
	payload: serde_json::Value,
	typ: Option<&str>,
) -> String {
	// Test key matching the P-256 public coordinates in the JWKS fixtures.
	const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgltxBTVDLg7C6vE1T
7OtwJIZ/dpm8ygE2MBTjPCY3hgahRANCAARYzu50EeBrT0rELmTGroaGtn0zdjxL
1lOGr9fGw5wOGcXO0+Gn5F5sIxGyTM0FwnUHFNz2SoixZR5dtxhNc+Lo
-----END PRIVATE KEY-----
";
	crate::crypto::jwt::init();
	let header = jsonwebtoken::Header {
		alg: jsonwebtoken::Algorithm::ES256,
		kid: Some(kid.to_string()),
		typ: typ.map(str::to_owned),
		..Default::default()
	};
	let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
	jsonwebtoken::encode(&header, &payload, &key).unwrap()
}

#[test]
pub fn test_configured_issuer_and_audiences_require_claims() {
	use std::time::{SystemTime, UNIX_EPOCH};

	use jsonwebtoken::errors::ErrorKind;

	// Even an explicitly empty requiredClaims list cannot make identity constraints optional.
	let (jwt, kid, issuer, allowed_aud) = setup_test_jwt_with_required_claims(HashSet::new());
	let exp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs()
		+ 600;

	let cases = [
		("aud", json!({ "iss": issuer, "exp": exp })),
		("iss", json!({ "aud": allowed_aud, "exp": exp })),
	];
	for (missing_claim, payload) in cases {
		let token = build_signed_token_with_payload(kid, payload);
		match jwt.validate_claims(&token) {
			Err(TokenError::Invalid(error)) => assert!(
				matches!(error.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == missing_claim),
				"expected missing {missing_claim}, got {error:?}"
			),
			other => panic!("expected missing {missing_claim}, got {other:?}"),
		}
	}
}

fn build_unsigned_token_without_kid(iss: &str, aud: &str, exp: u64) -> String {
	use base64::Engine as _;
	use base64::engine::general_purpose::URL_SAFE_NO_PAD;
	let header = json!({ "alg": "ES256" });
	let payload = json!({ "iss": iss, "aud": aud, "exp": exp });
	let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
	let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
	let s = URL_SAFE_NO_PAD.encode(b"sig");
	format!("{h}.{p}.{s}")
}

#[test]
fn test_nbf_validation() {
	use jsonwebtoken::errors::ErrorKind;

	let now = jsonwebtoken::get_current_timestamp();
	for required_claims in [
		JWTValidationOptions::default().required_claims,
		HashSet::new(),
		HashSet::from(["exp".to_owned(), "nbf".to_owned()]),
	] {
		let (jwt, kid, issuer, aud) = setup_test_jwt_with_required_claims(required_claims);
		for (nbf, accepted) in [(now - 600, true), (now + 30, true), (now + 864_000, false)] {
			let token = build_signed_token_with_payload(
				kid,
				json!({ "iss": issuer, "aud": aud, "exp": now + 900_000, "nbf": nbf }),
			);
			let result = jwt.validate_claims(&token);
			if accepted {
				assert!(result.is_ok(), "nbf={nbf}: {result:?}");
			} else {
				assert!(matches!(
					result,
					Err(TokenError::Invalid(error)) if *error.kind() == ErrorKind::ImmatureSignature
				));
			}
		}
	}
}

// Validate specific rejection reasons for tokens: audience, issuer, expiry, missing kid, unknown kid
#[test]
pub fn test_jwt_rejections_table() {
	use std::time::{SystemTime, UNIX_EPOCH};

	use jsonwebtoken::errors::ErrorKind;

	let (jwt, kid, issuer, allowed_aud) = setup_test_jwt();
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();

	#[derive(Copy, Clone)]
	enum Expected {
		Aud,
		Iss,
		Exp,
	}
	let cases = [
		(
			"aud_mismatch",
			issuer,
			"wrong-aud",
			now + 600,
			Expected::Aud,
		),
		(
			"iss_mismatch",
			"https://wrong.example.com",
			allowed_aud,
			now + 600,
			Expected::Iss,
		),
		("expired", issuer, allowed_aud, now - 100_000, Expected::Exp),
	];

	for (name, iss, aud, exp, expected) in cases {
		let token = build_signed_token(kid, iss, aud, exp);
		let res = jwt.validate_claims(&token);
		match res {
			Err(TokenError::Invalid(e)) => match expected {
				Expected::Aud => assert!(matches!(e.kind(), ErrorKind::InvalidAudience), "{name}"),
				Expected::Iss => assert!(matches!(e.kind(), ErrorKind::InvalidIssuer), "{name}"),
				Expected::Exp => assert!(matches!(e.kind(), ErrorKind::ExpiredSignature), "{name}"),
			},
			other => panic!("{name}: expected Invalid(..), got {:?}", other),
		}
	}

	// MissingKeyId: token header without kid
	let token_no_kid = build_unsigned_token_without_kid(issuer, allowed_aud, now + 600);
	let res = jwt.validate_claims(&token_no_kid);
	assert!(matches!(res, Err(TokenError::MissingKeyId)));

	// UnknownKeyId: kid not found among providers
	let token_unknown_kid = build_signed_token("non-existent-kid", issuer, allowed_aud, now + 600);
	let res = jwt.validate_claims(&token_unknown_kid);
	assert!(matches!(res, Err(TokenError::UnknownKeyId(_))));
}

// Strict mode: reject requests that are missing the Authorization header
#[tokio::test]
pub async fn test_apply_strict_missing_token() {
	// Build a Strict-mode Jwt with no providers (not needed for missing-token path)
	let jwt = super::Jwt {
		mode: super::Mode::Strict,
		providers: vec![],
		location: bearer_location(),
		preserve_token: false,
	};

	// Minimal Request without Authorization header
	let mut req = crate::http::Request::new(crate::http::Body::empty());

	// Minimal RequestLog
	let mut req_log = make_min_req_log();

	let res = jwt.apply(Some(&mut req_log), &mut req).await;
	assert!(matches!(res, Err(super::TokenError::Missing)));
}

// Permissive mode: allow requests without a token and do not attach claims
#[tokio::test]
pub async fn test_apply_permissive_no_token_ok() {
	let base = setup_test_jwt().0;
	let jwt = Jwt {
		mode: Mode::Permissive,
		providers: base.providers.clone(),
		location: bearer_location(),
		preserve_token: false,
	};
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(res.is_ok());
	assert!(req.extensions().get::<super::Claims>().is_none());
}

// Permissive mode: invalid token does not fail the request and keeps the header
#[tokio::test]
pub async fn test_apply_permissive_invalid_token_ok_and_keeps_header() {
	let (base, kid, issuer, allowed_aud) = setup_test_jwt();
	let jwt = Jwt {
		mode: Mode::Permissive,
		providers: base.providers.clone(),
		location: bearer_location(),
		preserve_token: false,
	};
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	req.headers_mut().insert(
		crate::http::header::AUTHORIZATION,
		crate::http::HeaderValue::from_static("Bearer invalid-token"),
	);
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(res.is_ok());
	// Header should remain present on failure in permissive mode
	assert!(
		req
			.headers()
			.get(crate::http::header::AUTHORIZATION)
			.is_some()
	);
	assert!(req.extensions().get::<super::Claims>().is_none());
	let _ = (kid, issuer, allowed_aud); // silence unused
}

// Permissive mode: valid token attaches claims and removes the Authorization header
#[tokio::test]
pub async fn test_apply_permissive_valid_token_inserts_claims_and_removes_header() {
	use std::time::{SystemTime, UNIX_EPOCH};
	let (base, kid, issuer, allowed_aud) = setup_test_jwt();
	let jwt = Jwt {
		mode: Mode::Permissive,
		providers: base.providers.clone(),
		location: bearer_location(),
		preserve_token: false,
	};
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let token = build_signed_token(kid, issuer, allowed_aud, now + 600);
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	req.headers_mut().insert(
		crate::http::header::AUTHORIZATION,
		crate::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
	);
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(res.is_ok());
	assert!(
		req
			.headers()
			.get(crate::http::header::AUTHORIZATION)
			.is_none()
	);
	assert!(req.extensions().get::<super::Claims>().is_some());
}

// Optional mode: allow requests without a token and do not attach claims
#[tokio::test]
pub async fn test_apply_optional_no_token_ok() {
	let base = setup_test_jwt().0;
	let jwt = Jwt {
		mode: Mode::Optional,
		providers: base.providers.clone(),
		location: bearer_location(),
		preserve_token: false,
	};
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(res.is_ok());
	assert!(req.extensions().get::<super::Claims>().is_none());
}

// Optional mode: if a token is present but invalid, return an error
#[tokio::test]
pub async fn test_apply_optional_invalid_token_err() {
	let base = setup_test_jwt().0;
	let jwt = Jwt {
		mode: Mode::Optional,
		providers: base.providers.clone(),
		location: bearer_location(),
		preserve_token: false,
	};
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	req.headers_mut().insert(
		crate::http::header::AUTHORIZATION,
		crate::http::HeaderValue::from_static("Bearer invalid-token"),
	);
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(matches!(res, Err(TokenError::InvalidHeader(_))));
}

#[tokio::test]
pub async fn test_apply_optional_valid_token_respects_preserve_token() {
	use std::time::{SystemTime, UNIX_EPOCH};
	let (base, kid, issuer, allowed_aud) = setup_test_jwt();
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let token = build_signed_token(kid, issuer, allowed_aud, now + 600);
	for preserve_token in [false, true] {
		let jwt = Jwt {
			mode: Mode::Optional,
			providers: base.providers.clone(),
			location: bearer_location(),
			preserve_token,
		};
		let mut req = crate::http::Request::new(crate::http::Body::empty());
		req.headers_mut().insert(
			crate::http::header::AUTHORIZATION,
			crate::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
		);
		let mut log = make_min_req_log();
		let res = jwt.apply(Some(&mut log), &mut req).await;
		assert!(res.is_ok());
		assert_eq!(
			req
				.headers()
				.get(crate::http::header::AUTHORIZATION)
				.is_some(),
			preserve_token
		);
		assert!(req.extensions().get::<super::Claims>().is_some());
	}
}

#[tokio::test]
pub async fn test_apply_query_parameter_token_inserts_claims_and_removes_query_param() {
	use std::time::{SystemTime, UNIX_EPOCH};

	let (base, kid, issuer, allowed_aud) = setup_test_jwt();
	let jwt = Jwt {
		mode: Mode::Strict,
		providers: base.providers.clone(),
		location: crate::http::auth::AuthorizationLocation::QueryParameter {
			name: "token".into(),
		},
		preserve_token: false,
	};
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let token = build_signed_token(kid, issuer, allowed_aud, now + 600);
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	*req.uri_mut() = format!("http://example.com/?token={token}&keep=yes")
		.parse()
		.unwrap();
	let mut log = make_min_req_log();
	let res = jwt.apply(Some(&mut log), &mut req).await;
	assert!(res.is_ok());
	assert_eq!(req.uri().to_string(), "http://example.com/?keep=yes");
	assert!(req.extensions().get::<super::Claims>().is_some());
}

fn make_min_req_log() -> crate::telemetry::log::RequestLog {
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};
	use std::sync::Arc;

	use frozen_collections::FzHashSet;
	use prometheus_client::registry::Registry;

	use crate::telemetry::log;
	use crate::telemetry::log::{LoggingFields, RequestLog};
	use crate::telemetry::metrics::Metrics;
	use crate::transport::stream::TCPConnectionInfo;

	let log_cfg = log::Config {
		filter: None,
		fields: LoggingFields::default(),
		database_fields: Default::default(),
		level: "info".to_string(),
		format: crate::LoggingFormat::Text,
		database: None,
	};
	let cel = log::CelLogging::new(log_cfg, MetricsConfig::default());
	let mut prom = Registry::default();
	let metrics = Arc::new(Metrics::new(
		&mut prom,
		FzHashSet::default(),
		Default::default(),
	));
	let start = agent_core::Timestamp::now();
	let tcp_info = TCPConnectionInfo {
		peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
		local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
		start: start.as_instant(),
		raw_peer_addr: None,
	};
	RequestLog::new(
		cel,
		metrics,
		crate::llm::catalog::ModelCatalog::empty(),
		start,
		tcp_info,
	)
}

fn setup_test_multi_jwt() -> (Jwt, ProviderInfo, ProviderInfo) {
	setup_test_multi_jwt_with_kids("kid-1", "kid-2")
}

fn setup_test_multi_jwt_with_kids(
	kid1: &'static str,
	kid2: &'static str,
) -> (Jwt, ProviderInfo, ProviderInfo) {
	let jwks1 = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": kid1,
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks2 = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": kid2,
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks1 = serde_json::from_value(jwks1).unwrap();
	let jwks2 = serde_json::from_value(jwks2).unwrap();

	let issuer1 = "https://issuer-1.example.com";
	let issuer2 = "https://issuer-2.example.com";
	let aud1 = "aud-1";
	let aud2 = "aud-2";

	let provider1 = Provider::from_jwks(
		jwks1,
		issuer1.to_string(),
		Some(vec![aud1.to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();

	let provider2 = Provider::from_jwks(
		jwks2,
		issuer2.to_string(),
		Some(vec![aud2.to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();

	(
		Jwt {
			mode: Mode::Strict,
			providers: vec![provider1, provider2],
			location: bearer_location(),
			preserve_token: false,
		},
		(kid1, issuer1, aud1),
		(kid2, issuer2, aud2),
	)
}

// Multiple providers: tokens matching either provider's kid/issuer/audience are accepted
#[test]
pub fn test_validate_claims_multi_providers_accepts_both() {
	use std::time::{SystemTime, UNIX_EPOCH};
	let (jwt, (kid1, iss1, aud1), (kid2, iss2, aud2)) = setup_test_multi_jwt();
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();

	let token1 = build_signed_token(kid1, iss1, aud1, now + 600);
	let token2 = build_signed_token(kid2, iss2, aud2, now + 600);

	assert!(jwt.validate_claims(&token1).is_ok());
	assert!(jwt.validate_claims(&token2).is_ok());
}

// Multiple providers that publish the same key with the same kid.
// Multiple tokens are validated, one per issuer, and both are accepted.
#[test]
pub fn test_validate_claims_multi_providers_shared_kid_accepts_both() {
	let (jwt, (kid1, iss1, aud1), (kid2, iss2, aud2)) =
		setup_test_multi_jwt_with_kids("shared-kid", "shared-kid");
	let now = jsonwebtoken::get_current_timestamp();

	for (kid, iss, aud) in [(kid1, iss1, aud1), (kid2, iss2, aud2)] {
		let token = build_signed_token(kid, iss, aud, now + 600);
		let claims = jwt
			.validate_claims(&token)
			.unwrap_or_else(|e| panic!("token from {iss} should validate: {e:?}"));
		assert_eq!(claims.inner.get("iss"), Some(&json!(iss)));
	}
}

// Multiple providers that publish the same key under the same kid.
// The token's aud does not match either provider, so the token is rejected with InvalidAudience by the correct issuer.
#[test]
pub fn test_validate_claims_multi_providers_shared_kid_reports_matching_provider_error() {
	use jsonwebtoken::errors::ErrorKind;

	let (jwt, (kid1, iss1, aud1), (kid2, iss2, _)) =
		setup_test_multi_jwt_with_kids("shared-kid", "shared-kid");
	let now = jsonwebtoken::get_current_timestamp();

	for (kid, iss) in [(kid1, iss1), (kid2, iss2)] {
		let token = build_signed_token(kid, iss, "wrong-aud", now + 600);
		let result = jwt.validate_claims(&token);
		assert!(
			matches!(
				result,
				Err(TokenError::Invalid(ref error)) if *error.kind() == ErrorKind::InvalidAudience
			),
			"{iss}: expected InvalidAudience, got {result:?}"
		);
	}

	// No provider for the issuer, but the kid matches both providers.
	let token = build_signed_token(kid1, "https://unknown.example.com", aud1, now + 600);
	let result = jwt.validate_claims(&token);
	assert!(
		matches!(
			result,
			Err(TokenError::Invalid(ref error)) if *error.kind() == ErrorKind::InvalidIssuer
		),
		"expected InvalidIssuer, got {result:?}"
	);

	// No provider for the kid, but the issuer matches one provider.
	let token = build_signed_token("non-existent-kid", iss1, aud1, now + 600);
	assert!(matches!(
		jwt.validate_claims(&token),
		Err(TokenError::UnknownKeyId(_))
	));
}

// Multiple provider with the same kid but have different issuers.
// The provider with the matching issuer is used to validate the token, not just the kid.
#[test]
pub fn test_validate_claims_multi_providers_colliding_kid_different_keys() {
	let ed25519_jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "OKP",
				"kid": "shared-kid",
				"crv": "Ed25519",
				"x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"
			}
		]
	});
	let ec_jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "shared-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let ed25519_provider = Provider::from_jwks(
		serde_json::from_value(ed25519_jwks).unwrap(),
		"https://issuer-1.example.com".to_string(),
		Some(vec!["aud-1".to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	let ec_provider = Provider::from_jwks(
		serde_json::from_value(ec_jwks).unwrap(),
		"https://issuer-2.example.com".to_string(),
		Some(vec!["aud-2".to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();
	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![ed25519_provider, ec_provider],
		location: bearer_location(),
		preserve_token: false,
	};

	// Sign with the second provider's key and validate with the second provider's iss and aud.
	let token = build_signed_token(
		"shared-kid",
		"https://issuer-2.example.com",
		"aud-2",
		jsonwebtoken::get_current_timestamp() + 600,
	);
	let result = jwt.validate_claims(&token);
	assert!(result.is_ok(), "expected token to validate, got {result:?}");
}

// Multiple providers share the same issuer and kid, but the audiences are different.
// The provider with the matching audience, issuer, and kid is used to validate the token, not just the iss/kid.
#[test]
pub fn test_validate_claims_multi_providers_same_issuer() {
	use jsonwebtoken::errors::ErrorKind;

	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "shared-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let issuer = "https://issuer.example.com";
	let providers = ["aud-1", "aud-2"].map(|aud| {
		Provider::from_jwks(
			serde_json::from_value(jwks.clone()).unwrap(),
			issuer.to_string(),
			Some(vec![aud.to_string()]),
			JWTValidationOptions::default(),
		)
		.unwrap()
	});
	let jwt = Jwt {
		mode: Mode::Strict,
		providers: providers.into(),
		location: bearer_location(),
		preserve_token: false,
	};
	let now = jsonwebtoken::get_current_timestamp();

	for aud in ["aud-1", "aud-2"] {
		let token = build_signed_token("shared-kid", issuer, aud, now + 600);
		let result = jwt.validate_claims(&token);
		assert!(
			result.is_ok(),
			"{aud}: expected token to validate, got {result:?}"
		);
	}

	let token = build_signed_token("shared-kid", issuer, "aud-3", now + 600);
	let result = jwt.validate_claims(&token);
	assert!(
		matches!(
			result,
			Err(TokenError::Invalid(ref error)) if *error.kind() == ErrorKind::InvalidAudience
		),
		"expected InvalidAudience, got {result:?}"
	);
}

// Empty required_claims accepts tokens without exp claim
#[test]
pub fn test_empty_required_claims_accepts_token_without_exp() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "no-exp-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let issuer = "https://no-exp-idp.example.com";
	let aud = "no-exp-aud";
	let kid = "no-exp-kid";

	let jwt_validation_options = JWTValidationOptions {
		required_claims: HashSet::new(),
		..Default::default()
	};

	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![aud.to_string()]),
		jwt_validation_options,
	)
	.unwrap();

	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![provider],
		location: bearer_location(),
		preserve_token: false,
	};

	let token = build_signed_token_with_payload(
		kid,
		json!({ "iss": issuer, "aud": aud, "sub": "test-user" }),
	);
	let result = jwt.validate_claims(&token);
	assert!(
		result.is_ok(),
		"empty required_claims should accept tokens without exp claim"
	);

	let claims = result.unwrap();
	assert_eq!(
		claims.inner.get("sub"),
		Some(&serde_json::Value::String("test-user".to_string()))
	);
}

// Default required_claims (["exp"]): rejects tokens without exp claim
#[test]
pub fn test_default_required_claims_rejects_token_without_exp() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "default-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let issuer = "https://default-idp.example.com";
	let aud = "default-aud";
	let kid = "default-kid";

	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![aud.to_string()]),
		JWTValidationOptions::default(),
	)
	.unwrap();

	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![provider],
		location: bearer_location(),
		preserve_token: false,
	};

	let token = build_signed_token_with_payload(
		kid,
		json!({ "iss": issuer, "aud": aud, "sub": "test-user" }),
	);
	let result = jwt.validate_claims(&token);
	assert!(
		result.is_err(),
		"default required_claims ([\"exp\"]) should reject tokens without exp claim"
	);
}

// Empty required_claims still rejects expired tokens (exp is validated if present)
#[test]
pub fn test_empty_required_claims_still_rejects_expired_tokens() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "expired-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let issuer = "https://expired-idp.example.com";
	let aud = "expired-aud";
	let kid = "expired-kid";

	let jwt_validation_options = JWTValidationOptions {
		required_claims: HashSet::new(),
		..Default::default()
	};

	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![aud.to_string()]),
		jwt_validation_options,
	)
	.unwrap();

	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![provider],
		location: bearer_location(),
		preserve_token: false,
	};

	let token = build_signed_token_with_payload(
		kid,
		json!({ "iss": issuer, "aud": aud, "sub": "test-user", "exp": 0 }),
	);
	let result = jwt.validate_claims(&token);
	assert!(
		result.is_err(),
		"empty required_claims should still reject tokens with expired exp claim"
	);
}

// Requiring additional claims (e.g., "nbf") rejects tokens missing those claims
#[test]
pub fn test_required_claims_with_nbf_rejects_missing_nbf() {
	let jwks = json!({
		"keys": [
			{
				"use": "sig",
				"kty": "EC",
				"kid": "nbf-kid",
				"crv": "P-256",
				"alg": "ES256",
				"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
				"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
			}
		]
	});
	let jwks = serde_json::from_value(jwks).unwrap();
	let issuer = "https://nbf-idp.example.com";
	let aud = "nbf-aud";
	let kid = "nbf-kid";

	let jwt_validation_options = JWTValidationOptions {
		required_claims: HashSet::from(["exp".to_owned(), "nbf".to_owned()]),
		..Default::default()
	};

	let provider = Provider::from_jwks(
		jwks,
		issuer.to_string(),
		Some(vec![aud.to_string()]),
		jwt_validation_options,
	)
	.unwrap();

	let jwt = Jwt {
		mode: Mode::Strict,
		providers: vec![provider],
		location: bearer_location(),
		preserve_token: false,
	};

	// Token with exp but without nbf should be rejected when nbf is required
	use std::time::{SystemTime, UNIX_EPOCH};
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let token = build_signed_token(kid, issuer, aud, now + 600);
	let result = jwt.validate_claims(&token);
	assert!(
		result.is_err(),
		"required_claims with nbf should reject tokens missing nbf claim"
	);
}

#[test]
fn test_public_validation_dump_tracks_applied_security_constraints() {
	let key = json!({"kty":"EC","kid":"same-id","crv":"P-256","alg":"ES256",
		"x":"WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
		"y":"xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"});
	let build = |key: serde_json::Value, audiences, required_claims| {
		Provider::from_jwks(
			serde_json::from_value(json!({"keys":[key]})).unwrap(),
			"https://example.com".into(),
			audiences,
			JWTValidationOptions {
				required_claims,
				..Default::default()
			},
		)
		.unwrap()
	};
	let p = build(
		key.clone(),
		Some(vec!["z".into(), "a".into()]),
		HashSet::from(["sub".into(), "exp".into()]),
	);
	let dump = serde_json::to_value(&p).unwrap();
	assert_eq!(dump["validationSummaryVersion"], 1);
	assert_eq!(dump["keys"], json!(["same-id"]));
	let applied = &dump["validation"]["same-id"];
	assert_eq!(applied["audiences"], json!(["a", "z"]));
	assert_eq!(
		applied["requiredClaims"],
		json!(["aud", "exp", "iss", "sub"])
	);
	assert_eq!(applied["algorithms"], json!(["ES256"]));
	assert_eq!(applied["issuers"], json!(["https://example.com"]));
	assert_eq!(applied["validateExp"], true);
	assert_eq!(applied["validateNbf"], true);
	assert_eq!(applied["validateAud"], true);
	assert_eq!(applied["publicKeySha256"].as_str().unwrap().len(), 64);
	assert_eq!(
		applied["publicKeySha256"],
		"2ff287327f3f327b6a15a6c7b8293c4bde468f702802e207f71ec224801623e2"
	);
	let weak = serde_json::to_value(build(key.clone(), None, HashSet::new())).unwrap();
	assert_ne!(dump, weak);
	assert_eq!(weak["validation"]["same-id"]["validateAud"], false);
	let mut changed = key;
	changed["y"] = json!("WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk");
	let changed = serde_json::to_value(build(
		changed,
		Some(vec!["z".into(), "a".into()]),
		HashSet::from(["sub".into(), "exp".into()]),
	))
	.unwrap();
	assert_ne!(
		applied["publicKeySha256"],
		changed["validation"]["same-id"]["publicKeySha256"]
	);
	let raw = serde_json::to_string(&dump).unwrap();
	for field in ["decoding", "private", "WM7ud", "xc7T4", "\"x\"", "\"y\""] {
		assert!(!raw.contains(field));
	}
	assert_eq!(dump, serde_json::to_value(&p).unwrap());
}

fn traffic_profile_options() -> JWTValidationOptions {
	JWTValidationOptions {
		required_claims: HashSet::new(),
		expected_token_type: Some("runtime-traffic+jwt".to_owned()),
		max_token_lifetime_seconds: Some(300),
		required_string_claims: HashSet::from([
			"execution_id".to_owned(),
			"workload_id".to_owned(),
			"jti".to_owned(),
		]),
		non_forwardable_token: false,
	}
}

#[test]
fn typed_profile_checks_signed_header_and_application_claims() {
	let (jwt, kid, issuer, audience) = setup_test_jwt_with_options(traffic_profile_options());
	let now = jsonwebtoken::get_current_timestamp();
	let payload = json!({"iss": issuer, "aud": audience, "iat": now, "exp": now + 300,
        "workload_id": "synthetic-workload", "execution_id": "synthetic-execution", "jti": "synthetic-id"});
	assert!(
		jwt
			.validate_claims(&build_signed_token_with_type(
				kid,
				payload.clone(),
				Some("runtime-traffic+jwt")
			))
			.is_ok()
	);
	for typ in [
		None,
		Some("JWT"),
		Some("RUNTIME-TRAFFIC+jwt"),
		Some("runtime-session+jwt"),
	] {
		assert_eq!(
			jwt
				.validate_claims(&build_signed_token_with_type(kid, payload.clone(), typ))
				.unwrap_err(),
			TokenError::TokenTypeMismatch
		);
	}
	for name in ["execution_id", "workload_id", "jti"] {
		for invalid in [
			Value::Null,
			json!(false),
			json!([]),
			json!(42),
			json!(""),
			json!("x\n"),
			json!("x".repeat(513)),
		] {
			let mut candidate = payload.clone();
			candidate[name] = invalid;
			assert_eq!(
				jwt
					.validate_claims(&build_signed_token_with_type(
						kid,
						candidate,
						Some("runtime-traffic+jwt")
					))
					.unwrap_err(),
				TokenError::TokenStringClaimInvalid
			);
		}
		let mut missing = payload.clone();
		missing.as_object_mut().unwrap().remove(name);
		assert_eq!(
			jwt
				.validate_claims(&build_signed_token_with_type(
					kid,
					missing,
					Some("runtime-traffic+jwt")
				))
				.unwrap_err(),
			TokenError::TokenStringClaimInvalid
		);
	}
}

#[test]
fn typed_profile_requires_bounded_integer_lifetime_even_without_required_claims() {
	let (jwt, kid, issuer, audience) = setup_test_jwt_with_options(traffic_profile_options());
	let now = jsonwebtoken::get_current_timestamp();
	let payload = json!({"iss": issuer, "aud": audience, "iat": now, "exp": now + 300,
        "workload_id": "synthetic-workload", "execution_id": "synthetic-execution", "jti": "synthetic-id"});
	for (iat, exp) in [
		(json!(now + 30), json!(now + 60)),
		(json!(now), json!(now + 301)),
		(json!(now), json!(now)),
		(json!(now), json!(now - 1)),
		(json!(now - 1), json!(now - 1)),
		(Value::Null, json!(now + 60)),
		(json!("0"), json!(now + 60)),
		(json!(-1), json!(now + 60)),
		(json!(now as f64), json!(now + 60)),
		(json!(now), json!("9999999999")),
		(json!(now), json!(u64::MAX)),
	] {
		let mut candidate = payload.clone();
		candidate["iat"] = iat;
		candidate["exp"] = exp;
		assert!(
			jwt
				.validate_claims(&build_signed_token_with_type(
					kid,
					candidate,
					Some("runtime-traffic+jwt")
				))
				.is_err()
		);
	}
	for name in ["iat", "exp"] {
		let mut candidate = payload.clone();
		candidate.as_object_mut().unwrap().remove(name);
		assert!(
			jwt
				.validate_claims(&build_signed_token_with_type(
					kid,
					candidate,
					Some("runtime-traffic+jwt")
				))
				.is_err()
		);
	}
}

#[test]
fn typed_profile_cannot_replace_signature_issuer_or_audience_validation() {
	let (jwt, kid, issuer, audience) = setup_test_jwt_with_options(traffic_profile_options());
	let now = jsonwebtoken::get_current_timestamp();
	let payload = json!({"iss": issuer, "aud": audience, "iat": now, "exp": now + 60,
        "workload_id": "synthetic-workload", "execution_id": "synthetic-execution", "jti": "synthetic-id"});
	for name in ["iss", "aud"] {
		let mut candidate = payload.clone();
		candidate[name] = json!("other-authority");
		assert!(
			jwt
				.validate_claims(&build_signed_token_with_type(
					kid,
					candidate,
					Some("runtime-traffic+jwt")
				))
				.is_err()
		);
	}
	let token = build_signed_token_with_type(kid, payload, Some("runtime-traffic+jwt"));
	let (signed, _) = token.rsplit_once('.').unwrap();
	assert!(jwt.validate_claims(&format!("{signed}.AAAA")).is_err());
}

#[test]
fn typed_profile_refuses_invalid_configuration_and_reports_effective_constraints() {
	let mut invalid = vec![];
	for typ in ["", "type with spaces", "type\n", &"x".repeat(129)] {
		let mut opts = traffic_profile_options();
		opts.expected_token_type = Some(typ.to_owned());
		invalid.push(opts);
	}
	for lifetime in [0, 86_401] {
		let mut opts = traffic_profile_options();
		opts.max_token_lifetime_seconds = Some(lifetime);
		invalid.push(opts);
	}
	for name in ["", "9claim", "claim.with.path", &"x".repeat(129)] {
		let mut opts = traffic_profile_options();
		opts.required_string_claims = HashSet::from([name.to_owned()]);
		invalid.push(opts);
	}
	let mut too_many = traffic_profile_options();
	too_many.required_string_claims = (0..65).map(|index| format!("claim_{index}")).collect();
	invalid.push(too_many);
	for opts in invalid {
		assert!(matches!(
			opts.validate_configuration(),
			Err(JwkError::InvalidValidationProfile)
		));
	}
	let (jwt, _, _, _) = setup_test_jwt_with_options(traffic_profile_options());
	let dump = serde_json::to_value(&jwt.providers[0]).unwrap();
	assert_eq!(dump["validationSummaryVersion"], 2);
	let applied = dump["validation"]
		.as_object()
		.unwrap()
		.values()
		.next()
		.unwrap();
	assert_eq!(applied["expectedTokenType"], "runtime-traffic+jwt");
	assert_eq!(applied["maxTokenLifetimeSeconds"], 300);
	assert_eq!(
		applied["requiredStringClaims"],
		json!(["execution_id", "jti", "workload_id"])
	);
	assert_eq!(applied["leewaySeconds"], 0);
	assert_eq!(applied["requiredClaims"], json!(["aud", "exp", "iss"]));
}

#[tokio::test]
async fn non_forwardable_token_keeps_claims_and_provider_auth_without_raw_access() {
	use secrecy::ExposeSecret;

	use crate::http::auth::AuthorizationLocation;
	let (mut jwt, kid, issuer, aud) = setup_test_jwt_with_options(JWTValidationOptions {
		non_forwardable_token: true,
		..Default::default()
	});
	jwt.location = AuthorizationLocation::Header {
		name: http::HeaderName::from_static("x-runtime-token"),
		prefix: None,
	};
	let token = build_signed_token(kid, issuer, aud, 4_102_444_800);
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	req
		.headers_mut()
		.insert("x-runtime-token", token.parse().unwrap());
	req.headers_mut().insert(
		http::header::AUTHORIZATION,
		"Bearer synthetic-provider-key".parse().unwrap(),
	);
	jwt.apply(None, &mut req).await.unwrap();
	assert!(!req.headers().contains_key("x-runtime-token"));
	assert_eq!(
		req.headers()[http::header::AUTHORIZATION],
		"Bearer synthetic-provider-key"
	);
	let claims = req.extensions().get::<super::Claims>().unwrap();
	assert_eq!(claims.inner["iss"], issuer);
	assert!(claims.jwt.expose_secret().is_empty());
	let expression = crate::cel::Expression::new_strict("jwt.rawToken.unredacted()").unwrap();
	assert_eq!(
		crate::cel::Executor::new_request(&req)
			.eval(&expression)
			.unwrap()
			.json()
			.unwrap(),
		json!("")
	);
	let dump = serde_json::to_value(&jwt).unwrap();
	assert_eq!(dump["providers"][0]["validationSummaryVersion"], 2);
	assert_eq!(
		dump["providers"][0]["validation"][kid]["nonForwardableToken"],
		true
	);
}

#[tokio::test]
async fn non_forwardable_token_rejects_duplicate_carriers() {
	let (jwt, kid, issuer, aud) = setup_test_jwt_with_options(JWTValidationOptions {
		non_forwardable_token: true,
		..Default::default()
	});
	let token = build_signed_token(kid, issuer, aud, 4_102_444_800);
	let mut req = crate::http::Request::new(crate::http::Body::empty());
	for _ in 0..2 {
		req.headers_mut().append(
			http::header::AUTHORIZATION,
			format!("Bearer {token}").parse().unwrap(),
		);
	}
	assert!(matches!(
		jwt.apply(None, &mut req).await,
		Err(TokenError::AmbiguousCredentialCarrier)
	));
	assert!(req.extensions().get::<super::Claims>().is_none());
}

#[tokio::test]
async fn non_forwardable_token_rejects_conflicting_programmatic_configuration() {
	use crate::http::auth::AuthorizationLocation;
	let (base, _, _, _) = setup_test_jwt_with_options(JWTValidationOptions {
		non_forwardable_token: true,
		..Default::default()
	});
	let mut variants = Vec::new();
	for mode in [Mode::Optional, Mode::Permissive] {
		let mut jwt = base.clone();
		jwt.mode = mode;
		variants.push(jwt);
	}
	let mut jwt = base.clone();
	jwt.preserve_token = true;
	variants.push(jwt);
	for location in [
		AuthorizationLocation::QueryParameter {
			name: "token".into(),
		},
		AuthorizationLocation::Cookie {
			name: "token".into(),
		},
		AuthorizationLocation::Expression(std::sync::Arc::new(
			crate::cel::Expression::new_strict("'token'").unwrap(),
		)),
	] {
		let mut jwt = base.clone();
		jwt.location = location;
		variants.push(jwt);
	}
	// An empty key set must not erase the retention constraint.
	let provider = Provider::from_jwks(
		serde_json::from_value(json!({"keys":[]})).unwrap(),
		"issuer".into(),
		None,
		JWTValidationOptions {
			non_forwardable_token: true,
			..Default::default()
		},
	)
	.unwrap();
	variants.push(Jwt::from_providers(
		vec![provider],
		Mode::Optional,
		bearer_location(),
		false,
	));
	for jwt in variants {
		let mut req = crate::http::Request::new(crate::http::Body::empty());
		assert!(matches!(
			jwt.apply(None, &mut req).await,
			Err(TokenError::InvalidCredentialRetention)
		));
	}
}

#[tokio::test]
async fn non_forwardable_token_local_conflicts_rejected_before_loading_keys() {
	for extra in [
		json!({"mode":"optional"}),
		json!({"mode":"permissive"}),
		json!({"preserveToken":true}),
		json!({"location":{"queryParameter":{"name":"token"}}}),
		json!({"location":{"expression":"'token'"}}),
	] {
		let mut config = json!({"mode":"strict", "issuer":"synthetic-issuer", "jwks":{"file":"/nonexistent-must-not-be-read"}, "jwtValidationOptions":{"nonForwardableToken":true}});
		config
			.as_object_mut()
			.unwrap()
			.extend(extra.as_object().unwrap().clone());
		let local: LocalJwtConfig = serde_json::from_value(config).unwrap();
		assert!(matches!(
			local
				.try_into(&crate::resource_manager::ResourceFetcher::files_only())
				.await,
			Err(JwkError::InvalidCredentialRetention)
		));
	}
}

#[test]
fn credential_errors_do_not_render_untrusted_values_or_sources() {
	use std::error::Error;
	let sentinel = "synthetic-sensitive-input";
	for error in [
		TokenError::UnknownKeyId(sentinel.into()),
		TokenError::CredentialRemoval(sentinel.into()),
	] {
		assert!(!format!("{error} {error:?}").contains(sentinel));
		assert!(error.source().is_none());
	}
	let parse = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(sentinel).unwrap_err();
	for error in [
		JwkError::JwksParseError(parse),
		JwkError::JwkLoadError(anyhow::anyhow!(sentinel)),
		JwkError::UnexpectedAlgorithm {
			key_id: sentinel.into(),
			algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
				jsonwebtoken::jwk::OctetKeyParameters {
					key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
					value: sentinel.into(),
				},
			),
		},
	] {
		assert!(!format!("{error} {error:?}").contains(sentinel));
		assert!(error.source().is_none());
	}
}
