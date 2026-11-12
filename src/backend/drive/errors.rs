//! Classification of Drive HTTP responses (SPEC §6.5) — owned by WP3.

use std::time::Duration;

use serde::Deserialize;

use crate::util;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpClass {
    Success,
    Throttle {
        retry_after: Option<std::time::Duration>,
    },
    Transient,
    Unauthorized,
    NotFound,
    Conflict,
    StorageFull,
    DailyUpload,
    DailyDownload,
    ProjectApiQuota,
    AppNotAuthorized,
    AbuseFlag,
    Fatal {
        status: u16,
        reason: String,
        message: String,
    },
}

/// The error envelope of §6.4.1; every part of it may be missing.
#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    error: ErrorBody,
}

#[derive(Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    errors: Vec<ErrorItem>,
}

#[derive(Deserialize, Default)]
struct ErrorItem {
    #[serde(default)]
    reason: Option<String>,
}

/// Table of §6.5; `body` need not be JSON.
pub fn classify(status: u16, retry_after: Option<&str>, body: &[u8]) -> HttpClass {
    if (200..300).contains(&status) {
        return HttpClass::Success;
    }
    // Upload sessions and front ends answer plain text or HTML: then only the status counts.
    let error = serde_json::from_slice::<Envelope>(body)
        .unwrap_or_default()
        .error;
    let reasons: Vec<&str> = error
        .errors
        .iter()
        .filter_map(|e| e.reason.as_deref())
        .collect();
    let message = error.message.as_deref().unwrap_or("");
    let has = |reason: &str| reasons.contains(&reason);
    let mentions =
        |needle: &str| message.contains(needle) || reasons.iter().any(|r| r.contains(needle));
    let throttle = || HttpClass::Throttle {
        retry_after: parse_retry_after(retry_after),
    };

    match status {
        401 => HttpClass::Unauthorized,
        404 => HttpClass::NotFound,
        409 => HttpClass::Conflict,
        403 if has("storageQuotaExceeded") => HttpClass::StorageFull,
        403 if mentions("uploadLimit") => HttpClass::DailyUpload,
        403 if mentions("downloadQuota") => HttpClass::DailyDownload,
        403 if has("dailyLimitExceeded") => HttpClass::ProjectApiQuota,
        403 if has("appNotAuthorizedToFile") => HttpClass::AppNotAuthorized,
        403 if mentions("Abusive") => HttpClass::AbuseFlag,
        429 => throttle(),
        403 if has("rateLimitExceeded")
            || has("userRateLimitExceeded")
            || error.status.as_deref() == Some("RESOURCE_EXHAUSTED") =>
        {
            throttle()
        }
        // No recognised reason is left at this point; the 750 GB/day cap and some front ends
        // only say it in prose.
        403 if {
            let lower = message.to_ascii_lowercase();
            lower.contains("rate limit") || lower.contains("quota")
        } =>
        {
            throttle()
        }
        500 | 502 | 503 | 504 => HttpClass::Transient,
        _ => HttpClass::Fatal {
            status,
            reason: reasons.first().copied().unwrap_or("").to_string(),
            message: message.to_string(),
        },
    }
}

/// `Retry-After`: delay seconds, or an HTTP date.
fn parse_retry_after(v: Option<&str>) -> Option<Duration> {
    let v = v?.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = util::parse_http_date_ms(v)?;
    Some(Duration::from_millis(at.saturating_sub(util::now_ms())))
}

/// `"bytes=0-N"` → `N + 1`; `None` → 0.
pub fn parse_range_header(v: Option<&str>) -> u64 {
    v.and_then(|v| v.trim().strip_prefix("bytes="))
        .and_then(|range| range.split_once('-'))
        .and_then(|(_, last)| last.trim().parse::<u64>().ok())
        .map_or(0, |last| last.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(code: u16, message: &str, status: Option<&str>, reasons: &[&str]) -> Vec<u8> {
        let mut error = serde_json::json!({ "code": code, "message": message });
        if let Some(s) = status {
            error["status"] = s.into();
        }
        if !reasons.is_empty() {
            error["errors"] = reasons
                .iter()
                .map(|r| serde_json::json!({ "domain": "usageLimits", "reason": r, "message": message }))
                .collect();
        }
        serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap()
    }

    fn class(status: u16, message: &str, reasons: &[&str]) -> HttpClass {
        classify(status, None, &envelope(status, message, None, reasons))
    }

    const THROTTLE: HttpClass = HttpClass::Throttle { retry_after: None };

    #[test]
    fn every_row_of_the_table() {
        assert_eq!(classify(200, None, b""), HttpClass::Success);
        assert_eq!(classify(204, None, b""), HttpClass::Success);
        assert_eq!(
            class(401, "Invalid Credentials", &["authError"]),
            HttpClass::Unauthorized
        );
        assert_eq!(
            class(404, "File not found: x", &["notFound"]),
            HttpClass::NotFound
        );
        assert_eq!(class(409, "exists", &["fileIdInUse"]), HttpClass::Conflict);

        assert_eq!(
            class(
                403,
                "The user's Drive storage quota has been exceeded.",
                &["storageQuotaExceeded"]
            ),
            HttpClass::StorageFull,
            "the word quota in the message must not make it a throttle"
        );
        assert_eq!(
            class(
                403,
                "User rate limit exceeded.",
                &["userRateLimitExceeded", "storageQuotaExceeded"]
            ),
            HttpClass::StorageFull,
            "a reason counts wherever it stands in errors[]"
        );
        assert_eq!(
            class(403, "x", &["uploadLimitExceeded"]),
            HttpClass::DailyUpload
        );
        assert_eq!(
            class(403, "User uploadLimit reached", &[]),
            HttpClass::DailyUpload,
            "also when only the message says it"
        );
        assert_eq!(
            class(
                403,
                "The download quota for this file has been exceeded.",
                &["downloadQuotaExceeded"]
            ),
            HttpClass::DailyDownload
        );
        assert_eq!(
            class(403, "downloadQuota used up", &[]),
            HttpClass::DailyDownload
        );
        assert_eq!(
            class(403, "Daily Limit Exceeded", &["dailyLimitExceeded"]),
            HttpClass::ProjectApiQuota
        );
        assert_eq!(
            class(
                403,
                "The user has not granted the app access to the file.",
                &["appNotAuthorizedToFile"]
            ),
            HttpClass::AppNotAuthorized
        );
        assert_eq!(
            class(
                403,
                "This file has been identified as malware or spam.",
                &["cannotDownloadAbusiveFile"]
            ),
            HttpClass::AbuseFlag
        );
        assert_eq!(class(403, "Abusive content", &[]), HttpClass::AbuseFlag);

        assert_eq!(
            class(429, "Too many requests", &["rateLimitExceeded"]),
            THROTTLE
        );
        assert_eq!(classify(429, None, b"slow down"), THROTTLE);
        assert_eq!(
            class(403, "Rate Limit Exceeded", &["rateLimitExceeded"]),
            THROTTLE
        );
        assert_eq!(
            class(403, "User rate limit exceeded.", &["userRateLimitExceeded"]),
            THROTTLE
        );
        assert_eq!(
            class(403, "x", &["forbidden", "userRateLimitExceeded"]),
            THROTTLE,
            "reason only in errors[1]"
        );
        assert_eq!(
            classify(
                403,
                None,
                &envelope(
                    403,
                    "Resource has been exhausted",
                    Some("RESOURCE_EXHAUSTED"),
                    &[]
                )
            ),
            THROTTLE,
            "status without errors[]"
        );
        assert_eq!(class(403, "User Rate Limit Exceeded", &[]), THROTTLE);
        assert_eq!(
            class(
                403,
                "Quota exceeded for quota metric 'Queries'",
                &["someNewReason"]
            ),
            THROTTLE
        );

        for status in [500, 502, 503, 504] {
            assert_eq!(
                classify(status, None, b"<html>oops</html>"),
                HttpClass::Transient
            );
        }

        assert_eq!(
            class(
                403,
                "The limit for this folder's number of children has been exceeded.",
                &["numChildrenInNonRootLimitExceeded"]
            ),
            HttpClass::Fatal {
                status: 403,
                reason: "numChildrenInNonRootLimitExceeded".into(),
                message: "The limit for this folder's number of children has been exceeded.".into(),
            }
        );
        assert_eq!(
            class(400, "Invalid field selection", &["invalidParameter"]),
            HttpClass::Fatal {
                status: 400,
                reason: "invalidParameter".into(),
                message: "Invalid field selection".into(),
            }
        );
    }

    #[test]
    fn a_body_that_is_not_json_falls_back_to_the_status() {
        let html = b"<!DOCTYPE html><title>Error 403 (Forbidden)!!1</title> rate limit quota";
        let fatal = |status| HttpClass::Fatal {
            status,
            reason: String::new(),
            message: String::new(),
        };
        assert_eq!(classify(403, None, html), fatal(403));
        assert_eq!(classify(400, None, b""), fatal(400));
        assert_eq!(classify(410, None, b"Gone"), fatal(410));
        assert_eq!(classify(308, None, b""), fatal(308));
        assert_eq!(classify(401, None, html), HttpClass::Unauthorized);
        assert_eq!(classify(404, None, b"Not Found"), HttpClass::NotFound);
        assert_eq!(classify(409, None, html), HttpClass::Conflict);
        assert_eq!(classify(503, None, html), HttpClass::Transient);
        // JSON of another shape is no envelope either
        assert_eq!(classify(403, None, b"[1, 2]"), fatal(403));
        assert_eq!(classify(403, None, br#"{"error":"forbidden"}"#), fatal(403));
        assert_eq!(
            classify(403, None, br#"{"error":{"errors":[{}]}}"#),
            fatal(403)
        );
    }

    #[test]
    fn retry_after_forms() {
        let ra = |v| match classify(429, Some(v), b"") {
            HttpClass::Throttle { retry_after } => retry_after,
            other => panic!("{other:?}"),
        };
        assert_eq!(ra("7"), Some(Duration::from_secs(7)));
        assert_eq!(ra(" 120 "), Some(Duration::from_secs(120)));
        assert_eq!(ra("soon"), None);
        assert_eq!(
            ra("Wed, 11 Nov 1998 09:14:03 GMT"),
            Some(Duration::ZERO),
            "a date in the past"
        );
        let future = ra("Fri, 01 Jan 2100 00:00:00 GMT").unwrap();
        assert!(future > Duration::from_secs(3600));
        // only throttles carry it
        assert_eq!(classify(503, Some("7"), b""), HttpClass::Transient);
    }

    #[test]
    fn range_header() {
        assert_eq!(parse_range_header(None), 0);
        assert_eq!(parse_range_header(Some("bytes=0-0")), 1);
        assert_eq!(parse_range_header(Some("bytes=0-262143")), 262_144);
        assert_eq!(parse_range_header(Some(" bytes=0-16777215 ")), 16_777_216);
        assert_eq!(parse_range_header(Some("0-5")), 0);
        assert_eq!(parse_range_header(Some("bytes=")), 0);
        assert_eq!(parse_range_header(Some("bytes=0-x")), 0);
    }
}
