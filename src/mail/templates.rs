//! Mail templates in Hangar style: table layout with inline CSS (Outlook, Gmail, Apple Mail),
//! light as the base, dark via `prefers-color-scheme`, no images from the network, no
//! tracking. Every mail has an equivalent text part; the button link is also given as text.
//! Colors from the app's design tokens (`resources/css/theme.css` of the website).

use super::i18n::{fill, strings, Strings};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailKind {
    Invitation {
        inviter: String,
        team: String,
        link: String,
        days: u32,
    },
    LoginLink {
        link: String,
        minutes: u32,
    },
    InvitationAccepted {
        who: String,
        team: String,
    },
    Attention {
        team: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Values from input (team name, addresses) must not contain line breaks or control
/// characters; in the subject they could otherwise forge header lines. Invisible formatting
/// characters (bidi overrides) are dropped as well, so that a name cannot be shown reversed.
fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| crate::util::visible(*c))
        .take(120)
        .collect()
}

struct Parts {
    subject: String,
    intro: String,
    action: Option<(String, String)>,
    note: Option<String>,
}

fn parts(kind: &MailKind, s: &Strings) -> Parts {
    match kind {
        MailKind::Invitation {
            inviter,
            team,
            link,
            days,
        } => {
            let values = [("inviter", inviter.as_str()), ("team", team.as_str())];
            Parts {
                subject: fill(s.invite_subject, &values),
                intro: fill(s.invite_intro, &values),
                action: Some((s.invite_action.to_owned(), link.clone())),
                note: Some(fill(s.invite_note, &[("days", &days.to_string())])),
            }
        }
        MailKind::LoginLink { link, minutes } => Parts {
            subject: s.login_subject.to_owned(),
            intro: s.login_intro.to_owned(),
            action: Some((s.login_action.to_owned(), link.clone())),
            note: Some(fill(s.login_note, &[("minutes", &minutes.to_string())])),
        },
        MailKind::InvitationAccepted { who, team } => {
            let values = [("who", who.as_str()), ("team", team.as_str())];
            Parts {
                subject: fill(s.accepted_subject, &values),
                intro: fill(s.accepted_intro, &values),
                action: None,
                note: None,
            }
        }
        MailKind::Attention { team } => {
            let values = [("team", team.as_str())];
            Parts {
                subject: fill(s.attention_subject, &values),
                intro: fill(s.attention_intro, &values),
                action: None,
                note: Some(s.attention_note.to_owned()),
            }
        }
    }
}

fn cleaned(kind: &MailKind) -> MailKind {
    match kind {
        MailKind::Invitation {
            inviter,
            team,
            link,
            days,
        } => MailKind::Invitation {
            inviter: clean(inviter),
            team: clean(team),
            link: link.clone(),
            days: *days,
        },
        MailKind::InvitationAccepted { who, team } => MailKind::InvitationAccepted {
            who: clean(who),
            team: clean(team),
        },
        MailKind::Attention { team } => MailKind::Attention { team: clean(team) },
        other => other.clone(),
    }
}

/// Builds subject, text and HTML part. `server` is the server's host (for the footer).
pub fn render(kind: &MailKind, lang: &str, server: &str) -> Rendered {
    let s = strings(lang);
    let kind = cleaned(kind);
    let footer = fill(s.footer, &[("server", server)]);
    let plain = parts(&kind, s);

    let mut text = format!("{}\n\n{}\n", s.greeting, plain.intro);
    if let Some((label, link)) = &plain.action {
        text.push_str(&format!("\n{label}:\n{link}\n"));
    }
    if let Some(note) = &plain.note {
        text.push_str(&format!("\n{note}\n"));
    }
    text.push_str(&format!("\nHangar\n\n--\n{footer}\n"));

    // Same parts for HTML, but with escaped values.
    let html_kind = match &kind {
        MailKind::Invitation {
            inviter,
            team,
            link,
            days,
        } => MailKind::Invitation {
            inviter: escape(inviter),
            team: escape(team),
            link: link.clone(),
            days: *days,
        },
        MailKind::InvitationAccepted { who, team } => MailKind::InvitationAccepted {
            who: escape(who),
            team: escape(team),
        },
        MailKind::Attention { team } => MailKind::Attention { team: escape(team) },
        other => other.clone(),
    };
    let rich = parts(&html_kind, s);
    let dir = if s.rtl { "rtl" } else { "ltr" };
    let align = if s.rtl { "right" } else { "left" };
    let lang_attr = escape(lang);
    let mut body = format!(
        r##"<p class="t" style="margin:0 0 16px;font-size:16px;line-height:24px;color:#0e1116">{greeting}</p>
<p class="t" style="margin:0 0 24px;font-size:16px;line-height:24px;color:#0e1116">{intro}</p>"##,
        greeting = escape(s.greeting),
        intro = rich.intro,
    );
    if let Some((label, link)) = &rich.action {
        let href = escape(link);
        body.push_str(&format!(
            r##"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px"><tr><td class="btn" bgcolor="#0969da" style="border-radius:10px;background:#0969da">
<a class="btnl" href="{href}" style="display:inline-block;padding:12px 22px;font-size:16px;font-weight:600;line-height:20px;color:#ffffff;text-decoration:none;border-radius:10px">{label}</a>
</td></tr></table>
<p class="m" style="margin:0 0 6px;font-size:13px;line-height:20px;color:#59636e">{fallback}</p>
<p style="margin:0 0 24px;font-size:13px;line-height:20px;word-break:break-all"><a class="lnk" href="{href}" style="color:#0969da">{href}</a></p>"##,
            label = escape(label),
            fallback = escape(s.fallback),
        ));
    }
    if let Some(note) = &rich.note {
        body.push_str(&format!(
            r##"<p class="m" style="margin:0 0 8px;font-size:14px;line-height:22px;color:#59636e">{}</p>"##,
            escape(note)
        ));
    }
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="{lang_attr}" dir="{dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{title}</title>
<style>
@media (prefers-color-scheme: dark) {{
  .bg {{ background:#0a0d11 !important; }}
  .card {{ background:#0e1116 !important; border-color:#262e39 !important; }}
  .t {{ color:#e6edf3 !important; }}
  .m {{ color:#8592a3 !important; }}
  .btn {{ background:#5aa9ff !important; }}
  .btnl {{ color:#06121f !important; }}
  .lnk {{ color:#5aa9ff !important; }}
  .mark {{ background:#5aa9ff !important; color:#06121f !important; }}
}}
</style>
</head>
<body class="bg" style="margin:0;padding:0;background:#eef1f5">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="bg" bgcolor="#eef1f5" style="background:#eef1f5">
<tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px">
<tr><td style="padding:0 4px 16px;text-align:{align}">
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td class="mark" width="28" height="28" align="center" bgcolor="#0969da" style="width:28px;height:28px;border-radius:8px;background:#0969da;color:#ffffff;font-family:'Inter Variable','Segoe UI',system-ui,-apple-system,sans-serif;font-size:16px;font-weight:700;line-height:28px">H</td>
<td class="t" style="padding:0 10px;font-family:'Inter Variable','Segoe UI',system-ui,-apple-system,sans-serif;font-size:18px;font-weight:700;color:#0e1116">Hangar</td>
</tr></table>
</td></tr>
<tr><td class="card" bgcolor="#ffffff" style="background:#ffffff;border:1px solid #dde3ea;border-radius:16px;padding:32px;text-align:{align};font-family:'Inter Variable','Segoe UI',system-ui,-apple-system,sans-serif">
{body}
</td></tr>
<tr><td class="m" style="padding:16px 4px 0;font-family:'Inter Variable','Segoe UI',system-ui,-apple-system,sans-serif;font-size:12px;line-height:18px;color:#59636e;text-align:{align}">{footer_html}</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"##,
        title = rich.subject,
        footer_html = escape(&footer),
    );
    Rendered {
        subject: plain.subject,
        text,
        html,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::i18n::LANGS;

    fn invitation() -> MailKind {
        MailKind::Invitation {
            inviter: "ana@example.org".into(),
            team: "<script>Team\r\nBcc: x@y</script>".into(),
            link: "https://team.example.org/invite/abc?x=1&y=2".into(),
            days: 7,
        }
    }

    #[test]
    fn escaped_and_without_remote_images() {
        let r = render(&invitation(), "de", "team.example.org");
        assert!(!r.html.contains("<script>"));
        assert!(r.html.contains("&lt;script&gt;"));
        assert!(!r.subject.contains('\n') && !r.subject.contains('\r'));
        assert!(!r.html.contains("<img"));
        assert!(!r.html.contains("http://") && !r.html.contains("src="));
        assert!(r
            .html
            .contains("href=\"https://team.example.org/invite/abc?x=1&amp;y=2\""));
        assert!(r
            .text
            .contains("https://team.example.org/invite/abc?x=1&y=2"));
        assert!(r.html.contains("prefers-color-scheme: dark"));
    }

    #[test]
    fn all_kinds_in_all_languages() {
        let kinds = [
            invitation(),
            MailKind::LoginLink {
                link: "https://t.example/auth/magic/x".into(),
                minutes: 15,
            },
            MailKind::InvitationAccepted {
                who: "bo@example.org".into(),
                team: "Core".into(),
            },
            MailKind::Attention {
                team: "Core".into(),
            },
        ];
        for lang in LANGS {
            for kind in &kinds {
                let r = render(kind, lang, "t.example");
                assert!(!r.subject.is_empty() && !r.text.is_empty());
                assert!(
                    !r.subject.contains('{') && !r.text.contains("{team}"),
                    "{lang}: {}",
                    r.subject
                );
                assert!(!r.html.contains('\u{2014}') && !r.text.contains('\u{2013}'));
            }
        }
        assert!(render(&kinds[3], "ar", "t").html.contains("dir=\"rtl\""));
    }

    #[test]
    fn attention_without_content() {
        let r = render(
            &MailKind::Attention {
                team: "Core".into(),
            },
            "en",
            "t.example",
        );
        assert!(!r.html.contains("href"));
        assert!(r.text.contains("end-to-end"));
    }
}
