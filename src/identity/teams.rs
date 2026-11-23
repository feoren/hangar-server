//! Teams, roles, invitations, seats and tickets for self-hosting.
//!
//! Rules:
//! - Rank owner > admin > member. Only someone ranked higher decides about a person; only a
//!   role below one's own can be granted; owner can never be granted. Anyone except the owner
//!   may leave.
//! - Invitations only to an email address: single use, valid for 7 days, one open invitation
//!   per team and address; inviting again renews token and deadline. The seat check happens on
//!   acceptance in the same write transaction as the join (BEGIN IMMEDIATE: acceptances
//!   run one after another, the last seat is taken exactly once).
//! - Seats per account: distinct people across all of the owner's teams, the owner
//!   included; limit from the owner's license document, otherwise Free (3).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::SqliteConnection;
use tokio::sync::{mpsc, watch};

use super::auth::{
    authenticate, browser_user, find_or_create_user, identity, mail_lang, start_browser_session,
    User, BROWSER_TTL_S,
};
use super::pages::{self, csrf_ok, csrf_token, hidden, message, page, same_origin, t};
use super::{ApiError, ApiResult, Identity};
use crate::db::{begin_write, Db};
use crate::http::ratelimit::Rule;
use crate::http::AppState;
use crate::license::{self, LicenseClaims, FREE_SEATS};
use crate::mail::i18n::{fill, pick};
use crate::mail::templates::{escape, MailKind};
use crate::relay::team::Attention;
use crate::signed::{self, TICKET_CONTEXT};
use crate::ticket::{Role, TicketClaims};
use crate::util::{normalize_email, now_s, random_id, random_token, token_hash};

pub const INVITATION_TTL_S: i64 = 7 * 86_400;
pub const MAX_INVITES_PER_REQUEST: usize = 20;
pub const TICKET_TTL_S: i64 = 60;
const ATTENTION_INTERVAL_S: i64 = 3600;
/// Invitation mails per account and hour, counting each address and each resend separately.
const INVITE_RULE: Rule = Rule {
    limit: 50,
    window_s: 3600,
};

fn conflict(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code)
}

fn clean_name(raw: &str) -> Option<String> {
    let name: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    (!name.is_empty() && name.chars().count() <= 80).then_some(name)
}

async fn role_of(
    conn: &mut SqliteConnection,
    team: &str,
    user: &str,
) -> Result<Option<Role>, sqlx::Error> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM team_members WHERE team_id = ? AND user_id = ?")
            .bind(team)
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(role.and_then(|r| Role::parse(&r)))
}

/// The person's role in the team; foreign teams are "not found" (IDs cannot be probed).
pub(crate) async fn require_member(
    identity: &Identity,
    team: &str,
    user: &User,
) -> ApiResult<Role> {
    let mut conn = identity.db.acquire().await?;
    role_of(&mut conn, team, &user.id)
        .await?
        .ok_or(ApiError::NOT_FOUND)
}

/// The account's license, if stored and still valid with the configured keys.
async fn license_of(
    conn: &mut SqliteConnection,
    identity: &Identity,
    user: &str,
) -> Result<Option<LicenseClaims>, sqlx::Error> {
    let document: Option<String> =
        sqlx::query_scalar("SELECT document FROM licenses WHERE user_id = ?")
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(document.and_then(|d| {
        license::verify(
            &d,
            &identity.config.license_keys,
            &identity.config.license_revoked,
        )
        .ok()
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seats {
    pub limit: u32,
    pub used: u32,
}

async fn seats(
    conn: &mut SqliteConnection,
    identity: &Identity,
    owner: &str,
) -> Result<(Seats, Option<LicenseClaims>), sqlx::Error> {
    let lic = license_of(conn, identity, owner).await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT m.user_id) FROM team_members m JOIN teams t ON t.id = m.team_id WHERE t.owner_id = ?",
    )
    .bind(owner)
    .fetch_one(&mut *conn)
    .await?;
    let limit = license::seats_for(lic.as_ref(), now_s());
    Ok((
        Seats {
            limit,
            used: u32::try_from(used).unwrap_or(u32::MAX),
        },
        lic,
    ))
}

// ---------------------------------------------------------------------------------------------
// Services

pub async fn create(identity: &Identity, user: &User, name: &str) -> ApiResult<String> {
    let name = clean_name(name).ok_or(ApiError::INVALID)?;
    if !identity.limiter.hit(
        "team-create",
        &user.id,
        Rule {
            limit: 10,
            window_s: 3600,
        },
        now_s(),
    ) {
        return Err(ApiError::RATE_LIMITED);
    }
    let id = insert_team(&identity.db, &user.id, &name).await?;
    tracing::info!("team created");
    Ok(id)
}

/// Creates a team with owner (API and command `create-team`); `name` is already validated.
async fn insert_team(db: &Db, owner_id: &str, name: &str) -> Result<String, sqlx::Error> {
    let id = format!("t_{}", random_id());
    let now = now_s();
    let mut tx = begin_write(db).await?;
    sqlx::query("INSERT INTO teams (id, name, owner_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(owner_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, 'owner', ?)",
    )
    .bind(&id)
    .bind(owner_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accept {
    Joined { team: String, name: String },
    SeatsFull,
    WrongAccount,
    Invalid,
}

/// id, team_id, email, role, invited_by, expires_at, team name, owner_id
type InvitationRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
);

/// Accepts an invitation: the address must match, seat check and join in one transaction.
pub async fn accept(
    identity: &Identity,
    token: &str,
    user_id: &str,
    user_email: &str,
) -> ApiResult<Accept> {
    let now = now_s();
    let mut tx = begin_write(&identity.db).await?;
    let row: Option<InvitationRow> = sqlx::query_as(
        "SELECT i.id, i.team_id, i.email, i.role, i.invited_by, i.expires_at, t.name, t.owner_id FROM invitations i \
         JOIN teams t ON t.id = i.team_id WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.revoked_at IS NULL",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((invitation, team, email, role, invited_by, expires_at, name, owner)) = row else {
        return Ok(Accept::Invalid);
    };
    if expires_at <= now {
        return Ok(Accept::Invalid);
    }
    if email != user_email {
        return Ok(Accept::WrongAccount);
    }
    if role_of(&mut tx, &team, user_id).await?.is_none() {
        let counted: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM team_members m JOIN teams t ON t.id = m.team_id WHERE t.owner_id = ? AND m.user_id = ? LIMIT 1",
        )
        .bind(&owner)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if counted.is_none() {
            let (seats, _) = seats(&mut tx, identity, &owner).await?;
            if seats.used >= seats.limit {
                tracing::info!(limit = seats.limit, "join refused: no seat available");
                return Ok(Accept::SeatsFull);
            }
        }
        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&team)
        .bind(user_id)
        .bind(&role)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE invitations SET accepted_at = ?, accepted_by = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .bind(&invitation)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some(relay) = identity.relay() {
        crate::relay::store::set_member_removed(&relay.db, &team, user_id, None).await?;
    }
    if let Some(inviter) = invited_by {
        let who: Option<(String, String)> =
            sqlx::query_as("SELECT email, lang FROM users WHERE id = ?")
                .bind(&inviter)
                .fetch_optional(&identity.db)
                .await?;
        if let Some((to, lang)) = who {
            identity.mailer.send(
                &to,
                mail_lang(Some(&lang), &identity.config),
                MailKind::InvitationAccepted {
                    who: user_email.to_owned(),
                    team: name.clone(),
                },
            );
        }
    }
    tracing::info!("invitation accepted");
    Ok(Accept::Joined { team, name })
}

/// Renews token and deadline of an open invitation or creates it; sends the mail or
/// returns the link (without mail delivery).
async fn send_invitation(
    identity: &Identity,
    inviter: &User,
    team: &str,
    team_name: &str,
    email: &str,
    role: Role,
    lang: &str,
) -> ApiResult<Value> {
    let (id, status, token, expires_at) =
        upsert_invitation(&identity.db, &inviter.id, team, email, role, lang).await?;
    let link = identity.url(&format!("/invite/{token}"));
    let mut out = json!({ "id": id, "email": email, "status": status, "expiresAt": expires_at });
    if identity.links_to_admin() {
        out["link"] = Value::String(link);
    } else {
        identity.mailer.send(
            email,
            lang,
            MailKind::Invitation {
                inviter: inviter.email.clone(),
                team: team_name.to_owned(),
                link,
                days: 7,
            },
        );
    }
    Ok(out)
}

/// Renews or creates an open invitation: (id, status, token, expiry). The token appears only in
/// the link; its hash is what gets stored.
async fn upsert_invitation(
    db: &Db,
    inviter_id: &str,
    team: &str,
    email: &str,
    role: Role,
    lang: &str,
) -> Result<(String, &'static str, String, i64), sqlx::Error> {
    let token = random_token();
    let now = now_s();
    let mut tx = begin_write(db).await?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM invitations WHERE team_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL")
            .bind(team)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
    let (id, status) = match existing {
        Some(id) => {
            sqlx::query("UPDATE invitations SET token_hash = ?, role = ?, expires_at = ?, sent_count = sent_count + 1, last_sent_at = ?, invited_by = ?, lang = ? WHERE id = ?")
                .bind(token_hash(&token))
                .bind(role.as_str())
                .bind(now + INVITATION_TTL_S)
                .bind(now)
                .bind(inviter_id)
                .bind(lang)
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            (id, "renewed")
        }
        None => {
            let id = format!("i_{}", random_id());
            sqlx::query("INSERT INTO invitations (id, team_id, email, role, token_hash, invited_by, lang, created_at, expires_at, last_sent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&id)
                .bind(team)
                .bind(email)
                .bind(role.as_str())
                .bind(token_hash(&token))
                .bind(inviter_id)
                .bind(lang)
                .bind(now)
                .bind(now + INVITATION_TTL_S)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            (id, "invited")
        }
    };
    tx.commit().await?;
    Ok((id, status, token, now + INVITATION_TTL_S))
}

// ---------------------------------------------------------------------------------------------
// Administration on the host (commands create-team, invite, teams; IDENTITY=local only)
//
// Whoever runs the commands has access to the server and its database; hence no
// authentication and no rate limiting. The rules stay the same as in the API: name at most
// 80 characters, invitation only as admin or member, seat check only on acceptance.

/// A team as the `teams` command shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamLine {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: i64,
    pub open_invitations: i64,
}

/// `create-team <owner-email> <name>`: creates the owner's account if needed and returns
/// the team ID.
pub async fn cli_create_team(
    db: &Db,
    default_lang: &str,
    owner_email: &str,
    name: &str,
) -> Result<String, String> {
    let email = normalize_email(owner_email).ok_or("invalid email address")?;
    let name = clean_name(name).ok_or("team name missing or longer than 80 characters")?;
    let owner = async {
        let mut tx = begin_write(db).await?;
        let id = find_or_create_user(&mut tx, &email, default_lang, now_s()).await?;
        tx.commit().await?;
        Ok::<_, sqlx::Error>(id)
    }
    .await
    .map_err(|e| e.to_string())?;
    let id = insert_team(db, &owner, &name)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("team created (command)");
    Ok(id)
}

/// Finds a team by its ID or its exact name: (id, name, owner_id).
async fn cli_find_team(db: &Db, team: &str) -> Result<(String, String, String), String> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, name, owner_id FROM teams WHERE id = ? OR name = ? ORDER BY created_at",
    )
    .bind(team)
    .bind(team)
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;
    if let Some(row) = rows.iter().find(|r| r.0 == team) {
        return Ok(row.clone());
    }
    let mut rows = rows.into_iter();
    match (rows.next(), rows.next()) {
        (None, _) => Err(format!("no team {team:?} (list: teams)")),
        (Some(row), None) => Ok(row),
        (Some(first), Some(second)) => {
            let ids: Vec<String> = [first, second]
                .into_iter()
                .chain(rows)
                .map(|r| r.0)
                .collect();
            Err(format!(
                "several teams are named {team:?}, please use the ID: {}",
                ids.join(", ")
            ))
        }
    }
}

/// `invite <team> <email> [member|admin]`: invitation on behalf of the owner, returns the link
/// (single use, 7 days, only for this address). The invitation page signs the person in with the
/// link itself; no mail is sent.
pub async fn cli_invite(
    db: &Db,
    public_url: &str,
    default_lang: &str,
    team: &str,
    email: &str,
    role: &str,
) -> Result<String, String> {
    let role = Role::parse(role)
        .filter(|r| *r != Role::Owner)
        .ok_or("role must be member or admin")?;
    let email = normalize_email(email).ok_or("invalid email address")?;
    let (team, _, owner) = cli_find_team(db, team).await?;
    let member: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? AND u.email = ?",
    )
    .bind(&team)
    .bind(&email)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
    if member.is_some() {
        return Err(format!("{email} is already a member"));
    }
    let (_, _, token, _) = upsert_invitation(db, &owner, &team, &email, role, default_lang)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("invitation created (command)");
    Ok(format!("{public_url}/invite/{token}"))
}

/// `teams`: all teams with owner, members and open invitations.
pub async fn cli_teams(db: &Db) -> Result<Vec<TeamLine>, String> {
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT t.id, t.name, u.email, \
         (SELECT COUNT(*) FROM team_members m WHERE m.team_id = t.id), \
         (SELECT COUNT(*) FROM invitations i WHERE i.team_id = t.id AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?) \
         FROM teams t JOIN users u ON u.id = t.owner_id ORDER BY t.created_at",
    )
    .bind(now_s())
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|(id, name, owner, members, open_invitations)| TeamLine {
            id,
            name,
            owner,
            members,
            open_invitations,
        })
        .collect())
}

fn can_manage(actor: Role, target: Role) -> bool {
    actor.rank() > target.rank()
}

// ---------------------------------------------------------------------------------------------
// Handlers (app, bearer)

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let teams: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT t.id, t.name, m.role FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ? ORDER BY t.name",
    )
    .bind(&user.id)
    .fetch_all(&identity.db)
    .await?;
    let teams: Vec<Value> = teams
        .into_iter()
        .map(|(id, name, role)| json!({ "id": id, "name": name, "role": role }))
        .collect();
    Ok(Json(
        json!({ "id": user.id, "email": user.email, "teams": teams }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateTeam {
    name: String,
}

pub async fn create_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateTeam>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let id = create(identity, &user, &body.name).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

pub async fn team_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team): Path<String>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let role = require_member(identity, &team, &user).await?;
    let mut conn = identity.db.acquire().await?;
    let (name, owner): (String, String) =
        sqlx::query_as("SELECT name, owner_id FROM teams WHERE id = ?")
            .bind(&team)
            .fetch_one(&mut *conn)
            .await?;
    let members: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT u.id, u.email, m.role, m.joined_at FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? ORDER BY m.joined_at",
    )
    .bind(&team)
    .fetch_all(&mut *conn)
    .await?;
    let invitations: Vec<Value> = if role.rank() >= Role::Admin.rank() {
        let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
            "SELECT id, email, role, expires_at, sent_count FROM invitations WHERE team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL ORDER BY created_at",
        )
        .bind(&team)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter()
            .map(|(id, email, role, exp, sent)| json!({ "id": id, "email": email, "role": role, "expiresAt": exp, "expired": exp <= now_s(), "sentCount": sent }))
            .collect()
    } else {
        Vec::new()
    };
    let (seats, lic) = seats(&mut conn, identity, &owner).await?;
    Ok(Json(json!({
        "id": team,
        "name": name,
        "role": role.as_str(),
        "members": members.into_iter().map(|(id, email, role, joined)| json!({ "id": id, "email": email, "role": role, "joinedAt": joined })).collect::<Vec<_>>(),
        "invitations": invitations,
        "seats": { "limit": seats.limit, "used": seats.used, "plan": lic.as_ref().filter(|l| l.active(now_s())).map_or("free", |l| l.plan.as_str()) },
    })))
}

pub async fn delete_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team): Path<String>,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    if require_member(identity, &team, &user).await? != Role::Owner {
        return Err(ApiError::FORBIDDEN);
    }
    sqlx::query("DELETE FROM teams WHERE id = ? AND owner_id = ?")
        .bind(&team)
        .bind(&user.id)
        .execute(&identity.db)
        .await?;
    if let Some(relay) = identity.relay() {
        relay.close_team(&team).await?;
    }
    tracing::info!("team deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct SetRole {
    role: String,
}

pub async fn set_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team, target)): Path<(String, String)>,
    Json(body): Json<SetRole>,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let new = Role::parse(&body.role)
        .filter(|r| *r != Role::Owner)
        .ok_or(ApiError::INVALID)?;
    let mut tx = begin_write(&identity.db).await?;
    let actor = role_of(&mut tx, &team, &user.id)
        .await?
        .ok_or(ApiError::NOT_FOUND)?;
    let current = role_of(&mut tx, &team, &target)
        .await?
        .ok_or(ApiError::NOT_FOUND)?;
    if !can_manage(actor, current) || new.rank() >= actor.rank() {
        return Err(ApiError::FORBIDDEN);
    }
    sqlx::query("UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?")
        .bind(new.as_str())
        .bind(&team)
        .bind(&target)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some(relay) = identity.relay() {
        relay
            .apply_role(&team, &target, new, crate::util::now_ms())
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team, target)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let mut tx = begin_write(&identity.db).await?;
    let actor = role_of(&mut tx, &team, &user.id)
        .await?
        .ok_or(ApiError::NOT_FOUND)?;
    let current = role_of(&mut tx, &team, &target)
        .await?
        .ok_or(ApiError::NOT_FOUND)?;
    let leaving = target == user.id;
    if (leaving && actor == Role::Owner) || (!leaving && !can_manage(actor, current)) {
        return Err(ApiError::FORBIDDEN);
    }
    sqlx::query("DELETE FROM team_members WHERE team_id = ? AND user_id = ?")
        .bind(&team)
        .bind(&target)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some(relay) = identity.relay() {
        relay.remove_member(&team, &target).await?;
    }
    tracing::info!(leaving, "member removed");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct Invite {
    emails: Vec<String>,
    role: String,
    lang: Option<String>,
}

pub async fn invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team): Path<String>,
    Json(body): Json<Invite>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let actor = require_member(identity, &team, &user).await?;
    let role = Role::parse(&body.role)
        .filter(|r| *r != Role::Owner)
        .ok_or(ApiError::INVALID)?;
    if actor.rank() < Role::Admin.rank() || role.rank() >= actor.rank() {
        return Err(ApiError::FORBIDDEN);
    }
    if body.emails.is_empty() || body.emails.len() > MAX_INVITES_PER_REQUEST {
        return Err(ApiError::INVALID);
    }
    let mut emails: Vec<String> = Vec::new();
    for raw in &body.emails {
        let email = normalize_email(raw).ok_or(ApiError::INVALID)?;
        if !emails.contains(&email) {
            emails.push(email);
        }
    }
    // Each address counts separately (otherwise 20 mails per request for a single hit).
    let now = now_s();
    for _ in &emails {
        if !identity.limiter.hit("invite", &user.id, INVITE_RULE, now) {
            return Err(ApiError::RATE_LIMITED);
        }
    }
    let lang = pick(
        body.lang.as_deref(),
        headers.get("accept-language").and_then(|v| v.to_str().ok()),
        &identity.config.default_lang,
    );
    let name: String = sqlx::query_scalar("SELECT name FROM teams WHERE id = ?")
        .bind(&team)
        .fetch_one(&identity.db)
        .await?;
    let mut results = Vec::new();
    for email in emails {
        let member: Option<i64> = sqlx::query_scalar("SELECT 1 FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? AND u.email = ?")
            .bind(&team)
            .bind(&email)
            .fetch_optional(&identity.db)
            .await?;
        if member.is_some() {
            results.push(json!({ "email": email, "status": "member" }));
            continue;
        }
        results.push(send_invitation(identity, &user, &team, &name, &email, role, lang).await?);
    }
    Ok(Json(json!({ "invitations": results })))
}

pub async fn resend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team, invitation)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let actor = require_member(identity, &team, &user).await?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT email, role, lang FROM invitations WHERE id = ? AND team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(&invitation)
    .bind(&team)
    .fetch_optional(&identity.db)
    .await?;
    let (email, role, lang) = row.ok_or(ApiError::NOT_FOUND)?;
    let role = Role::parse(&role).ok_or(ApiError::INTERNAL)?;
    if actor.rank() < Role::Admin.rank() || role.rank() >= actor.rank() {
        return Err(ApiError::FORBIDDEN);
    }
    if !identity
        .limiter
        .hit("invite", &user.id, INVITE_RULE, now_s())
    {
        return Err(ApiError::RATE_LIMITED);
    }
    let name: String = sqlx::query_scalar("SELECT name FROM teams WHERE id = ?")
        .bind(&team)
        .fetch_one(&identity.db)
        .await?;
    Ok(Json(
        send_invitation(
            identity,
            &user,
            &team,
            &name,
            &email,
            role,
            mail_lang(Some(&lang), &identity.config),
        )
        .await?,
    ))
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team, invitation)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    if require_member(identity, &team, &user).await?.rank() < Role::Admin.rank() {
        return Err(ApiError::FORBIDDEN);
    }
    let done = sqlx::query("UPDATE invitations SET revoked_at = ? WHERE id = ? AND team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL")
        .bind(now_s())
        .bind(&invitation)
        .bind(&team)
        .execute(&identity.db)
        .await?;
    if done.rows_affected() == 1 {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NOT_FOUND)
    }
}

#[derive(Debug, Deserialize)]
pub struct AcceptBody {
    token: String,
}

pub async fn accept_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AcceptBody>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    match accept(identity, &body.token, &user.id, &user.email).await? {
        Accept::Joined { team, name } => Ok(Json(json!({ "team": team, "name": name }))),
        Accept::SeatsFull => Err(conflict("seats_full")),
        Accept::WrongAccount => Err(ApiError::new(StatusCode::FORBIDDEN, "wrong_account")),
        Accept::Invalid => Err(ApiError::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------------------------
// Invitation page (browser)

async fn invitation_preview(
    identity: &Identity,
    token: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT i.email, t.name FROM invitations i JOIN teams t ON t.id = i.team_id \
         WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?",
    )
    .bind(token_hash(token))
    .bind(now_s())
    .fetch_optional(&identity.db)
    .await
}

pub async fn invite_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let Ok(Some((email, team))) = invitation_preview(identity, &token).await else {
        return message(
            lang,
            s.page_invite_button,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        );
    };
    let csrf = match browser_user(identity, &headers).await {
        Ok(Some(user)) => hidden("csrf", &csrf_token(&identity.config, &user.session_id)),
        _ => String::new(),
    };
    let body = format!(
        r#"<h1>{title}</h1><p>{prompt}</p><form method="post" action="/invite/{token}">{csrf}<button type="submit">{button}</button></form>"#,
        title = escape(s.page_invite_button),
        prompt = escape(&fill(
            s.page_invite_prompt,
            &[("team", &team), ("email", &email)]
        )),
        token = escape(&token),
        button = escape(s.page_invite_button),
    );
    page(lang, s.page_invite_button, &body, StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct InviteForm {
    csrf: Option<String>,
}

/// POST: accept. Without a browser session, the link may sign in only an address that has no
/// account yet, and only once it has joined: without mail the inviter receives the link, so it
/// proves nothing about the mailbox of an existing account (that would let any account take
/// over any other). An existing account signs in first and then opens the link again.
pub async fn invite_accept_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    axum::Form(form): axum::Form<InviteForm>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let title = s.page_invite_button;
    if !same_origin(&headers, &identity.config) {
        return message(
            lang,
            title,
            s.page_link_invalid,
            "error",
            StatusCode::FORBIDDEN,
        );
    }
    let Ok(Some((email, _))) = invitation_preview(identity, &token).await else {
        return message(
            lang,
            title,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        );
    };
    let mut new_account = false;
    let user = match browser_user(identity, &headers).await {
        Ok(Some(user)) => {
            if !csrf_ok(&identity.config, &user.session_id, form.csrf.as_deref()) {
                return message(
                    lang,
                    title,
                    s.page_link_invalid,
                    "error",
                    StatusCode::FORBIDDEN,
                );
            }
            (user.id, user.email)
        }
        Ok(None) => {
            let existing: Result<Option<i64>, sqlx::Error> =
                sqlx::query_scalar("SELECT 1 FROM users WHERE email = ?")
                    .bind(&email)
                    .fetch_optional(&identity.db)
                    .await;
            match existing {
                Ok(Some(_)) => {
                    let mut response = super::auth::sign_in_page(identity, lang, title, "/device");
                    *response.status_mut() = StatusCode::FORBIDDEN;
                    return response;
                }
                Ok(None) => {}
                Err(error) => return ApiError::from(error).into_response(),
            }
            let created = async {
                let mut tx = begin_write(&identity.db).await?;
                let id = find_or_create_user(&mut tx, &email, lang, now_s()).await?;
                tx.commit().await?;
                Ok::<_, sqlx::Error>(id)
            }
            .await;
            match created {
                Ok(id) => {
                    new_account = true;
                    (id, email.clone())
                }
                Err(error) => return ApiError::from(error).into_response(),
            }
        }
        Err(error) => return error.into_response(),
    };
    let outcome = accept(identity, &token, &user.0, &user.1).await;
    // The session of a new account starts only once it has joined.
    let mut cookie = None;
    if new_account && matches!(outcome, Ok(Accept::Joined { .. })) {
        let started = async {
            let mut tx = begin_write(&identity.db).await?;
            let token = start_browser_session(&mut tx, &user.0, now_s()).await?;
            tx.commit().await?;
            Ok::<_, sqlx::Error>(token)
        }
        .await;
        match started {
            Ok(token) => cookie = Some(token),
            Err(error) => return ApiError::from(error).into_response(),
        }
    }
    let mut response = match outcome {
        Ok(Accept::Joined { name, .. }) => message(
            lang,
            title,
            &fill(s.page_invite_done, &[("team", &name), ("email", &user.1)]),
            "ok",
            StatusCode::OK,
        ),
        Ok(Accept::SeatsFull) => message(
            lang,
            title,
            s.page_seats_full,
            "error",
            StatusCode::CONFLICT,
        ),
        Ok(Accept::WrongAccount) => message(
            lang,
            title,
            s.page_wrong_account,
            "error",
            StatusCode::FORBIDDEN,
        ),
        Ok(Accept::Invalid) => message(
            lang,
            title,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        ),
        Err(error) => error.into_response(),
    };
    if let Some(token) = cookie {
        response.headers_mut().insert(
            header::SET_COOKIE,
            pages::session_cookie(&identity.config, &token, BROWSER_TTL_S),
        );
    }
    response
}

// ---------------------------------------------------------------------------------------------
// License

fn license_json(lic: Option<&LicenseClaims>) -> Value {
    let now = now_s();
    match lic {
        Some(l) => json!({
            "plan": l.plan, "seats": l.seats, "features": l.features, "expiresAt": l.exp,
            "active": l.active(now), "effectiveSeats": l.effective_seats(now), "licenseId": l.lid,
        }),
        None => json!({ "plan": "free", "effectiveSeats": FREE_SEATS, "active": false }),
    }
}

pub async fn license_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let mut conn = identity.db.acquire().await?;
    Ok(Json(license_json(
        license_of(&mut conn, identity, &user.id).await?.as_ref(),
    )))
}

#[derive(Debug, Deserialize)]
pub struct LicenseBody {
    document: String,
}

pub async fn license_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LicenseBody>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    if !identity.limiter.hit(
        "license",
        &user.id,
        Rule {
            limit: 10,
            window_s: 3600,
        },
        now_s(),
    ) {
        return Err(ApiError::RATE_LIMITED);
    }
    if identity.config.license_keys.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_license_keys",
        ));
    }
    let document = body.document.trim().to_owned();
    let claims = license::verify(
        &document,
        &identity.config.license_keys,
        &identity.config.license_revoked,
    )
    .map_err(|error| {
        tracing::info!(reason = %error, "license rejected");
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_license")
    })?;
    if claims.email != user.email {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "license_email_mismatch",
        ));
    }
    if !claims.active(now_s()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "license_expired",
        ));
    }
    let mut tx = begin_write(&identity.db).await?;
    if !store_license(&mut tx, &user.id, &claims.lid, &document).await? {
        return Err(conflict("license_in_use"));
    }
    tx.commit().await?;
    tracing::info!(seats = claims.seats, "license stored");
    Ok(Json(license_json(Some(&claims))))
}

/// Stores the license document for the account and replaces its previous one. Returns `false`
/// without writing when another account already holds this license ID.
async fn store_license(
    tx: &mut crate::db::Tx,
    user_id: &str,
    lid: &str,
    document: &str,
) -> Result<bool, sqlx::Error> {
    let holder: Option<String> = sqlx::query_scalar("SELECT user_id FROM licenses WHERE lid = ?")
        .bind(lid)
        .fetch_optional(&mut **tx)
        .await?;
    if holder.is_some_and(|h| h != user_id) {
        return Ok(false);
    }
    sqlx::query("INSERT INTO licenses (user_id, lid, document, uploaded_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET lid = excluded.lid, document = excluded.document, uploaded_at = excluded.uploaded_at")
        .bind(user_id)
        .bind(lid)
        .bind(document)
        .bind(now_s())
        .execute(&mut **tx)
        .await?;
    Ok(true)
}

/// Result of `license <file>`: for whom the license was stored and what it grants.
#[derive(Debug)]
pub struct InstalledLicense {
    pub email: String,
    pub seats: u32,
    pub exp: i64,
}

/// `license <file>`: verifies a license document (as downloaded from the website) and stores it
/// for the account of the address it names, creating that account if needed. Same checks as
/// `PUT /v1/license`, without a signed-in user.
pub async fn cli_install_license(
    db: &Db,
    config: &crate::config::Config,
    document: &str,
) -> Result<InstalledLicense, String> {
    if config.license_keys.is_empty() {
        return Err("LICENSE_PUBLIC_KEYS is not set; the license cannot be verified".into());
    }
    let document = document.trim();
    let claims = license::verify(document, &config.license_keys, &config.license_revoked)
        .map_err(|error| format!("invalid license: {error}"))?;
    if !claims.active(now_s()) {
        return Err("the license has expired".into());
    }
    let email = normalize_email(&claims.email).ok_or("the license names no valid email address")?;
    let mut tx = begin_write(db).await.map_err(|e| e.to_string())?;
    let user = find_or_create_user(&mut tx, &email, &config.default_lang, now_s())
        .await
        .map_err(|e| e.to_string())?;
    if !store_license(&mut tx, &user, &claims.lid, document)
        .await
        .map_err(|e| e.to_string())?
    {
        return Err("this license is already stored for another account".into());
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    tracing::info!(seats = claims.seats, "license stored (command)");
    Ok(InstalledLicense {
        email,
        seats: claims.seats,
        exp: claims.exp,
    })
}

pub async fn license_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    sqlx::query("DELETE FROM licenses WHERE user_id = ?")
        .bind(&user.id)
        .execute(&identity.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Account and projects for the app (`/api/v1/me`, `/api/v1/projects`)

/// Seats of the own account (limit from the own license, used across all own teams).
pub async fn account_seats(identity: &Identity, user: &User) -> ApiResult<Seats> {
    let mut conn = identity.db.acquire().await?;
    Ok(seats(&mut conn, identity, &user.id).await?.0)
}

/// A project of the list, as the website returns it (`wiki/Team-Schnittstelle.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectView {
    pub id: String,
    pub name: String,
    pub role: String,
    pub owner_id: String,
    pub plan: String,
    pub seats: Seats,
    /// Only for owner and admin (those allowed to manage invitations).
    pub pending_invitations: Option<u32>,
}

/// The members of `team` with their roles, for a member of it; foreign and unknown teams are
/// "not found". The whole list in one answer (the app refuses paged lists).
pub async fn project_members(
    identity: &Identity,
    user: &User,
    team: &str,
) -> ApiResult<Vec<(String, String)>> {
    require_member(identity, team, user).await?;
    let mut conn = identity.db.acquire().await?;
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, role FROM team_members WHERE team_id = ? \
         ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, joined_at, user_id",
    )
    .bind(team)
    .fetch_all(&mut *conn)
    .await?;
    Ok(members)
}

/// All of the person's teams with the seats of the respective owner account. Four queries
/// regardless of the number of teams (no query per team or per owner): teams,
/// used seats per owner, the owners' licenses, open invitations. Indexes:
/// `team_members_user`, `teams_owner`, `invitations_open`, primary key of `licenses`.
pub async fn projects_of(identity: &Identity, user: &User) -> ApiResult<Vec<ProjectView>> {
    let now = now_s();
    let mut conn = identity.db.acquire().await?;
    let teams: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT t.id, t.name, m.role, t.owner_id FROM team_members m JOIN teams t ON t.id = m.team_id \
         WHERE m.user_id = ? ORDER BY t.name, t.id",
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    if teams.is_empty() {
        return Ok(Vec::new());
    }
    let used: Vec<(String, i64)> = sqlx::query_as(
        "SELECT t.owner_id, COUNT(DISTINCT m.user_id) FROM teams t JOIN team_members m ON m.team_id = t.id \
         WHERE t.owner_id IN (SELECT t2.owner_id FROM team_members m2 JOIN teams t2 ON t2.id = m2.team_id WHERE m2.user_id = ?) \
         GROUP BY t.owner_id",
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    let documents: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, document FROM licenses WHERE user_id IN \
         (SELECT t.owner_id FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ?)",
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    let pending: Vec<(String, i64)> = sqlx::query_as(
        "SELECT i.team_id, COUNT(*) FROM invitations i \
         JOIN team_members m ON m.team_id = i.team_id AND m.user_id = ? AND m.role IN ('owner', 'admin') \
         WHERE i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ? GROUP BY i.team_id",
    )
    .bind(&user.id)
    .bind(now)
    .fetch_all(&mut *conn)
    .await?;
    let used: HashMap<String, u32> = used
        .into_iter()
        .map(|(owner, n)| (owner, u32::try_from(n).unwrap_or(u32::MAX)))
        .collect();
    let licenses: HashMap<String, LicenseClaims> = documents
        .into_iter()
        .filter_map(|(owner, document)| {
            license::verify(
                &document,
                &identity.config.license_keys,
                &identity.config.license_revoked,
            )
            .ok()
            .map(|claims| (owner, claims))
        })
        .collect();
    let pending: HashMap<String, u32> = pending
        .into_iter()
        .map(|(team, n)| (team, u32::try_from(n).unwrap_or(u32::MAX)))
        .collect();
    Ok(teams
        .into_iter()
        .map(|(id, name, role, owner_id)| {
            let lic = licenses.get(&owner_id);
            let manages = Role::parse(&role).is_some_and(|r| r.rank() >= Role::Admin.rank());
            ProjectView {
                pending_invitations: manages.then(|| pending.get(&id).copied().unwrap_or(0)),
                plan: lic
                    .filter(|l| l.active(now))
                    .map_or("free", |l| l.plan.as_str())
                    .to_owned(),
                seats: Seats {
                    limit: license::seats_for(lic, now),
                    used: used.get(&owner_id).copied().unwrap_or(0),
                },
                id,
                name,
                role,
                owner_id,
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// Tickets

/// Tickets per account and hour (old and new route share the counter).
const TICKET_RULE: Rule = Rule {
    limit: 600,
    window_s: 3600,
};

/// Address of the live channel from `PUBLIC_URL`: `http` becomes `ws`, `https` becomes `wss`.
pub fn live_url(public_url: &str) -> String {
    if let Some(rest) = public_url.strip_prefix("https://") {
        format!("wss://{rest}/v1/live")
    } else if let Some(rest) = public_url.strip_prefix("http://") {
        format!("ws://{rest}/v1/live")
    } else {
        format!("{public_url}/v1/live")
    }
}

/// Service: short-lived ticket for `hello`, in the website's format (`docs/ticket-format.md`).
/// Members only; foreign and unknown teams are equally "not found".
/// Returns ticket and expiry (Unix seconds).
pub async fn issue(identity: &Identity, user: &User, team: &str) -> ApiResult<(String, i64)> {
    if !identity
        .limiter
        .hit("ticket", &user.id, TICKET_RULE, now_s())
    {
        return Err(ApiError::RATE_LIMITED);
    }
    let role = require_member(identity, team, user).await?;
    let now = now_s();
    let claims = TicketClaims {
        v: 1,
        kid: identity.ticket_kid().to_owned(),
        sub: user.id.clone(),
        prj: team.to_owned(),
        role,
        seat_ok: true,
        iat: now,
        exp: now + TICKET_TTL_S,
        jti: random_token(),
        aud: Some(identity.config.ticket_audience.clone()),
    };
    let payload = serde_json::to_vec(&claims).map_err(|_| ApiError::INTERNAL)?;
    let ticket = signed::sign(&payload, TICKET_CONTEXT, identity.signing_key());
    Ok((ticket, claims.exp))
}

#[derive(Debug, Deserialize)]
pub struct TicketRequest {
    team: String,
}

/// `POST /v1/tickets` (old form). The app uses `POST /api/v1/relay-ticket`.
pub async fn issue_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TicketRequest>,
) -> ApiResult<Json<Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let (ticket, _) = issue(identity, &user, &body.team).await?;
    Ok(Json(
        json!({ "ticket": ticket, "expiresIn": TICKET_TTL_S, "live": live_url(&identity.config.public_url) }),
    ))
}

// ---------------------------------------------------------------------------------------------
// Attention mails

/// "Something needs your attention": at most one mail per person, team and hour, without
/// any content.
pub async fn attention_worker(
    identity: Arc<Identity>,
    mut rx: mpsc::Receiver<Attention>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let item = tokio::select! {
            item = rx.recv() => match item { Some(item) => item, None => break },
            _ = shutdown.changed() => break,
        };
        if let Err(error) = notify(&identity, &item).await {
            tracing::error!(%error, "attention mail not prepared");
        }
    }
}

async fn notify(identity: &Identity, item: &Attention) -> Result<(), sqlx::Error> {
    let now = now_s();
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT u.email, u.lang, t.name FROM team_members m JOIN users u ON u.id = m.user_id JOIN teams t ON t.id = m.team_id \
         WHERE m.team_id = ? AND m.user_id = ?",
    )
    .bind(&item.team)
    .bind(&item.member)
    .fetch_optional(&identity.db)
    .await?;
    let Some((email, lang, team)) = row else {
        return Ok(());
    };
    let fresh = sqlx::query(
        "INSERT INTO mail_throttle (user_id, team_id, kind, sent_at) VALUES (?, ?, 'attention', ?) \
         ON CONFLICT (user_id, team_id, kind) DO UPDATE SET sent_at = excluded.sent_at WHERE mail_throttle.sent_at < ?",
    )
    .bind(&item.member)
    .bind(&item.team)
    .bind(now)
    .bind(now - ATTENTION_INTERVAL_S)
    .execute(&identity.db)
    .await?;
    if fresh.rows_affected() == 1 {
        identity.mailer.send(
            &email,
            mail_lang(Some(&lang), &identity.config),
            MailKind::Attention { team },
        );
    }
    Ok(())
}
