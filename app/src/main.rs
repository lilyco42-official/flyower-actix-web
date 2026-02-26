use actix_files::Files;
use actix_multipart::Multipart;
use actix_web::{
    delete, get, post,
    web::{self, Data, Json, Path, Query},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use bytes::BytesMut;
use futures_util::StreamExt;
use image::ImageReader;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

// ─── Constants ───────────────────────────────────────────────────────────────

const DAILY_LIMIT_BYTES: i64 = 50 * 1024 * 1024;
const MAX_FILE_BYTES: i64 = 10 * 1024 * 1024;

static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-key".to_string())
});

// ─── DB Wrapper ──────────────────────────────────────────────────────────────

struct Db(Mutex<Connection>);

impl Db {
    fn new(path: &str) -> Self {
        let conn = Connection::open(path).expect("open db");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        Self(Mutex::new(conn))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap()
    }
}

// ─── Models ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    user_id: i64,
    username: String,
    role: String,
    exp: u64,
}

fn make_token(user_id: i64, username: &str, role: &str) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60 * 60 * 24 * 7;
    let claims = Claims {
        user_id,
        username: username.to_string(),
        role: role.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn verify_token(token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
}

fn extract_user(req: &HttpRequest) -> Option<Claims> {
    let auth = req.headers().get("Authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    verify_token(token)
}

fn is_admin(db: &Db, user_id: i64) -> bool {
    let conn = db.lock();
    conn.query_row(
        "SELECT role FROM users WHERE id=?1",
        params![user_id],
        |row| row.get::<_, String>(0),
    )
    .map(|r| r == "admin")
    .unwrap_or(false)
}

fn get_today_usage(db: &Db, user_id: i64) -> i64 {
    let conn = db.lock();
    conn.query_row(
        "SELECT COALESCE(SUM(file_size),0) FROM images WHERE user_id=?1 AND DATE(created_at)=DATE('now','localtime')",
        params![user_id],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0)
}

// ─── DB Init ─────────────────────────────────────────────────────────────────

fn init_db(db: &Db) {
    let conn = db.lock();
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            is_banned     INTEGER NOT NULL DEFAULT 0,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS images (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            title         TEXT,
            description   TEXT,
            filename      TEXT NOT NULL,
            width         INTEGER,
            height        INTEGER,
            file_size     INTEGER NOT NULL DEFAULT 0,
            status        TEXT NOT NULL DEFAULT 'pending',
            reject_reason TEXT,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS tags (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS image_tags (
            image_id INTEGER,
            tag_id   INTEGER,
            PRIMARY KEY (image_id, tag_id),
            FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id)   REFERENCES tags(id)   ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS likes (
            user_id    INTEGER,
            image_id   INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, image_id),
            FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE,
            FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS collections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            description TEXT,
            is_public   INTEGER NOT NULL DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS collection_images (
            collection_id INTEGER,
            image_id      INTEGER,
            added_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection_id, image_id),
            FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
            FOREIGN KEY (image_id)      REFERENCES images(id)      ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS follows (
            follower_id  INTEGER,
            following_id INTEGER,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (follower_id, following_id),
            FOREIGN KEY (follower_id)  REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE
        );
        "#,
    )
    .unwrap();
}

// ─── Request / Response Types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct SignUpBody {
    username: String,
    email: Option<String>,
    password: String,
    confirm_password: String,
}

#[derive(Deserialize)]
struct SignInBody {
    login: String,
    password: String,
}

#[derive(Deserialize)]
struct ImageListQuery {
    page: Option<i64>,
    limit: Option<i64>,
    tag: Option<String>,
    q: Option<String>,
    sort: Option<String>,
}

#[derive(Deserialize)]
struct PaginationQuery {
    page: Option<i64>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct AdminImagesQuery {
    page: Option<i64>,
    limit: Option<i64>,
    status: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct AdminUsersQuery {
    page: Option<i64>,
    limit: Option<i64>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct ReviewBody {
    action: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct BatchReviewBody {
    ids: Vec<i64>,
    action: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct BanBody {
    ban: bool,
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

#[derive(Deserialize)]
struct CollectionBody {
    name: String,
    description: Option<String>,
    is_public: Option<bool>,
}

#[derive(Deserialize)]
struct CollectionAddBody {
    image_id: i64,
}

fn ok<T: Serialize>(v: T) -> HttpResponse {
    HttpResponse::Ok().json(v)
}
fn err(status: u16, msg: &str) -> HttpResponse {
    let body = serde_json::json!({ "message": msg });
    match status {
        400 => HttpResponse::BadRequest().json(body),
        401 => HttpResponse::Unauthorized().json(body),
        403 => HttpResponse::Forbidden().json(body),
        404 => HttpResponse::NotFound().json(body),
        413 => HttpResponse::PayloadTooLarge().json(body),
        429 => HttpResponse::TooManyRequests().json(body),
        _ => HttpResponse::InternalServerError().json(body),
    }
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────

#[post("/sign_up")]
async fn sign_up(db: Data<Db>, body: Json<SignUpBody>) -> impl Responder {
    let b = body.into_inner();
    if b.username.is_empty() || b.password.is_empty() {
        return err(400, "必填项不能为空");
    }
    if b.password.len() < 6 {
        return err(400, "密码至少6位");
    }
    if b.password != b.confirm_password {
        return err(400, "两次密码不一致");
    }
    {
        let conn = db.lock();
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username=?1",
                params![b.username],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if exists {
            return err(400, "用户名已存在");
        }
        if let Some(ref email) = b.email {
            if !email.contains('@') || !email.contains('.') {
                return err(400, "邮箱格式不正确");
            }
            let e_exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM users WHERE email=?1",
                    params![email],
                    |r| r.get::<_, i64>(0),
                )
                .map(|c| c > 0)
                .unwrap_or(false);
            if e_exists {
                return err(400, "邮箱已被注册");
            }
        }
    }
    let hash_val = hash(&b.password, DEFAULT_COST).unwrap();
    let conn = db.lock();
    match conn.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?1,?2,?3)",
        params![b.username, hash_val, b.email],
    ) {
        Ok(_) => ok(serde_json::json!({ "success": true, "message": "注册成功" })),
        Err(_) => err(500, "注册失败，请稍后重试"),
    }
}

#[post("/sign_in")]
async fn sign_in(db: Data<Db>, body: Json<SignInBody>) -> impl Responder {
    let b = body.into_inner();
    let conn = db.lock();
    let sql = if b.login.contains('@') {
        "SELECT id,username,email,password_hash,role,is_banned FROM users WHERE email=?1"
    } else {
        "SELECT id,username,email,password_hash,role,is_banned FROM users WHERE username=?1"
    };
    let row = conn.query_row(sql, params![b.login], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
        ))
    });
    match row {
        Err(_) => err(401, "用户名/邮箱或密码错误"),
        Ok((id, username, _email, pw_hash, role, is_banned)) => {
            if is_banned != 0 {
                return err(403, "账号已被封禁，请联系管理员");
            }
            if !verify(&b.password, &pw_hash).unwrap_or(false) {
                return err(401, "用户名/邮箱或密码错误");
            }
            let token = make_token(id, &username, &role);
            ok(serde_json::json!({
                "success": true,
                "message": "登录成功",
                "token": token,
                "user": { "username": username, "role": role }
            }))
        }
    }
}

#[post("/sign_out")]
async fn sign_out() -> impl Responder {
    ok(serde_json::json!({ "success": true, "message": "已登出" }))
}

#[get("/me")]
async fn me(req: HttpRequest, db: Data<Db>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "未认证"),
    };
    let conn = db.lock();
    match conn.query_row(
        "SELECT id,username,role,is_banned FROM users WHERE id=?1",
        params![user.user_id],
        |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "username": r.get::<_,String>(1)?,
                "role": r.get::<_,String>(2)?,
                "is_banned": r.get::<_,i64>(3)?
            }))
        },
    ) {
        Ok(v) => ok(v),
        Err(_) => err(404, "用户不存在"),
    }
}

#[get("/me/upload-quota")]
async fn upload_quota(req: HttpRequest, db: Data<Db>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "未认证"),
    };
    let used = get_today_usage(&db, user.user_id);
    let remaining = (DAILY_LIMIT_BYTES - used).max(0);
    ok(serde_json::json!({
        "used": used,
        "limit": DAILY_LIMIT_BYTES,
        "remaining": remaining,
        "usedMB": format!("{:.2}", used as f64 / 1024.0 / 1024.0),
        "limitMB": "50.00",
        "remainingMB": format!("{:.2}", remaining as f64 / 1024.0 / 1024.0),
    }))
}

// ─── Image Upload ─────────────────────────────────────────────────────────────

#[post("/images")]
async fn upload_image(
    req: HttpRequest,
    db: Data<Db>,
    mut payload: Multipart,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    {
        let conn = db.lock();
        let banned: i64 = conn
            .query_row(
                "SELECT is_banned FROM users WHERE id=?1",
                params![user.user_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if banned != 0 {
            return err(403, "账号已封禁");
        }
    }

    let mut file_data: Option<(Vec<u8>, String, String)> = None; // bytes, filename, content_type
    let mut title: Option<String> = None;
    let mut description: Option<String> = None;
    let mut tags: Option<String> = None;

    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(_) => return err(400, "multipart解析失败"),
        };
        let field_name = field.name().unwrap_or("").to_string();
        let mut buf = BytesMut::new();
        while let Some(chunk) = field.next().await {
            match chunk {
                Ok(c) => buf.extend_from_slice(&c),
                Err(_) => return err(400, "读取数据失败"),
            }
        }
        match field_name.as_str() {
            "file" => {
                let content_type = field
                    .content_type()
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                let orig_name = field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .unwrap_or("upload.bin")
                    .to_string();
                file_data = Some((buf.to_vec(), orig_name, content_type));
            }
            "title" => title = Some(String::from_utf8_lossy(&buf).to_string()),
            "description" => description = Some(String::from_utf8_lossy(&buf).to_string()),
            "tags" => tags = Some(String::from_utf8_lossy(&buf).to_string()),
            _ => {}
        }
    }

    let (data, orig_name, content_type) = match file_data {
        Some(f) => f,
        None => return err(400, "请上传有效图片"),
    };

    if !content_type.starts_with("image/") {
        return err(400, "请上传有效图片");
    }
    let file_size = data.len() as i64;
    if file_size > MAX_FILE_BYTES {
        return err(413, "单张图片 ≤ 10MB");
    }

    let today_used = get_today_usage(&db, user.user_id);
    if today_used + file_size > DAILY_LIMIT_BYTES {
        let remaining_mb = (DAILY_LIMIT_BYTES - today_used) as f64 / 1024.0 / 1024.0;
        return err(
            429,
            &format!("今日额度不足，剩余 {:.2}MB", remaining_mb),
        );
    }

    let ext = std::path::Path::new(&orig_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();
    let filename = format!("{}{}", Uuid::new_v4(), ext);
    let dest = format!("uploads/{}", filename);

    if let Err(e) = std::fs::write(&dest, &data) {
        eprintln!("写文件失败: {e}");
        return err(500, "保存文件失败");
    }

    // Get image dimensions
    let (width, height) = ImageReader::new(Cursor::new(&data))
        .with_guessed_format()
        .ok()
        .and_then(|r| r.decode().ok())
        .map(|img| (img.width() as i64, img.height() as i64))
        .unwrap_or((0, 0));

    let image_id: i64 = {
        let conn = db.lock();
        conn.execute(
            "INSERT INTO images (user_id,title,description,filename,width,height,file_size,status) VALUES (?1,?2,?3,?4,?5,?6,?7,'pending')",
            params![user.user_id, title, description, filename, width, height, file_size],
        )
        .unwrap();
        conn.last_insert_rowid()
    };

    if let Some(tag_str) = tags {
        let conn = db.lock();
        for tag_name in tag_str
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
        {
            conn.execute(
                "INSERT OR IGNORE INTO tags (name) VALUES (?1)",
                params![tag_name],
            )
            .unwrap();
            let tag_id: i64 = conn
                .query_row(
                    "SELECT id FROM tags WHERE name=?1",
                    params![tag_name],
                    |r| r.get(0),
                )
                .unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO image_tags VALUES (?1,?2)",
                params![image_id, tag_id],
            )
            .unwrap();
        }
    }

    ok(serde_json::json!({ "success": true, "imageId": image_id }))
}

// ─── Image Queries ────────────────────────────────────────────────────────────

const IMAGE_SELECT: &str = r#"
    SELECT i.id, i.user_id, i.title, i.description, i.filename, i.width, i.height,
           i.file_size, i.status, i.reject_reason, i.created_at, u.username,
           (SELECT COUNT(*) FROM likes WHERE image_id=i.id) AS like_count,
           (SELECT COUNT(*) FROM collection_images WHERE image_id=i.id) AS collect_count,
           EXISTS(SELECT 1 FROM likes WHERE image_id=i.id AND user_id=?1) AS liked
    FROM images i JOIN users u ON u.id=i.user_id
"#;

fn row_to_image(r: &rusqlite::Row) -> rusqlite::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "id": r.get::<_,i64>(0)?,
        "user_id": r.get::<_,i64>(1)?,
        "title": r.get::<_,Option<String>>(2)?,
        "description": r.get::<_,Option<String>>(3)?,
        "filename": r.get::<_,String>(4)?,
        "width": r.get::<_,Option<i64>>(5)?,
        "height": r.get::<_,Option<i64>>(6)?,
        "file_size": r.get::<_,i64>(7)?,
        "status": r.get::<_,String>(8)?,
        "reject_reason": r.get::<_,Option<String>>(9)?,
        "created_at": r.get::<_,String>(10)?,
        "username": r.get::<_,String>(11)?,
        "like_count": r.get::<_,i64>(12)?,
        "collect_count": r.get::<_,i64>(13)?,
        "liked": r.get::<_,bool>(14)?
    }))
}

#[get("/images")]
async fn list_images(req: HttpRequest, db: Data<Db>, query: Query<ImageListQuery>) -> impl Responder {
    let uid = extract_user(&req).map(|u| u.user_id).unwrap_or(0);
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);
    let offset = (page - 1) * limit;
    let sort = query.sort.as_deref().unwrap_or("latest");

    let conn = db.lock();
    let mut sql = IMAGE_SELECT.to_string();
    let mut conds = vec!["i.status = 'approved'".to_string()];
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(uid)];

    if let Some(tag) = &query.tag {
        sql.push_str(" JOIN image_tags it ON it.image_id=i.id JOIN tags t ON t.id=it.tag_id");
        conds.push("t.name=?".to_string());
        params_vec.push(Box::new(tag.clone()));
    }
    if let Some(q) = &query.q {
        conds.push("(i.title LIKE ? OR i.description LIKE ?)".to_string());
        let pat = format!("%{}%", q);
        params_vec.push(Box::new(pat.clone()));
        params_vec.push(Box::new(pat));
    }
    sql.push_str(&format!(" WHERE {}", conds.join(" AND ")));
    match sort {
        "hot" => sql.push_str(" ORDER BY like_count DESC, i.created_at DESC"),
        "random" => sql.push_str(" ORDER BY RANDOM()"),
        _ => sql.push_str(" ORDER BY i.created_at DESC"),
    }
    sql.push_str(" LIMIT ? OFFSET ?");
    params_vec.push(Box::new(limit));
    params_vec.push(Box::new(offset));

    let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql).unwrap();
    let images: Vec<serde_json::Value> = stmt
        .query_map(refs.as_slice(), row_to_image)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    ok(serde_json::json!({ "success": true, "images": images }))
}

#[get("/images/{id}")]
async fn get_image(req: HttpRequest, db: Data<Db>, path: Path<i64>) -> impl Responder {
    let uid = extract_user(&req).map(|u| u.user_id).unwrap_or(0);
    let image_id = path.into_inner();
    let conn = db.lock();
    let sql = format!(
        "{} WHERE i.id=?2 AND i.status='approved'",
        IMAGE_SELECT
    );
    match conn.query_row(&sql, params![uid, image_id], row_to_image) {
        Err(_) => err(404, "图片不存在"),
        Ok(mut img) => {
            let tags: Vec<String> = conn
                .prepare(
                    "SELECT t.name FROM tags t JOIN image_tags it ON it.tag_id=t.id WHERE it.image_id=?1",
                )
                .unwrap()
                .query_map(params![image_id], |r| r.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            img["tags"] = serde_json::json!(tags);
            ok(img)
        }
    }
}

#[post("/images/{id}/like")]
async fn like_image(req: HttpRequest, db: Data<Db>, path: Path<i64>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let image_id = path.into_inner();
    let conn = db.lock();
    if conn
        .query_row(
            "SELECT id FROM images WHERE id=?1",
            params![image_id],
            |r| r.get::<_, i64>(0),
        )
        .is_err()
    {
        return err(404, "图片不存在");
    }
    let liked = conn
        .query_row(
            "SELECT 1 FROM likes WHERE user_id=?1 AND image_id=?2",
            params![user.user_id, image_id],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if liked {
        conn.execute(
            "DELETE FROM likes WHERE user_id=?1 AND image_id=?2",
            params![user.user_id, image_id],
        )
        .unwrap();
    } else {
        conn.execute(
            "INSERT INTO likes (user_id,image_id) VALUES (?1,?2)",
            params![user.user_id, image_id],
        )
        .unwrap();
    }
    let cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM likes WHERE image_id=?1",
            params![image_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    ok(serde_json::json!({ "success": true, "liked": !liked, "like_count": cnt }))
}

// ─── Collections ──────────────────────────────────────────────────────────────

#[post("/collections")]
async fn create_collection(
    req: HttpRequest,
    db: Data<Db>,
    body: Json<CollectionBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let b = body.into_inner();
    if b.name.is_empty() {
        return err(400, "名称不能为空");
    }
    let is_public = b.is_public.unwrap_or(true) as i64;
    let conn = db.lock();
    conn.execute(
        "INSERT INTO collections (user_id,name,description,is_public) VALUES (?1,?2,?3,?4)",
        params![user.user_id, b.name, b.description, is_public],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    ok(serde_json::json!({ "success": true, "collectionId": id }))
}

#[get("/me/collections")]
async fn my_collections(req: HttpRequest, db: Data<Db>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let conn = db.lock();
    let collections: Vec<serde_json::Value> = conn
        .prepare(
            r#"SELECT c.*,
               (SELECT COUNT(*) FROM collection_images WHERE collection_id=c.id) AS image_count,
               (SELECT filename FROM images WHERE id=(SELECT image_id FROM collection_images WHERE collection_id=c.id ORDER BY added_at ASC LIMIT 1)) AS cover_filename
               FROM collections c WHERE c.user_id=?1 ORDER BY c.created_at DESC"#,
        )
        .unwrap()
        .query_map(params![user.user_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "user_id": r.get::<_,i64>(1)?,
                "name": r.get::<_,String>(2)?,
                "description": r.get::<_,Option<String>>(3)?,
                "is_public": r.get::<_,i64>(4)?,
                "created_at": r.get::<_,String>(5)?,
                "image_count": r.get::<_,i64>(6)?,
                "cover_filename": r.get::<_,Option<String>>(7)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "collections": collections }))
}

#[get("/users/{username}/collections")]
async fn user_collections(db: Data<Db>, path: Path<String>) -> impl Responder {
    let username = path.into_inner();
    let conn = db.lock();
    let uid: i64 = match conn.query_row(
        "SELECT id FROM users WHERE username=?1",
        params![username],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "用户不存在"),
    };
    let collections: Vec<serde_json::Value> = conn
        .prepare(
            r#"SELECT c.*,
               (SELECT COUNT(*) FROM collection_images WHERE collection_id=c.id) AS image_count,
               (SELECT filename FROM images WHERE id=(SELECT image_id FROM collection_images WHERE collection_id=c.id ORDER BY added_at ASC LIMIT 1)) AS cover_filename
               FROM collections c WHERE c.user_id=?1 AND c.is_public=1 ORDER BY c.created_at DESC"#,
        )
        .unwrap()
        .query_map(params![uid], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "user_id": r.get::<_,i64>(1)?,
                "name": r.get::<_,String>(2)?,
                "description": r.get::<_,Option<String>>(3)?,
                "is_public": r.get::<_,i64>(4)?,
                "created_at": r.get::<_,String>(5)?,
                "image_count": r.get::<_,i64>(6)?,
                "cover_filename": r.get::<_,Option<String>>(7)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "collections": collections }))
}

#[get("/collections/{id}/images")]
async fn collection_images(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
) -> impl Responder {
    let collection_id = path.into_inner();
    let user = extract_user(&req);
    let conn = db.lock();
    let col = conn.query_row(
        "SELECT id,user_id,name,description,is_public,created_at FROM collections WHERE id=?1",
        params![collection_id],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
            ))
        },
    );
    match col {
        Err(_) => err(404, "收藏夹不存在"),
        Ok((id, owner_id, name, desc, is_public, created_at)) => {
            if is_public == 0 {
                match &user {
                    Some(u) if u.user_id == owner_id => {}
                    _ => return err(403, "无权访问"),
                }
            }
            let uid = user.as_ref().map(|u| u.user_id).unwrap_or(0);
            let sql = format!(
                "{} JOIN collection_images ci ON ci.image_id=i.id WHERE ci.collection_id=?2 ORDER BY ci.added_at DESC",
                IMAGE_SELECT
            );
            let images: Vec<serde_json::Value> = conn
                .prepare(&sql)
                .unwrap()
                .query_map(params![uid, collection_id], row_to_image)
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            ok(serde_json::json!({
                "success": true,
                "collection": { "id": id, "user_id": owner_id, "name": name, "description": desc, "is_public": is_public, "created_at": created_at },
                "images": images
            }))
        }
    }
}

#[post("/collections/{id}/images")]
async fn add_to_collection(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
    body: Json<CollectionAddBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let collection_id = path.into_inner();
    let conn = db.lock();
    let owner_id: i64 = match conn.query_row(
        "SELECT user_id FROM collections WHERE id=?1",
        params![collection_id],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "收藏夹不存在"),
    };
    if owner_id != user.user_id {
        return err(403, "无权操作");
    }
    let image_id = body.image_id;
    match conn.execute(
        "INSERT INTO collection_images (collection_id,image_id) VALUES (?1,?2)",
        params![collection_id, image_id],
    ) {
        Ok(_) => ok(serde_json::json!({ "success": true })),
        Err(_) => {
            conn.execute(
                "DELETE FROM collection_images WHERE collection_id=?1 AND image_id=?2",
                params![collection_id, image_id],
            )
            .unwrap();
            ok(serde_json::json!({ "success": true, "removed": true }))
        }
    }
}

#[delete("/collections/{id}")]
async fn delete_collection(req: HttpRequest, db: Data<Db>, path: Path<i64>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let collection_id = path.into_inner();
    let conn = db.lock();
    let owner_id: i64 = match conn.query_row(
        "SELECT user_id FROM collections WHERE id=?1",
        params![collection_id],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "收藏夹不存在"),
    };
    if owner_id != user.user_id {
        return err(403, "无权操作");
    }
    conn.execute(
        "DELETE FROM collections WHERE id=?1",
        params![collection_id],
    )
    .unwrap();
    ok(serde_json::json!({ "success": true }))
}

#[get("/images/{id}/my-collections")]
async fn my_collection_status(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let image_id = path.into_inner();
    let conn = db.lock();
    let collections: Vec<serde_json::Value> = conn
        .prepare(
            "SELECT c.id,c.name,EXISTS(SELECT 1 FROM collection_images WHERE collection_id=c.id AND image_id=?1) AS collected FROM collections c WHERE c.user_id=?2 ORDER BY c.created_at DESC",
        )
        .unwrap()
        .query_map(params![image_id, user.user_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "name": r.get::<_,String>(1)?,
                "collected": r.get::<_,bool>(2)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "collections": collections }))
}

// ─── Follows ──────────────────────────────────────────────────────────────────

#[post("/users/{username}/follow")]
async fn follow_user(req: HttpRequest, db: Data<Db>, path: Path<String>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let username = path.into_inner();
    let conn = db.lock();
    let target_id: i64 = match conn.query_row(
        "SELECT id FROM users WHERE username=?1",
        params![username],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "用户不存在"),
    };
    if target_id == user.user_id {
        return err(400, "不能关注自己");
    }
    match conn.execute(
        "INSERT INTO follows (follower_id,following_id) VALUES (?1,?2)",
        params![user.user_id, target_id],
    ) {
        Ok(_) => ok(serde_json::json!({ "followed": true })),
        Err(_) => {
            conn.execute(
                "DELETE FROM follows WHERE follower_id=?1 AND following_id=?2",
                params![user.user_id, target_id],
            )
            .unwrap();
            ok(serde_json::json!({ "followed": false }))
        }
    }
}

#[get("/users/{username}/followers")]
async fn user_followers(db: Data<Db>, path: Path<String>) -> impl Responder {
    let username = path.into_inner();
    let conn = db.lock();
    let uid: i64 = match conn.query_row(
        "SELECT id FROM users WHERE username=?1",
        params![username],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "用户不存在"),
    };
    let followers: Vec<serde_json::Value> = conn
        .prepare(
            "SELECT u.id,u.username,(SELECT COUNT(*) FROM follows WHERE following_id=u.id) AS follower_count FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.following_id=?1 ORDER BY f.created_at DESC",
        )
        .unwrap()
        .query_map(params![uid], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "username": r.get::<_,String>(1)?,
                "follower_count": r.get::<_,i64>(2)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "followers": followers }))
}

#[get("/users/{username}/following")]
async fn user_following(db: Data<Db>, path: Path<String>) -> impl Responder {
    let username = path.into_inner();
    let conn = db.lock();
    let uid: i64 = match conn.query_row(
        "SELECT id FROM users WHERE username=?1",
        params![username],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "用户不存在"),
    };
    let following: Vec<serde_json::Value> = conn
        .prepare(
            "SELECT u.id,u.username,(SELECT COUNT(*) FROM follows WHERE following_id=u.id) AS follower_count FROM follows f JOIN users u ON u.id=f.following_id WHERE f.follower_id=?1 ORDER BY f.created_at DESC",
        )
        .unwrap()
        .query_map(params![uid], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "username": r.get::<_,String>(1)?,
                "follower_count": r.get::<_,i64>(2)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "following": following }))
}

// ─── User Profile / Feed ──────────────────────────────────────────────────────

#[get("/users/{username}")]
async fn get_user(req: HttpRequest, db: Data<Db>, path: Path<String>) -> impl Responder {
    let viewer = extract_user(&req);
    let username = path.into_inner();
    let conn = db.lock();
    let user = conn.query_row(
        r#"SELECT id,username,created_at,
           (SELECT COUNT(*) FROM images WHERE user_id=id AND status='approved') AS image_count,
           (SELECT COUNT(*) FROM follows WHERE following_id=id) AS follower_count,
           (SELECT COUNT(*) FROM follows WHERE follower_id=id) AS following_count
           FROM users WHERE username=?1"#,
        params![username],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        },
    );
    match user {
        Err(_) => err(404, "用户不存在"),
        Ok((uid, uname, created_at, image_count, follower_count, following_count)) => {
            let is_following = match &viewer {
                Some(v) if v.user_id != uid => conn
                    .query_row(
                        "SELECT 1 FROM follows WHERE follower_id=?1 AND following_id=?2",
                        params![v.user_id, uid],
                        |_| Ok(true),
                    )
                    .unwrap_or(false),
                _ => false,
            };
            ok(serde_json::json!({
                "success": true,
                "user": {
                    "id": uid,
                    "username": uname,
                    "created_at": created_at,
                    "image_count": image_count,
                    "follower_count": follower_count,
                    "following_count": following_count,
                    "is_following": is_following
                }
            }))
        }
    }
}

#[get("/users/{username}/images")]
async fn user_images(db: Data<Db>, path: Path<String>) -> impl Responder {
    let username = path.into_inner();
    let conn = db.lock();
    let uid: i64 = match conn.query_row(
        "SELECT id FROM users WHERE username=?1",
        params![username],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return err(404, "用户不存在"),
    };
    let sql = format!(
        "{} WHERE i.user_id=?2 AND i.status='approved' ORDER BY i.created_at DESC",
        IMAGE_SELECT
    );
    let images: Vec<serde_json::Value> = conn
        .prepare(&sql)
        .unwrap()
        .query_map(params![0i64, uid], row_to_image)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "images": images }))
}

#[get("/feed/following")]
async fn feed_following(
    req: HttpRequest,
    db: Data<Db>,
    query: Query<PaginationQuery>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(401, "请先登录"),
    };
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);
    let offset = (page - 1) * limit;
    let conn = db.lock();
    let sql = format!(
        "{} WHERE i.user_id IN (SELECT following_id FROM follows WHERE follower_id=?2) AND i.status='approved' ORDER BY i.created_at DESC LIMIT ?3 OFFSET ?4",
        IMAGE_SELECT
    );
    let images: Vec<serde_json::Value> = conn
        .prepare(&sql)
        .unwrap()
        .query_map(params![user.user_id, user.user_id, limit, offset], row_to_image)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok(serde_json::json!({ "success": true, "images": images }))
}

// ─── Admin Routes ─────────────────────────────────────────────────────────────

#[get("/admin/stats")]
async fn admin_stats(req: HttpRequest, db: Data<Db>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let conn = db.lock();
    macro_rules! cnt {
        ($sql:expr) => {
            conn.query_row($sql, [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
        };
    }
    ok(serde_json::json!({
        "success": true,
        "stats": {
            "users":        cnt!("SELECT COUNT(*) FROM users"),
            "images":       cnt!("SELECT COUNT(*) FROM images"),
            "pending":      cnt!("SELECT COUNT(*) FROM images WHERE status='pending'"),
            "approved":     cnt!("SELECT COUNT(*) FROM images WHERE status='approved'"),
            "rejected":     cnt!("SELECT COUNT(*) FROM images WHERE status='rejected'"),
            "likes":        cnt!("SELECT COUNT(*) FROM likes"),
            "collections":  cnt!("SELECT COUNT(*) FROM collections"),
            "banned":       cnt!("SELECT COUNT(*) FROM users WHERE is_banned=1"),
            "today_uploads":cnt!("SELECT COUNT(*) FROM images WHERE DATE(created_at)=DATE('now','localtime')"),
            "today_users":  cnt!("SELECT COUNT(*) FROM users WHERE DATE(created_at)=DATE('now','localtime')"),
        }
    }))
}

#[get("/admin/images")]
async fn admin_list_images(
    req: HttpRequest,
    db: Data<Db>,
    query: Query<AdminImagesQuery>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);
    let offset = (page - 1) * limit;
    let status = query.status.as_deref().unwrap_or("pending");

    let conn = db.lock();
    let mut base = "SELECT i.*,u.username,(SELECT COUNT(*) FROM likes WHERE image_id=i.id) AS like_count FROM images i JOIN users u ON u.id=i.user_id".to_string();
    let mut conds: Vec<String> = vec![];
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if status != "all" {
        conds.push("i.status=?".to_string());
        params_vec.push(Box::new(status.to_string()));
    }
    if let Some(q) = &query.q {
        conds.push("(i.title LIKE ? OR i.description LIKE ? OR u.username LIKE ?)".to_string());
        let pat = format!("%{}%", q);
        params_vec.push(Box::new(pat.clone()));
        params_vec.push(Box::new(pat.clone()));
        params_vec.push(Box::new(pat));
    }
    if !conds.is_empty() {
        base.push_str(&format!(" WHERE {}", conds.join(" AND ")));
    }

    let count_sql = format!(
        "SELECT COUNT(*) FROM images i JOIN users u ON u.id=i.user_id{}",
        if !conds.is_empty() {
            format!(" WHERE {}", conds.join(" AND "))
        } else {
            String::new()
        }
    );
    let count_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
    let total: i64 = conn
        .query_row(&count_sql, count_refs.as_slice(), |r| r.get(0))
        .unwrap_or(0);

    base.push_str(" ORDER BY i.created_at DESC LIMIT ? OFFSET ?");
    params_vec.push(Box::new(limit));
    params_vec.push(Box::new(offset));
    let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();

    let images: Vec<serde_json::Value> = conn
        .prepare(&base)
        .unwrap()
        .query_map(refs.as_slice(), |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "user_id": r.get::<_,i64>(1)?,
                "title": r.get::<_,Option<String>>(2)?,
                "description": r.get::<_,Option<String>>(3)?,
                "filename": r.get::<_,String>(4)?,
                "width": r.get::<_,Option<i64>>(5)?,
                "height": r.get::<_,Option<i64>>(6)?,
                "file_size": r.get::<_,i64>(7)?,
                "status": r.get::<_,String>(8)?,
                "reject_reason": r.get::<_,Option<String>>(9)?,
                "created_at": r.get::<_,String>(10)?,
                "username": r.get::<_,String>(11)?,
                "like_count": r.get::<_,i64>(12)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    ok(serde_json::json!({ "success": true, "images": images, "total": total }))
}

#[post("/admin/images/{id}/review")]
async fn admin_review_image(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
    body: Json<ReviewBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let image_id = path.into_inner();
    let b = body.into_inner();
    if b.action != "approve" && b.action != "reject" {
        return err(400, "action 必须是 approve 或 reject");
    }
    let conn = db.lock();
    if conn
        .query_row(
            "SELECT id FROM images WHERE id=?1",
            params![image_id],
            |r| r.get::<_, i64>(0),
        )
        .is_err()
    {
        return err(404, "图片不存在");
    }
    let new_status = if b.action == "approve" { "approved" } else { "rejected" };
    conn.execute(
        "UPDATE images SET status=?1,reject_reason=?2 WHERE id=?3",
        params![new_status, b.reason, image_id],
    )
    .unwrap();
    ok(serde_json::json!({ "success": true, "status": new_status }))
}

#[post("/admin/images/batch-review")]
async fn admin_batch_review(
    req: HttpRequest,
    db: Data<Db>,
    body: Json<BatchReviewBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let b = body.into_inner();
    if b.ids.is_empty() {
        return err(400, "ids 不能为空");
    }
    let new_status = if b.action == "approve" { "approved" } else { "rejected" };
    let placeholders = b.ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "UPDATE images SET status=?,reject_reason=? WHERE id IN ({})",
        placeholders
    );
    let conn = db.lock();
    let mut stmt = conn.prepare(&sql).unwrap();
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(new_status.to_string()),
        Box::new(b.reason.clone()),
    ];
    for id in &b.ids {
        params_vec.push(Box::new(*id));
    }
    let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
    stmt.execute(refs.as_slice()).unwrap();
    ok(serde_json::json!({ "success": true, "updated": b.ids.len(), "status": new_status }))
}

#[delete("/admin/images/{id}")]
async fn admin_delete_image(req: HttpRequest, db: Data<Db>, path: Path<i64>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let image_id = path.into_inner();
    let conn = db.lock();
    if conn
        .query_row(
            "SELECT id FROM images WHERE id=?1",
            params![image_id],
            |r| r.get::<_, i64>(0),
        )
        .is_err()
    {
        return err(404, "图片不存在");
    }
    conn.execute("DELETE FROM images WHERE id=?1", params![image_id])
        .unwrap();
    ok(serde_json::json!({ "success": true }))
}

#[get("/admin/users")]
async fn admin_list_users(
    req: HttpRequest,
    db: Data<Db>,
    query: Query<AdminUsersQuery>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);
    let offset = (page - 1) * limit;

    let conn = db.lock();
    let mut sql = "SELECT id,username,email,role,is_banned,created_at,(SELECT COUNT(*) FROM images WHERE user_id=users.id) AS image_count FROM users".to_string();
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(q) = &query.q {
        sql.push_str(" WHERE username LIKE ? OR email LIKE ?");
        let pat = format!("%{}%", q);
        params_vec.push(Box::new(pat.clone()));
        params_vec.push(Box::new(pat));
    }

    let count_sql = if query.q.is_some() {
        format!("SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?")
    } else {
        "SELECT COUNT(*) FROM users".to_string()
    };
    let count_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
    let total: i64 = conn
        .query_row(&count_sql, count_refs.as_slice(), |r| r.get(0))
        .unwrap_or(0);

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
    params_vec.push(Box::new(limit));
    params_vec.push(Box::new(offset));
    let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();

    let users: Vec<serde_json::Value> = conn
        .prepare(&sql)
        .unwrap()
        .query_map(refs.as_slice(), |r| {
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "username": r.get::<_,String>(1)?,
                "email": r.get::<_,Option<String>>(2)?,
                "role": r.get::<_,String>(3)?,
                "is_banned": r.get::<_,i64>(4)?,
                "created_at": r.get::<_,String>(5)?,
                "image_count": r.get::<_,i64>(6)?
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    ok(serde_json::json!({ "success": true, "users": users, "total": total }))
}

#[post("/admin/users/{id}/ban")]
async fn admin_ban_user(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
    body: Json<BanBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let target_id = path.into_inner();
    let conn = db.lock();
    let target = conn.query_row(
        "SELECT id,role FROM users WHERE id=?1",
        params![target_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    );
    match target {
        Err(_) => err(404, "用户不存在"),
        Ok((_, role)) => {
            if role == "admin" {
                return err(400, "不能封禁管理员");
            }
            if target_id == user.user_id {
                return err(400, "不能封禁自己");
            }
            let ban_val = if body.ban { 1i64 } else { 0i64 };
            conn.execute(
                "UPDATE users SET is_banned=?1 WHERE id=?2",
                params![ban_val, target_id],
            )
            .unwrap();
            ok(serde_json::json!({ "success": true, "is_banned": body.ban }))
        }
    }
}

#[post("/admin/users/{id}/role")]
async fn admin_set_role(
    req: HttpRequest,
    db: Data<Db>,
    path: Path<i64>,
    body: Json<RoleBody>,
) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let target_id = path.into_inner();
    let b = body.into_inner();
    if b.role != "user" && b.role != "admin" {
        return err(400, "role 必须是 user 或 admin");
    }
    if target_id == user.user_id {
        return err(400, "不能修改自己的权限");
    }
    let conn = db.lock();
    conn.execute(
        "UPDATE users SET role=?1 WHERE id=?2",
        params![b.role, target_id],
    )
    .unwrap();
    ok(serde_json::json!({ "success": true, "role": b.role }))
}

#[delete("/admin/users/{id}")]
async fn admin_delete_user(req: HttpRequest, db: Data<Db>, path: Path<i64>) -> impl Responder {
    let user = match extract_user(&req) {
        Some(u) => u,
        None => return err(403, "无权限"),
    };
    if !is_admin(&db, user.user_id) {
        return err(403, "无权限");
    }
    let target_id = path.into_inner();
    let conn = db.lock();
    let target = conn.query_row(
        "SELECT id,role FROM users WHERE id=?1",
        params![target_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    );
    match target {
        Err(_) => err(404, "用户不存在"),
        Ok((_, role)) => {
            if role == "admin" {
                return err(400, "不能删除管理员");
            }
            if target_id == user.user_id {
                return err(400, "不能删除自己");
            }
            conn.execute("DELETE FROM users WHERE id=?1", params![target_id])
                .unwrap();
            ok(serde_json::json!({ "success": true }))
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenv::dotenv();
    std::fs::create_dir_all("uploads").unwrap();
    std::fs::create_dir_all("public").unwrap();

    let db = Data::new(Db::new("users.db"));
    init_db(&db);

    println!("🦀 actix-web server running at http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(db.clone())
            .app_data(web::JsonConfig::default().error_handler(|err, _| {
                actix_web::error::InternalError::from_response(
                    err,
                    HttpResponse::BadRequest()
                        .json(serde_json::json!({ "message": "请求体格式错误" })),
                )
                .into()
            }))
            // Static files
            .service(Files::new("/uploads", "uploads"))
            .service(Files::new("/", "public").index_file("index.html"))
            // Auth
            .service(sign_up)
            .service(sign_in)
            .service(sign_out)
            .service(me)
            .service(upload_quota)
            // Images
            .service(upload_image)
            .service(list_images)
            .service(get_image)
            .service(like_image)
            // Collections
            .service(create_collection)
            .service(my_collections)
            .service(user_collections)
            .service(collection_images)
            .service(add_to_collection)
            .service(delete_collection)
            .service(my_collection_status)
            // Follows
            .service(follow_user)
            .service(user_followers)
            .service(user_following)
            // Users / Feed
            .service(get_user)
            .service(user_images)
            .service(feed_following)
            // Admin
            .service(admin_stats)
            .service(admin_list_images)
            .service(admin_review_image)
            .service(admin_batch_review)
            .service(admin_delete_image)
            .service(admin_list_users)
            .service(admin_ban_user)
            .service(admin_set_role)
            .service(admin_delete_user)
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}