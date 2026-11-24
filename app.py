import os, sqlite3, secrets, time, hmac, hashlib, re, math
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.environ.get("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "campusvault.db"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
IS_PRODUCTION = os.environ.get("FLASK_ENV", "development").lower() == "production"
secret = os.environ.get("SECRET_KEY")
if IS_PRODUCTION and not secret:
    raise RuntimeError("SECRET_KEY must be set for production. Generate a long random value and set it in your environment.")
app.secret_key = secret or "dev-only-change-me-" + secrets.token_hex(24)
app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    UPLOAD_FOLDER=UPLOAD_DIR,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "png", "jpg", "jpeg"}
LOGIN_MAX_ATTEMPTS = 8
LOGIN_WINDOW_SECONDS = 15 * 60

# Simple database-backed login throttle. For a multi-instance deployment, use a
# dedicated rate-limit service (e.g. Redis) and configure trusted proxy handling.
def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="Invalid or expired form token. Please reload the page and try again.")

STOP_WORDS = set("a an the and or but if while with without of to in on at by for from as is are was were be been being this that these those it its their his her you your we they them he she i not no do does did can could should will would may might about into over under after before between more most some any all each other such than then also very have has had use used using make made get got show shown example examples figure table chapter section lecture notes questions question answer answers important key topic topics concept concepts".split())

def extract_pdf_text(path):
    try:
        import fitz
    except ImportError:
        raise RuntimeError("PDF analysis dependency missing. Install requirements.txt (PyMuPDF).")
    doc=fitz.open(path)
    if doc.is_encrypted:
        raise ValueError("Encrypted PDFs are not supported.")
    text="\n".join(page.get_text("text") for page in doc[:80])
    return text[:180000]

def simple_nlp(text):
    words=re.findall(r"[A-Za-z][A-Za-z'-]{2,}", text.lower())
    freq={}
    for w in words:
        if w not in STOP_WORDS:
            freq[w]=freq.get(w,0)+1
    keywords=sorted(freq.items(),key=lambda x:(-x[1],x[0]))[:12]
    sentences=[re.sub(r"\s+"," ",s).strip() for s in re.split(r"(?<=[.!?])\s+|\n+",text) if len(s.strip())>45]
    # Score sentence importance using keyword density and length, then preserve source order.
    scores=[]
    for i,s in enumerate(sentences):
        sw=re.findall(r"[A-Za-z][A-Za-z'-]{2,}",s.lower())
        score=sum(freq.get(w,0) for w in sw if w not in STOP_WORDS)/(len(sw)+1)
        scores.append((score,i,s))
    summary=[x[2] for x in sorted(sorted(scores,key=lambda x:-x[0])[:5],key=lambda x:x[1])]
    quiz=[]
    for sentence in sentences:
        terms=[w for w in re.findall(r"[A-Za-z][A-Za-z'-]{3,}",sentence) if w.lower() not in STOP_WORDS and freq.get(w.lower(),0)>=2]
        if terms:
            answer=max(terms,key=lambda w:freq.get(w.lower(),0))
            question=re.sub(r"\b"+re.escape(answer)+r"\b", "________", sentence, count=1, flags=re.I)
            if question!=sentence:
                quiz.append({"question":question,"answer":answer})
        if len(quiz)>=5: break
    return keywords,summary,quiz

def allowed_file(name):
    return bool(name and "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)

def valid_upload_signature(path, ext):
    """Basic signature checks for common formats; not a full malware scanner."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if ext == "pdf": return head.startswith(b"%PDF-")
        if ext in {"jpg", "jpeg"}: return head.startswith(b"\xff\xd8\xff")
        if ext == "png": return head.startswith(b"\x89PNG\r\n\x1a\n")
        if ext in {"docx", "pptx"}: return head.startswith(b"PK\x03\x04")
        # Legacy Office formats are OLE compound files.
        if ext in {"doc", "ppt"}: return head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        return False
    except OSError:
        return False

def safe_next_url(target):
    if not target: return None
    from urllib.parse import urlparse
    parsed=urlparse(target)
    # Only allow relative local paths; reject protocol-relative and external URLs.
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, branch TEXT, semester TEXT, role TEXT NOT NULL DEFAULT 'student', status TEXT NOT NULL DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS resources(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, subject TEXT NOT NULL,
          subject_code TEXT, branch TEXT, semester TEXT, category TEXT NOT NULL, academic_year TEXT,
          description TEXT, filename TEXT NOT NULL, original_filename TEXT, user_id INTEGER NOT NULL,
          downloads INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS bookmarks(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL,
          UNIQUE(user_id, resource_id), FOREIGN KEY(user_id) REFERENCES users(id),
          FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS ratings(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL,
          rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), UNIQUE(user_id, resource_id),
          FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS comments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL,
          comment TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS reports(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, resource_id INTEGER NOT NULL,
          reason TEXT NOT NULL, status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS login_attempts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, identity TEXT NOT NULL, attempted_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_identity_time ON login_attempts(identity, attempted_at);
        """)
        # Upgrade older CampusVault databases without deleting user data.
        columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        if "role" not in columns:
            con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        if "status" not in columns:
            con.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        if admin_email:
            con.execute("UPDATE users SET role='admin' WHERE email=?", (admin_email,))
init_db()

def logged_in():
    return bool(session.get("user_id"))

def admin_required(f):
    @wraps(f)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapped

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not logged_in():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        user = current_user()
        if not user or user["status"] != "active":
            session.clear()
            flash("This account is disabled. Contact the administrator.", "danger")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    if not session.get("user_id"): return None
    with db() as con:
        return con.execute("SELECT id,name,email,branch,semester,role,status FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    branch = request.args.get("branch", "")
    semester = request.args.get("semester", "")
    category = request.args.get("category", "")
    with db() as con:
        where, params = [], []
        if q:
            where.append("(r.title LIKE ? OR r.subject LIKE ? OR r.subject_code LIKE ? OR r.description LIKE ?)")
            params.extend([f"%{q}%"]*4)
        if branch: where.append("r.branch=?"); params.append(branch)
        if semester: where.append("r.semester=?"); params.append(semester)
        if category: where.append("r.category=?"); params.append(category)
        clause = " WHERE " + " AND ".join(where) if where else ""
        resources = con.execute(f"""SELECT r.*,u.name uploader,
        COALESCE((SELECT ROUND(AVG(rating),1) FROM ratings x WHERE x.resource_id=r.id),0) avg_rating,
        (SELECT COUNT(*) FROM ratings x WHERE x.resource_id=r.id) rating_count
        FROM resources r JOIN users u ON u.id=r.user_id {clause}
        ORDER BY r.created_at DESC LIMIT 60""", params).fetchall()
        stats = {
          "resources": con.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
          "students": con.execute("SELECT COUNT(*) FROM users").fetchone()[0],
          "downloads": con.execute("SELECT COALESCE(SUM(downloads),0) FROM resources").fetchone()[0]
        }
    return render_template("index.html", resources=resources, stats=stats, q=q, branch=branch, semester=semester, category=category)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        branch=request.form.get("branch","")
        semester=request.form.get("semester","")
        if not name or len(name) > 80 or not email or len(email) > 254 or "@" not in email or len(password)<8:
            flash("Enter a valid name/email and a password of at least 8 characters.", "danger")
            return render_template("auth.html", mode="register")
        try:
            with db() as con:
                cur=con.execute("INSERT INTO users(name,email,password,branch,semester) VALUES(?,?,?,?,?)",
                  (name,email,generate_password_hash(password),branch,semester))
                session.clear()
                session["user_id"]=cur.lastrowid
                csrf_token()
            flash("Account created! Welcome to CampusVault.", "success")
            return redirect(url_for("index"))
        except sqlite3.IntegrityError:
            flash("This email is already registered.", "danger")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email"," ").strip().lower()
        password=request.form.get("password","")
        identity=hashlib.sha256(((request.remote_addr or "unknown") + "|" + email).encode()).hexdigest()
        now=int(time.time())
        with db() as con:
            con.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now-LOGIN_WINDOW_SECONDS,))
            attempts=con.execute("SELECT COUNT(*) FROM login_attempts WHERE identity=? AND attempted_at>=?",(identity,now-LOGIN_WINDOW_SECONDS)).fetchone()[0]
            user=con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if attempts >= LOGIN_MAX_ATTEMPTS:
            flash("Too many login attempts. Please wait 15 minutes before trying again.", "danger")
            return render_template("auth.html", mode="login"), 429
        if user and user["status"] == "active" and check_password_hash(user["password"],password):
            with db() as con: con.execute("DELETE FROM login_attempts WHERE identity=?",(identity,))
            session.clear(); session["user_id"]=user["id"]; csrf_token()
            flash("Logged in successfully.", "success")
            return redirect(safe_next_url(request.args.get("next")) or url_for("index"))
        with db() as con: con.execute("INSERT INTO login_attempts(identity,attempted_at) VALUES(?,?)",(identity,now))
        flash("Incorrect email or password, or this account is disabled.", "danger")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    if request.method=="POST":
        file=request.files.get("file")
        title=request.form.get("title","").strip()
        subject=request.form.get("subject","").strip()
        category=request.form.get("category","")
        if not file or not file.filename or not title or not subject or not category or len(title)>160 or len(subject)>120:
            flash("Please complete required fields. Title must be 160 characters or less and subject 120 or less.", "danger")
            return render_template("upload.html")
        if not allowed_file(file.filename):
            flash("Unsupported file. Upload PDF, Word, PowerPoint or image files.", "danger")
            return render_template("upload.html")
        original=secure_filename(file.filename)
        if not original or len(original) > 180:
            flash("Invalid filename. Please rename the file and upload again.", "danger")
            return render_template("upload.html")
        ext=original.rsplit(".",1)[1].lower()
        stored=f"{secrets.token_hex(16)}.{ext}"
        save_path=os.path.join(UPLOAD_DIR,stored)
        file.save(save_path)
        if not valid_upload_signature(save_path, ext):
            try: os.remove(save_path)
            except OSError: pass
            flash("The file content does not match its extension or is unsupported. Please upload a valid file.", "danger")
            return render_template("upload.html")
        with db() as con:
            con.execute("""INSERT INTO resources(title,subject,subject_code,branch,semester,category,academic_year,
                description,filename,original_filename,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (title,subject,request.form.get("subject_code",""),request.form.get("branch",""),
                 request.form.get("semester",""),category,request.form.get("academic_year",""),
                 request.form.get("description",""),stored,original,session["user_id"]))
        flash("Resource uploaded successfully. Thanks for sharing!", "success")
        return redirect(url_for("index"))
    return render_template("upload.html")

@app.route("/resource/<int:resource_id>")
def resource_detail(resource_id):
    with db() as con:
        r=con.execute("""SELECT r.*,u.name uploader,
          COALESCE((SELECT ROUND(AVG(rating),1) FROM ratings x WHERE x.resource_id=r.id),0) avg_rating,
          (SELECT COUNT(*) FROM ratings x WHERE x.resource_id=r.id) rating_count
          FROM resources r JOIN users u ON u.id=r.user_id WHERE r.id=?""",(resource_id,)).fetchone()
        if not r: abort(404)
        comments=con.execute("""SELECT c.*,u.name FROM comments c JOIN users u ON u.id=c.user_id
          WHERE c.resource_id=? ORDER BY c.created_at DESC""",(resource_id,)).fetchall()
        bookmarked=False; my_rating=0
        if logged_in():
            bookmarked=bool(con.execute("SELECT 1 FROM bookmarks WHERE user_id=? AND resource_id=?",(session["user_id"],resource_id)).fetchone())
            row=con.execute("SELECT rating FROM ratings WHERE user_id=? AND resource_id=?",(session["user_id"],resource_id)).fetchone()
            my_rating=row["rating"] if row else 0
    return render_template("detail.html", resource=r, comments=comments, bookmarked=bookmarked, my_rating=my_rating)

@app.route("/download/<int:resource_id>")
def download(resource_id):
    with db() as con:
        r=con.execute("SELECT filename,original_filename FROM resources WHERE id=?",(resource_id,)).fetchone()
        if not r: abort(404)
        con.execute("UPDATE resources SET downloads=downloads+1 WHERE id=?",(resource_id,))
    return send_from_directory(UPLOAD_DIR,r["filename"],as_attachment=True,download_name=r["original_filename"])

@app.route("/bookmark/<int:resource_id>", methods=["POST"])
@login_required
def bookmark(resource_id):
    with db() as con:
        if not con.execute("SELECT 1 FROM resources WHERE id=?", (resource_id,)).fetchone(): abort(404)
        exists=con.execute("SELECT 1 FROM bookmarks WHERE user_id=? AND resource_id=?",(session["user_id"],resource_id)).fetchone()
        if exists: con.execute("DELETE FROM bookmarks WHERE user_id=? AND resource_id=?",(session["user_id"],resource_id))
        else: con.execute("INSERT OR IGNORE INTO bookmarks(user_id,resource_id) VALUES(?,?)",(session["user_id"],resource_id))
    return redirect(request.referrer or url_for("index"))

@app.route("/rate/<int:resource_id>", methods=["POST"])
@login_required
def rate(resource_id):
    try: rating=int(request.form.get("rating", ""))
    except (TypeError, ValueError): abort(400, description="Rating must be an integer from 1 to 5.")
    if rating not in range(1, 6): abort(400, description="Rating must be an integer from 1 to 5.")
    with db() as con:
        if not con.execute("SELECT 1 FROM resources WHERE id=?", (resource_id,)).fetchone(): abort(404)
        con.execute("INSERT INTO ratings(user_id,resource_id,rating) VALUES(?,?,?) ON CONFLICT(user_id,resource_id) DO UPDATE SET rating=excluded.rating",
          (session["user_id"],resource_id,rating))
    flash("Your rating was saved.", "success")
    return redirect(url_for("resource_detail",resource_id=resource_id))

@app.route("/comment/<int:resource_id>", methods=["POST"])
@login_required
def comment(resource_id):
    value=request.form.get("comment","").strip()
    if len(value) > 1500: abort(400, description="Comment must be 1500 characters or fewer.")
    with db() as con:
        if not con.execute("SELECT 1 FROM resources WHERE id=?", (resource_id,)).fetchone(): abort(404)
        if value:
            con.execute("INSERT INTO comments(user_id,resource_id,comment) VALUES(?,?,?)",(session["user_id"],resource_id,value))
    return redirect(url_for("resource_detail",resource_id=resource_id))

@app.route("/report/<int:resource_id>", methods=["POST"])
@login_required
def report(resource_id):
    reason=request.form.get("reason","").strip() or "Reported content"
    with db() as con:
        con.execute("INSERT INTO reports(user_id,resource_id,reason) VALUES(?,?,?)",(session["user_id"],resource_id,reason[:500]))
    flash("Thanks. Your report was submitted for review.", "success")
    return redirect(url_for("resource_detail",resource_id=resource_id))

@app.route("/study-tools/<int:resource_id>")
@login_required
def study_tools(resource_id):
    with db() as con:
        resource=con.execute("SELECT id,title,filename,original_filename FROM resources WHERE id=?",(resource_id,)).fetchone()
    if not resource: abort(404)
    if not resource["filename"].lower().endswith(".pdf"):
        flash("Study tools currently support PDF files only.","warning")
        return redirect(url_for("resource_detail",resource_id=resource_id))
    path=os.path.join(UPLOAD_DIR,resource["filename"])
    if not os.path.isfile(path): abort(404)
    try:
        text=extract_pdf_text(path)
        if len(text.strip())<80:
            flash("Could not extract enough text. This may be a scanned PDF; OCR is not supported yet.","warning")
            return render_template("study_tools.html",resource=resource,keywords=[],summary=[],quiz=[],chars=len(text))
        keywords,summary,quiz=simple_nlp(text)
    except (ValueError,RuntimeError) as exc:
        flash(str(exc),"danger")
        return redirect(url_for("resource_detail",resource_id=resource_id))
    return render_template("study_tools.html",resource=resource,keywords=keywords,summary=summary,quiz=quiz,chars=len(text))

@app.route("/bookmarks")
@login_required
def bookmarks():
    with db() as con:
        resources=con.execute("""SELECT r.*,u.name uploader,
          COALESCE((SELECT ROUND(AVG(rating),1) FROM ratings x WHERE x.resource_id=r.id),0) avg_rating,
          (SELECT COUNT(*) FROM ratings x WHERE x.resource_id=r.id) rating_count
          FROM bookmarks b JOIN resources r ON r.id=b.resource_id JOIN users u ON u.id=r.user_id
          WHERE b.user_id=? ORDER BY b.id DESC""",(session["user_id"],)).fetchall()
    return render_template("list.html",resources=resources,page_title="My Bookmarks",empty_message="No bookmarks yet. Save resources you want to revisit.")

@app.route("/my-uploads")
@login_required
def my_uploads():
    with db() as con:
        resources=con.execute("""SELECT r.*,u.name uploader,
          COALESCE((SELECT ROUND(AVG(rating),1) FROM ratings x WHERE x.resource_id=r.id),0) avg_rating,
          (SELECT COUNT(*) FROM ratings x WHERE x.resource_id=r.id) rating_count
          FROM resources r JOIN users u ON u.id=r.user_id WHERE r.user_id=? ORDER BY r.created_at DESC""",(session["user_id"],)).fetchall()
    return render_template("list.html",resources=resources,page_title="My Uploads",empty_message="You have not uploaded anything yet.")

@app.route("/delete/<int:resource_id>", methods=["POST"])
@login_required
def delete_resource(resource_id):
    with db() as con:
        r=con.execute("SELECT * FROM resources WHERE id=? AND user_id=?",(resource_id,session["user_id"])).fetchone()
        if not r: abort(403)
        con.execute("DELETE FROM resources WHERE id=?",(resource_id,))
    try: os.remove(os.path.join(UPLOAD_DIR,r["filename"]))
    except OSError: pass
    flash("Your resource was deleted.", "info")
    return redirect(url_for("my_uploads"))


# Admin moderation and user management (role is stored in the users table).
@app.route("/admin")
@admin_required
def admin_dashboard():
    with db() as con:
        stats = {
            "users": con.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "active_users": con.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
            "resources": con.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
            "pending_reports": con.execute("SELECT COUNT(*) FROM reports WHERE status='pending'").fetchone()[0],
        }
        reports = con.execute("""SELECT p.*,r.title resource_title,r.filename,u.name reporter
            FROM reports p JOIN resources r ON r.id=p.resource_id JOIN users u ON u.id=p.user_id
            ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END, p.created_at DESC LIMIT 100""").fetchall()
        users = con.execute("SELECT id,name,email,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 100").fetchall()
    return render_template("admin.html", stats=stats, reports=reports, users=users)

@app.route("/admin/report/<int:report_id>/review", methods=["POST"])
@admin_required
def admin_review_report(report_id):
    action = request.form.get("action")
    if action not in {"dismiss", "remove"}: abort(400)
    with db() as con:
        report = con.execute("SELECT resource_id FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report: abort(404)
        if action == "remove":
            resource = con.execute("SELECT filename FROM resources WHERE id=?", (report["resource_id"],)).fetchone()
            con.execute("DELETE FROM resources WHERE id=?", (report["resource_id"],))
            con.execute("UPDATE reports SET status='removed' WHERE resource_id=?", (report["resource_id"],))
        else:
            con.execute("UPDATE reports SET status='dismissed' WHERE id=?", (report_id,))
            resource = None
    if action == "remove" and resource:
        try: os.remove(os.path.join(UPLOAD_DIR, resource["filename"]))
        except OSError: pass
    flash("Reported resource removed." if action == "remove" else "Report dismissed.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/user/<int:user_id>/status", methods=["POST"])
@admin_required
def admin_toggle_user_status(user_id):
    if user_id == session["user_id"]: abort(400, description="You cannot disable your own account.")
    with db() as con:
        user = con.execute("SELECT status FROM users WHERE id=?", (user_id,)).fetchone()
        if not user: abort(404)
        new_status = "disabled" if user["status"] == "active" else "active"
        if new_status == "disabled":
            target = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
            active_admins = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]
            if target["role"] == "admin" and active_admins <= 1:
                abort(400, description="Cannot disable the last active administrator.")
        con.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
    flash(f"User account {new_status}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_toggle_user_role(user_id):
    if user_id == session["user_id"]: abort(400, description="You cannot change your own role.")
    with db() as con:
        user = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not user: abort(404)
        role = "student" if user["role"] == "admin" else "admin"
        if role == "student":
            active_admins = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]
            if active_admins <= 1:
                abort(400, description="Cannot demote the last active administrator.")
        con.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    flash(f"User role changed to {role}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum upload size is 20 MB.", "danger")
    return redirect(url_for("upload"))

if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)
