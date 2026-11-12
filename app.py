import os, json, secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO
from config import Config
from services import seal_upload, decrypt_parts, verify_evidence

app = Flask(__name__)
app.config.from_object(Config)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
Path(app.instance_path).mkdir(parents=True, exist_ok=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

def now():
    return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="submitter")
    active = db.Column(db.Boolean, default=True)
    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)

class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    storage_id = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, default="")
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    submitter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    threshold = db.Column(db.Integer, nullable=False, default=2)
    reviewer_ids = db.Column(db.Text, nullable=False, default="[]")
    part_hashes_json = db.Column(db.Text, nullable=False)
    merkle_root = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(30), default="under_review")
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    released_at = db.Column(db.DateTime(timezone=True))
    @property
    def part_hashes(self): return json.loads(self.part_hashes_json)
    @property
    def reviewers(self): return json.loads(self.reviewer_ids)

class Approval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    decision = db.Column(db.String(20), nullable=False)
    comment = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    __table_args__ = (db.UniqueConstraint("evidence_id", "reviewer_id"),)

class Dispute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="open")
    resolution = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"))
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now)

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

def audit(eid, action, details=""):
    db.session.add(Audit(evidence_id=eid, actor_id=current_user.id if current_user.is_authenticated else None,
                         action=action, details=details))

def get_evidence(eid):
    item = db.session.get(Evidence, eid)
    if not item: abort(404)
    return item

def can_view(item):
    return current_user.role == "admin" or current_user.id == item.submitter_id or current_user.id in item.reviewers

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if current_user.role != "admin": abort(403)
        return fn(*a, **kw)
    return wrapper

def evaluate_release(item):
    approvals = Approval.query.filter_by(evidence_id=item.id, decision="approve").count()
    open_disputes = Dispute.query.filter_by(evidence_id=item.id, status="open").count()
    if open_disputes:
        item.status = "challenged"
    elif approvals >= item.threshold:
        item.status = "released"
        item.released_at = now()
    else:
        item.status = "under_review"

@app.route("/")
def index():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, password = request.form["name"].strip(), request.form["email"].lower().strip(), request.form["password"]
        if len(password) < 8: flash("Password must be at least 8 characters.", "danger")
        elif User.query.filter_by(email=email).first(): flash("Email already registered.", "danger")
        else:
            user = User(name=name, email=email, role="submitter"); user.set_password(password)
            db.session.add(user); db.session.commit()
            login_user(user); flash("Account created. You can now submit evidence.", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"].lower().strip()).first()
        if user and user.active and user.check_password(request.form["password"]):
            login_user(user); return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        items = Evidence.query.order_by(Evidence.created_at.desc()).all()
    else:
        items = Evidence.query.filter(
            (Evidence.submitter_id == current_user.id) |
            (Evidence.reviewer_ids.like(f'%{current_user.id}%'))
        ).order_by(Evidence.created_at.desc()).all()
        items = [x for x in items if can_view(x)]
    pending = sum(1 for x in items if x.status in ("under_review", "challenged"))
    released = sum(1 for x in items if x.status == "released")
    return render_template("dashboard.html", items=items, pending=pending, released=released)

@app.route("/evidence/new", methods=["GET", "POST"])
@login_required
def new_evidence():
    reviewers = User.query.filter(User.role == "reviewer", User.active.is_(True)).all()
    if request.method == "POST":
        upload = request.files.get("file")
        chosen = [int(x) for x in request.form.getlist("reviewers") if x.isdigit()]
        valid_ids = {u.id for u in reviewers}
        chosen = list(dict.fromkeys(x for x in chosen if x in valid_ids))
        try: threshold = int(request.form.get("threshold", "1"))
        except ValueError: threshold = 0
        if not upload or not upload.filename: flash("Choose a file.", "danger")
        elif not chosen or threshold < 1 or threshold > len(chosen): flash("Select reviewers and a valid approval threshold.", "danger")
        else:
            try:
                storage_id, size, hashes, root, _ = seal_upload(upload, app.config["UPLOAD_FOLDER"], app.config["EVIDENCE_MASTER_KEY"])
                item = Evidence(storage_id=storage_id, title=request.form["title"].strip(),
                    description=request.form.get("description","").strip(),
                    original_filename=secure_filename(upload.filename), file_size=size,
                    submitter_id=current_user.id, threshold=threshold,
                    reviewer_ids=json.dumps(chosen), part_hashes_json=json.dumps(hashes), merkle_root=root)
                db.session.add(item); db.session.flush()
                audit(item.id, "EVIDENCE_SEALED", f"parts={len(hashes)}; merkle_root={root}")
                db.session.commit(); flash("Evidence encrypted and submitted.", "success")
                return redirect(url_for("evidence_detail", eid=item.id))
            except Exception as exc:
                db.session.rollback(); flash(f"Upload failed: {exc}", "danger")
    return render_template("upload.html", reviewers=reviewers)

@app.route("/evidence/<int:eid>")
@login_required
def evidence_detail(eid):
    item = get_evidence(eid)
    if not can_view(item): abort(403)
    approvals = Approval.query.filter_by(evidence_id=eid).order_by(Approval.created_at.desc()).all()
    reviewer_map = {u.id:u for u in User.query.filter(User.id.in_(item.reviewers)).all()} if item.reviewers else {}
    disputes = Dispute.query.filter_by(evidence_id=eid).order_by(Dispute.created_at.desc()).all()
    audit_rows = Audit.query.filter_by(evidence_id=eid).order_by(Audit.created_at.desc()).all()
    my_approval = Approval.query.filter_by(evidence_id=eid, reviewer_id=current_user.id).first()
    return render_template("evidence_detail.html", item=item, approvals=approvals, reviewer_map=reviewer_map,
                           disputes=disputes, audit_rows=audit_rows, my_approval=my_approval)

@app.route("/evidence/<int:eid>/review", methods=["POST"])
@login_required
def review(eid):
    item = get_evidence(eid)
    if current_user.id not in item.reviewers or current_user.role not in ("reviewer", "admin"): abort(403)
    if item.status == "released" or item.status == "challenged": flash("This evidence is not currently accepting approvals.", "warning")
    elif Approval.query.filter_by(evidence_id=eid, reviewer_id=current_user.id).first():
        flash("You have already submitted a decision.", "warning")
    else:
        decision = request.form.get("decision")
        if decision not in ("approve", "reject"): abort(400)
        db.session.add(Approval(evidence_id=eid, reviewer_id=current_user.id, decision=decision,
                                comment=request.form.get("comment","").strip()))
        audit(eid, "REVIEW_" + decision.upper(), request.form.get("comment","").strip())
        db.session.flush(); evaluate_release(item); db.session.commit()
        flash("Your decision has been recorded.", "success")
    return redirect(url_for("evidence_detail", eid=eid))

@app.route("/evidence/<int:eid>/dispute", methods=["POST"])
@login_required
def dispute(eid):
    item = get_evidence(eid)
    if not can_view(item): abort(403)
    reason = request.form.get("reason","").strip()
    if len(reason) < 10: flash("Please provide a more detailed challenge reason.", "danger")
    else:
        db.session.add(Dispute(evidence_id=eid, user_id=current_user.id, reason=reason))
        item.status = "challenged"; audit(eid, "DISPUTE_OPENED", reason); db.session.commit()
        flash("Challenge submitted. Release is suspended.", "success")
    return redirect(url_for("evidence_detail", eid=eid))

@app.route("/admin/disputes")
@admin_required
def admin_disputes():
    disputes = Dispute.query.order_by(Dispute.created_at.desc()).all()
    return render_template("admin_disputes.html", disputes=disputes)

@app.route("/admin/disputes/<int:did>/resolve", methods=["POST"])
@admin_required
def resolve_dispute(did):
    dispute = db.session.get(Dispute, did)
    if not dispute: abort(404)
    dispute.status = request.form.get("status")
    dispute.resolution = request.form.get("resolution","").strip()
    if dispute.status not in ("resolved", "dismissed") or len(dispute.resolution) < 5: abort(400)
    item = get_evidence(dispute.evidence_id)
    audit(item.id, "DISPUTE_" + dispute.status.upper(), dispute.resolution)
    db.session.flush()
    evaluate_release(item)
    db.session.commit()
    flash("Dispute updated.", "success")
    return redirect(url_for("admin_disputes"))

@app.route("/evidence/<int:eid>/verify")
@login_required
def verify(eid):
    item = get_evidence(eid)
    if not can_view(item): abort(403)
    valid = verify_evidence(item, app.config["UPLOAD_FOLDER"], app.config["EVIDENCE_MASTER_KEY"])
    audit(eid, "INTEGRITY_CHECK", "passed" if valid else "failed"); db.session.commit()
    flash("Integrity verified: all parts match." if valid else "Integrity verification FAILED.", "success" if valid else "danger")
    return redirect(url_for("evidence_detail", eid=eid))

@app.route("/evidence/<int:eid>/download")
@login_required
def download(eid):
    item = get_evidence(eid)
    if not can_view(item): abort(403)
    if item.status != "released" and current_user.role != "admin":
        abort(403, "Evidence is sealed until the approval threshold is reached and disputes are resolved.")
    try:
        content = b"".join(decrypt_parts(item, app.config["UPLOAD_FOLDER"], app.config["EVIDENCE_MASTER_KEY"]))
    except Exception:
        abort(500, "Decryption or integrity verification failed.")
    audit(eid, "EVIDENCE_DOWNLOADED", current_user.email); db.session.commit()
    return send_file(BytesIO(content), as_attachment=True, download_name=item.original_filename)

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        user = db.session.get(User, int(request.form["user_id"]))
        role = request.form.get("role")
        if user and role in ("submitter", "reviewer", "admin"):
            user.role = role; db.session.commit(); flash("User role updated.", "success")
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)

@app.errorhandler(413)
def too_large(e): return "Upload too large. Increase MAX_CONTENT_LENGTH_MB in .env.", 413

with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@tmerp.local").first():
        admin = User(name="System Admin", email="admin@tmerp.local", role="admin")
        admin.set_password("Admin@12345"); db.session.add(admin); db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
