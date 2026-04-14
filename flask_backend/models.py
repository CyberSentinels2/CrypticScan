from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(100), unique=True, nullable=False)
    tool = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='running')
    results = db.Column(db.Text, nullable=True)
    report_path = db.Column(db.String(500), nullable=True)
