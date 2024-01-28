from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    selected_committee = db.Column(db.String(50), nullable=False)
    signature = db.Column(db.String(255), nullable=False)

class ElectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.Integer, nullable=False)
    hash_value = db.Column(db.String(255), nullable=False)
