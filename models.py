from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.String(100), nullable=False)
    creator_username = db.Column(db.String(100))
    
    # 访问控制
    is_public = db.Column(db.Boolean, default=True)
    min_trust_level = db.Column(db.Integer, default=0)
    allowed_users = db.Column(db.Text)
    
    # 卡密分发设置
    is_card_distribution = db.Column(db.Boolean, default=False)
    allow_repeat = db.Column(db.Boolean, default=False)

class CardDistribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paste_id = db.Column(db.Integer, db.ForeignKey('paste.id'), nullable=False)
    user_id = db.Column(db.String(100), nullable=False)
    card_line = db.Column(db.Integer, nullable=False)  # 分配的行号
    created_at = db.Column(db.DateTime, default=datetime.utcnow)