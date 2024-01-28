from flask import Flask, request, jsonify, url_for, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from collections import Counter
import hashlib

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Datas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    chosen_committee = db.Column(db.String(100))
    signature = db.Column(db.String(100))
    vote_hash = db.Column(db.String(64))
    public_key = db.Column(db.String(1000), nullable=True)

    def __init__(self, name, password, student_id):
        self.name = name
        self.password = self.hash_password(password)
        self.student_id = student_id

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

def generate_rsa_keypair(student_id):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'{student_id}_private.pem', 'wb') as f:
        f.write(private_key_pem)

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

# ฟังก์ชันตรวจสอบการเปลี่ยนแปลงข้อมูลโหวต
def check_vote_changes():

    all_voters = Voter.query.all()
    changed_votes = []

    # ตรวจสอบการเปลี่ยนแปลงข้อมูลโหวต
    for voter in all_voters:
        if voter.chosen_committee is not None:  # ตรวจสอบว่า chosen_committee ไม่ใช่ None ก่อนที่จะดำเนินการ
            vote_data = voter.student_id + voter.chosen_committee
            vote_hash = hashlib.sha512(vote_data.encode()).hexdigest()
            if voter.vote_hash != vote_hash:
                changed_votes.append({
                    'student_id': voter.student_id
                })
        
    return changed_votes

#นับผลโหวต
def count_committee_votes(all_votes):
    chosen_committees = [vote['chosen_committee'] for vote in all_votes if vote['chosen_committee']]

    committee_vote_counts = Counter(chosen_committees)

    return committee_vote_counts


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']

        voter = Voter.query.filter_by(name=name, password=password).first()
        if voter:
            session['name'] = voter.name
            return redirect(url_for('vote'))
        else:
            return jsonify({'message': 'Invalid username or password'})

    return render_template('login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'name' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # เรียกใช้ฟังก์ชัน check_vote_changes() เพื่อตรวจสอบการเปลี่ยนแปลงข้อมูลโหวต
        changed_votes = check_vote_changes()

        data = request.form
        student_id = data['student_id']
        chosen_committee = data['chosen_committee']
        private_key_value = data['private_key']

        private_key = serialization.load_pem_private_key( 
            private_key_value.encode(),
            password=None
        )

        message = student_id.encode() + chosen_committee.encode()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        hex_signature = signature.hex()

        voter = Voter.query.filter_by(student_id=student_id).first()
        if voter:
            voter.chosen_committee = chosen_committee
            voter.signature = hex_signature

            try:
                public_key = serialization.load_pem_public_key(
                    voter.public_key.encode('utf-8')
                )
                public_key.verify(
                    bytes.fromhex(voter.signature),
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA512()
                )
            except InvalidSignature:
                return jsonify({'message': 'Invalid signature'})

            vote_data = student_id + chosen_committee
            vote_hash = hashlib.sha512(vote_data.encode()).hexdigest()

            previous_vote_hash = voter.vote_hash
            if previous_vote_hash:
                vote_data += previous_vote_hash
            voter.vote_hash = hashlib.sha512(vote_data.encode()).hexdigest()

            db.session.commit()

            # นับจำนวนคนที่โหวตแล้วโดยอ้างอิงจาก chosen_committee
            total_voters = Voter.query.filter(Voter.chosen_committee != None).count()

            # เรียกฟังก์ชัน check_all_votes() เพื่อตรวจสอบว่าโหวตครบทั้ง 10 คนหรือไม่
            if total_voters == 10:
                all_votes = check_all_votes()
                return render_template('all_votes.html', all_votes=all_votes, changed_votes=changed_votes)  # ส่งข้อมูล changed_votes ไปยังเทมเพลต
            else:
                return jsonify({
                    'message': f'Vote updated successfully. Total voters: {total_voters}.',
                    'vote_hash': voter.vote_hash
                })
        else:
            return jsonify({'message': 'Invalid voter'})

    return render_template('vote.html')


def check_all_votes():

    all_voters = Voter.query.all()
    all_votes = []

    #ผลโหวตทั้งหมด
    for voter in all_voters:
        vote_info = {
            'student_id': voter.student_id,
            'chosen_committee': voter.chosen_committee
        }
        all_votes.append(vote_info)

    # นับจำนวนโหวตของแต่ละกรรมการ
    committee_vote_counts = count_committee_votes(all_votes)

    # เรียกใช้ฟังก์ชัน check_vote_changes() เพื่อตรวจสอบการเปลี่ยนแปลงข้อมูลโหวต
    changed_votes = check_vote_changes()

    return all_votes, committee_vote_counts, changed_votes


@app.route('/all_votes')
def all_votes():
    if 'name' not in session:
        return redirect(url_for('login'))

    # เรียกฟังก์ชัน check_all_votes() เพื่อดึงข้อมูลการโหวตทั้งหมดและนับจำนวนโหวตของแต่ละกรรมการ
    all_votes, committee_vote_counts, changed_votes = check_all_votes()

    # หากรรมการที่มีโหวตมากที่สุด
    most_voted_committee = max(committee_vote_counts, key=committee_vote_counts.get)

    return render_template('all_votes.html', all_votes=all_votes, committee_vote_counts=committee_vote_counts, most_voted_committee=most_voted_committee, changed_votes=changed_votes)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        for i in range(1, 11):
            student_id = f'B640000{i}'
            existing_voter = Voter.query.filter_by(student_id=student_id).first()
            if not existing_voter:
                new_voter = Voter(name=f'Voter {i}', password=f'password{i}', student_id=student_id)
                db.session.add(new_voter)
                public_key = generate_rsa_keypair(student_id)
                new_voter.public_key = public_key.decode('utf-8')
        db.session.commit()

    app.run(debug=True)