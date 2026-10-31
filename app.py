import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from nltk.sentiment.vader import SentimentIntensityAnalyzer
import nltk
import pandas as pd
from collections import Counter
from PIL import Image
from googletrans import Translator

try:
    from transformers import pipeline
except Exception:
    pipeline = None

try:
    from googletrans import Translator
except Exception:
   Translator = None

os.environ["TRANSFORMERS_NO_TF"] = "1"  
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"


EMOJI_CSV = "emoji_df.csv"
if os.path.exists(EMOJI_CSV):
    emoji_df = pd.read_csv(EMOJI_CSV)
    emoji_dict = dict(zip(emoji_df["emoji"].astype(str), emoji_df["label"].astype(str)))
else:
    print("Warning: emoji_df.csv not found, emoji detection disabled.")
    emoji_dict = {}

try:
    nltk.data.find('sentiment/vader_lexicon.zip')
except Exception:
    nltk.download('vader_lexicon')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "replace-this-with-a-secure-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emotisense.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
sia = SentimentIntensityAnalyzer()

nsfw_pipeline = None
url_pipeline = None

if pipeline is None:
    print("transformers.pipeline not available — skipping NSFW and URL model loading.")
else:
    
    try:
        print("⚡ Loading NSFW detection model... (optional; may take time)")
        nsfw_pipeline = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
    except Exception as e:
        print("Could not load NSFW pipeline:", e)
        nsfw_pipeline = None
    try:
        print("⚡ Loading URL/malicious-link detection model... (optional)")
        url_pipeline = pipeline("text-classification", model="kmack/malicious-url-detection")
    except Exception as e:
        print("Could not load URL pipeline:", e)
        url_pipeline = None

translator = None
if Translator is None:
    print("googletrans not installed — translation disabled. Install googletrans==4.0.0-rc1 for translation.")
else:
    try:
        translator = Translator()
        
        _ = translator.detect("hello")
        print("Translator ready")
    except Exception as e:
        print("Could not initialize translator:", e)
        translator = None

SIMULATE_MALICIOUS = os.environ.get("SIMULATE_MALICIOUS", "0") == "1"

def simulate_malicious_check(url: str) -> bool:
    """
    Dev-only: mark a URL as malicious if it matches safe test patterns.
    Example test tokens: 'simulate_malicious', 'example.test', 'simulate_malicious.example.test'.
    """
    if not SIMULATE_MALICIOUS:
        return False
    if not url:
        return False
    u = url.lower()
    patterns = [
        "simulate_malicious",
        ".test-malicious",
        "phish-test",
        ".malicious.test",
        "example.test",   
    ]
    return any(tok in u for tok in patterns)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    
    bio = db.Column(db.Text, default="")
    birthday = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(20), default="")
    relationship_status = db.Column(db.String(50), default="")
    clear_mode = db.Column(db.Boolean, default=False)

    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    replies = db.relationship('Reply', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    caption = db.Column(db.Text, nullable=False)
    translated_caption = db.Column(db.Text)  
    original_lang = db.Column(db.String(10)) 
    sentiment = db.Column(db.String(20))
    score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_path = db.Column(db.String(255))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    translated_text = db.Column(db.Text, nullable=True)
    original_lang = db.Column(db.String(10), default='en')
    sentiment = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    replies = db.relationship('Reply', backref='comment', lazy=True, cascade="all, delete-orphan")

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    translated_text = db.Column(db.Text, nullable=True)
    original_lang = db.Column(db.String(10), default='en')
    sentiment = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def check_nsfw(image_path):
    """Run HuggingFace NSFW detection; returns True if unsafe."""
    if nsfw_pipeline is None:
        return False  
    try:
        img = Image.open(image_path).convert("RGB")
        results = nsfw_pipeline(img)
        
        top = max(results, key=lambda x: x['score'])
        label = str(top['label']).lower()
        score = float(top['score'])
        
        if "nsfw" in label and score > 0.85:
            return True
    except Exception as e:
        print("NSFW check error:", e)
    return False

def check_url(url):
    """Run HF URL detection if available; returns (label, score) or ('unknown',0)."""
    if url_pipeline is None:
        return "unknown", 0.0
    try:
        out = url_pipeline(url)
        if isinstance(out, list) and len(out) > 0:
            return out[0].get('label', 'unknown'), float(out[0].get('score', 0.0))
        if isinstance(out, dict):
            return out.get('label','unknown'), float(out.get('score', 0.0))
    except Exception as e:
        print("URL check error:", e)
    return "unknown", 0.0

def translate_text_if_needed(text):
    """
    Detect language and translate to English if not English.
    Returns (translated_text, detected_lang).
    If translator not available or detection fails, returns (text, 'en' or detected if found).
    """
    if not text:
        return text, 'en'
    if translator is None:
        return text, 'en'
    try:
        detect_res = translator.detect(text)
        lang = getattr(detect_res, 'lang', None) or detect_res
        lang = str(lang)
        if lang == 'en':
            return text, 'en'
        trans = translator.translate(text, src=lang, dest='en')
        translated = getattr(trans, 'text', None) or trans
        return translated, lang
    except Exception as e:
        
        print("Translation error:", e)
        return text, 'en'

def analyze_text_with_translation(text):
    """
    Translate if needed, then analyze (emoji -> VADER).
    Returns (sentiment_label, score, translated_text, detected_lang)
    """
    translated, lang = translate_text_if_needed(text)
    sentiment, score = analyze_text(translated) if translated else ('neutral', 0.0)
    return sentiment, score, translated, lang

def analyze_text(text):
    """Return (sentiment_label, score). Emoji detection first, then VADER."""
    if not text:
        return "neutral", 0.0

    try:
        emoji_sentiments = [emoji_dict[char] for char in text if char in emoji_dict]
    except Exception:
        emoji_sentiments = []
    if emoji_sentiments:
        most_common = Counter(emoji_sentiments).most_common(1)[0][0]
        if most_common == 'positive':
            return 'positive', 0.5
        elif most_common == 'negative':
            return 'negative', -0.5
        else:
            return 'neutral', 0.0

    scores = sia.polarity_scores(text)
    compound = scores.get('compound', 0.0)
    if compound >= 0.05:
        sentiment = 'positive'
    elif compound <= -0.05:
        sentiment = 'negative'
    else:
        sentiment = 'neutral'
    return sentiment, compound

def detect_malicious_links(text):
    if not text:
        return False
    
    # NEW: Catch-all regex for links without http://
    urls = re.findall(r'(?:https?://)?(?:www\.)?[\w\.-]+\.\w+\S*', text)
    
    for url in urls:
        # Step 1: Manual Simulation Check
        if simulate_malicious_check(url):
            print("[SIM] simulated malicious URL matched:", url)
            return True
            
        # Step 2: AI Check
        label, prob = check_url(url)
        print(f"https://www.merriam-webster.com/dictionary/check {url} -> {label} (Conf: {prob:.2f})")
        
        # Step 3: Flexible Label Matching
        bad_labels = ["malicious", "malware", "phishing"]
        if any(bad in label.lower() for bad in bad_labels) and prob > 0.40:
            return True
            
    return False

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Please provide username and password', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('signup'))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('feed'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/profile/', methods=['GET','POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash("Account not found", "danger")
        return redirect(url_for('login'))

    user_posts = Post.query.filter_by(author_id=user.id).order_by(Post.created_at.desc()).all()
    all_comments = Comment.query.all()

    if request.method == 'POST':
        user.bio = request.form.get('bio', user.bio)
        user.gender = request.form.get('gender', user.gender)
        user.relationship_status = request.form.get('relationship_status', user.relationship_status)
        birthday = request.form.get('birthday')
        if birthday:
            try:
                user.birthday = datetime.strptime(birthday, "%Y-%m-%d").date()
            except Exception:
                flash("Invalid birthday format", "danger")
        user.clear_mode = True if request.form.get('clear_mode') == 'on' else False
        db.session.commit()
        flash("Profile updated", "success")
        return redirect(url_for('profile'))

    return render_template("profile.html", user=user, posts=user_posts, comments=all_comments)
@app.route('/profile/<username>')
def view_profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        flash("User not found", "danger")
        return redirect(url_for('feed'))

    
    posts = Post.query.filter_by(author_id=target_user.id).order_by(Post.created_at.desc()).all()
    all_comments = Comment.query.all()
    all_replies = Reply.query.all()
    viewing_user = User.query.get(session['user_id'])


    if viewing_user and viewing_user.clear_mode:

        posts = [p for p in posts if not (p.sentiment == "negative" and p.author_id != viewing_user.id)]
        
        visible_post_ids = [p.id for p in posts]
        all_comments = [c for c in all_comments if c.post_id in visible_post_ids and not (c.sentiment == "negative" and c.author_id != viewing_user.id)]
        
        comment_ids = [c.id for c in all_comments]
        all_replies = [r for r in all_replies if r.comment_id in comment_ids and not (r.sentiment == "negative" and r.author_id != viewing_user.id)]

    
    return render_template("user_profile.html", 
                           target_user=target_user, 
                           posts=posts, 
                           comments=all_comments, 
                           replies=all_replies,
                           viewing_user=viewing_user)

@app.route('/search', methods=['GET'])
def search():
    """Search users by username"""
    query = request.args.get("q", "").strip()
    if not query:
        flash("Please enter a username to search.", "warning")
        return redirect(url_for("feed"))
    user = User.query.filter(User.username.ilike(f"%{query}%")).first()
    if user:
        return redirect(url_for("view_profile", username=user.username))
    else:
        flash("No user found.", "danger")
        return redirect(url_for("feed"))

@app.route('/feed')
def feed():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash("Your account no longer exists. Please log in again.", "danger")
        return redirect(url_for('login'))

    posts = Post.query.order_by(Post.created_at.desc()).all()
    comments = Comment.query.order_by(Comment.created_at.asc()).all()
    replies = Reply.query.order_by(Reply.created_at.asc()).all()

    if user.clear_mode:
        posts = [p for p in posts if not (p.sentiment == "negative" and p.author_id != user.id)]
        comments = [c for c in comments if not (c.sentiment == "negative" and c.author_id != user.id)]
        replies = [r for r in replies if not (r.sentiment == "negative" and r.author_id != user.id)]

    return render_template('feed.html', posts=posts, comments=comments, replies=replies, user=user)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json() or {}
    text = data.get('text','') or ''
    sentiment, score = analyze_text(text)
    return jsonify({'sentiment': sentiment, 'score': float(score)})

@app.route('/post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    text = (request.form.get('caption') or '').strip()
    image_file = request.files.get("image")

    if not text and (not image_file or image_file.filename == ""):
        flash('Post cannot be empty', 'danger')
        return redirect(url_for('feed'))

    if detect_malicious_links(text):
        flash("⚠️ Post blocked: Malicious link detected.", "danger")
        return redirect(url_for('feed'))

    sentiment, score, translated_text, detected_lang = analyze_text_with_translation(text) if text else ("neutral", 0.0, None, 'en')

    image_path = None
    if image_file and image_file.filename != "" and allowed_file(image_file.filename):
        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{image_file.filename}")
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image_file.save(filepath)

        if check_nsfw(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass
            flash("⚠️ Post blocked: Image detected as NSFW", "danger")
            return redirect(url_for('feed'))

        image_path = filename

    p = Post(
        author_id=session['user_id'],
        caption=text or "",
        translated_caption=translated_text,
        original_lang=detected_lang or 'en',
        sentiment=sentiment,
        score=score,
        image_path=image_path
    )
    db.session.add(p)
    db.session.commit()
    flash('Post created', 'success')
    return redirect(url_for('feed'))

@app.route('/comment', methods=['POST'])
def create_comment():
    if 'user_id' not in session:
        return jsonify({'error':'Not logged in'}), 401
    post_id = request.form.get('post_id')
    text = (request.form.get('text') or '').strip()
    if not text or not post_id:
        flash('Invalid comment', 'danger')
        return redirect(url_for('feed'))

    if detect_malicious_links(text):
        flash("⚠️ Comment blocked: Malicious link detected.", "danger")
        return redirect(url_for('feed'))

    sentiment, score, translated_text, detected_lang = analyze_text_with_translation(text)
    c = Comment(post_id=int(post_id), author_id=session['user_id'], text=text, translated_text=translated_text, original_lang=detected_lang or 'en', sentiment=sentiment, score=score)
    db.session.add(c)
    db.session.commit()
    flash('Comment posted', 'success')
    return redirect(url_for('feed'))

@app.route('/reply', methods=['POST'])
def create_reply():
    if 'user_id' not in session:
        return jsonify({'error':'Not logged in'}), 401
    comment_id = request.form.get('comment_id')
    text = (request.form.get('text') or '').strip()
    if not text or not comment_id:
        return jsonify({'error':'Invalid'}), 400

    if detect_malicious_links(text):
        return jsonify({'error':'Malicious link detected'}, 400)

    sentiment, score, translated_text, detected_lang = analyze_text_with_translation(text)
    r = Reply(comment_id=int(comment_id), author_id=session['user_id'], text=text, translated_text=translated_text, original_lang=detected_lang or 'en', sentiment=sentiment, score=score)
    db.session.add(r)
    db.session.commit()
    return jsonify({'status':'ok','sentiment':sentiment,'score':score,'text':text,'author': session.get('username')})

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    post = Post.query.get_or_404(post_id)
    if post.author_id != session['user_id']:
        return jsonify({'error': 'Not authorized'}), 403
    
    if post.image_path:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], post.image_path))
        except Exception:
            pass
    db.session.delete(post)
    db.session.commit()
    return jsonify({'status':'ok','post_id': post_id})

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    comment = Comment.query.get_or_404(comment_id)
    if comment.author_id != session['user_id']:
        return jsonify({'error': 'Not authorized'}), 403
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'status':'ok','comment_id': comment_id})


@app.template_filter('humantime')
def humantime(dt):
    if not dt:
        return ""
    return dt.strftime("%b %d, %Y • %H:%M")

if __name__ == '__main__':
    
    app.run(debug=True)
