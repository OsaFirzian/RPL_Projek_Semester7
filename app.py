from flask import Flask, request, request, render_template, send_file, redirect, url_for, flash, session
from hybrid_crypto import load_public_key_from_file, load_private_key_from_file, encrypt_file_with_rsa_aes, decrypt_file_with_rsa_aes, generate_rsa_keypair, save_private_key_to_file, save_public_key_to_file
import os

app = Flask(__name__)
app.secret_key = "rahasia_super_aman"  # diperlukan untuk flash message

UPLOAD = "uploads"
ENC = "encrypted"
DEC = "decrypted"
os.makedirs(UPLOAD, exist_ok=True)
os.makedirs(ENC, exist_ok=True)
os.makedirs(DEC, exist_ok=True)

public_key = None
private_key = None

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload_key_public", methods=["POST"])
def upload_key_public():
    global public_key
    f = request.files["pubkey"]
    path = os.path.join(UPLOAD, "public.pem")
    f.save(path)
    public_key = load_public_key_from_file(path)
    session["public_key_name"] = f.filename
    flash("✔ Public key berhasil di-upload.")
    return redirect(url_for("index"))


@app.route("/upload_key_private", methods=["POST"])
def upload_key_private():
    global private_key
    f = request.files["privkey"]
    path = os.path.join(UPLOAD, "private.pem")
    f.save(path)
    private_key = load_private_key_from_file(path)
    session["private_key_name"] = f.filename
    flash("✔ Private key berhasil di-upload.")
    return redirect(url_for("index"))


@app.route("/encrypt", methods=["POST"])
def encrypt():
    f = request.files["file"]
    in_path = os.path.join(UPLOAD, f.filename)
    f.save(in_path)

    session["pending_encrypt"] = f.filename
    flash("File siap dienkripsi — klik tombol Encrypt & Download di halaman.")
    return redirect(url_for("index"))


@app.route("/decrypt", methods=["POST"])
def decrypt():
    f = request.files["file"]
    in_path = os.path.join(UPLOAD, f.filename)
    f.save(in_path)

    session["pending_decrypt"] = f.filename
    flash("File siap didekripsi — klik tombol Decrypt & Download di halaman.")
    return redirect(url_for("index"))

@app.route("/do_encrypt")
def do_encrypt():
    global public_key
    fname = session.pop("pending_encrypt", None)
    if not fname:
        return redirect(url_for("index"))

    in_path = os.path.join(UPLOAD, fname)
    out_name = fname + ".enc"
    out_path = os.path.join(ENC, out_name)

    encrypt_file_with_rsa_aes(public_key, in_path, out_path)
    return send_file(out_path, as_attachment=True)

@app.route("/do_decrypt")
def do_decrypt():
    global private_key
    fname = session.pop("pending_decrypt", None)
    if not fname:
        return redirect(url_for("index"))

    in_path = os.path.join(UPLOAD, fname)
    out_name = fname.replace(".enc", "")
    out_path = os.path.join(DEC, out_name)

    decrypt_file_with_rsa_aes(private_key, in_path, out_path)
    return send_file(out_path, as_attachment=True)


@app.route("/generate_keys", methods=["GET"])
def generate_keys():
    # buat pair RSA
    private_key, public_key = generate_rsa_keypair()

    private_path = os.path.join(ENC, "private.pem")
    public_path = os.path.join(ENC, "public.pem")

    save_private_key_to_file(private_key, private_path, password=None)
    save_public_key_to_file(public_key, public_path)

    flash("🔑 RSA Key Pair berhasil dibuat — silakan unduh file kunci.")
    return redirect(url_for("keys_page"))

@app.route("/keys", methods=["GET"])
def keys_page():
    return render_template("keys.html")

@app.route("/download_private")
def download_private():
    return send_file(os.path.join(ENC, "private.pem"), as_attachment=True)

@app.route("/download_public")
def download_public():
    return send_file(os.path.join(ENC, "public.pem"), as_attachment=True)

@app.route("/download_result")
def download_result():
    if "download_file" not in session:
        flash("⚠ Tidak ada file untuk diunduh.")
        return redirect(url_for("index"))

    filename = session["download_file"]
    session.pop("download_file", None)  # hapus supaya tombol tidak muncul terus

    # cek di folder encrypted atau decrypted
    enc_path = os.path.join(ENC, filename)
    dec_path = os.path.join(DEC, filename)

    if os.path.exists(enc_path):
        return send_file(enc_path, as_attachment=True)
    elif os.path.exists(dec_path):
        return send_file(dec_path, as_attachment=True)

    flash("⚠ File tidak ditemukan.")
    return redirect(url_for("index"))


app.run(debug=True)
