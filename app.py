
import os
import json
import bcrypt
import psycopg2
import logging
from flask import Flask, render_template, request, redirect, session, send_file, url_for
from datetime import datetime
import csv

app = Flask(__name__)
app.secret_key = "etapa_pg"
CONFIG_FILE = "config_etapa6_2025_1.json"

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def carregar_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def salvar_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def get_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])

def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS notas (
                    id SERIAL PRIMARY KEY,
                    aluno TEXT,
                    professor TEXT,
                    nota REAL,
                    datahora TEXT
                )
            ''')
        conn.commit()

def atualizar_senhas_para_hash():
    cfg = carregar_config()
    changed = False
    for usuario, data in cfg["usuarios"].items():
        senha = data["senha"]
        if not senha.startswith("$2b$"):
            hashed = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
            data["senha"] = hashed
            changed = True
    if changed:
        salvar_config(cfg)
        print("Senhas atualizadas para hash.")

@app.before_first_request
def setup():
    init_db()
    atualizar_senhas_para_hash()

def verificar_senha(hash_senha, senha_digitada):
    return bcrypt.checkpw(senha_digitada.encode(), hash_senha.encode())

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_usuario():
    return dict(usuario=session.get("usuario"))

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = carregar_config()
    erro = None
    if request.method == "POST":
        nome = request.form.get("professor")
        senha = request.form.get("senha")
        user = cfg["usuarios"].get(nome)
        if user and verificar_senha(user["senha"], senha):
            session["usuario"] = nome
            logging.info(f"Login realizado: {nome}")
            return redirect(url_for("index"))
        else:
            erro = "Nome ou senha inválidos."
            logging.warning(f"Tentativa de login falhou: {nome}")
    return render_template("login.html", professores=list(cfg["usuarios"].keys()), erro=erro)

@app.route("/logout")
@login_required
def logout():
    usuario = session.get("usuario")
    session.clear()
    logging.info(f"Logout: {usuario}")
    return redirect(url_for("login"))

@app.route("/alterar-senha", methods=["GET", "POST"])
@login_required
def alterar_senha():
    erro = sucesso = None
    cfg = carregar_config()
    usuario = session["usuario"]
    if request.method == "POST":
        atual = request.form["senha_atual"]
        nova = request.form["nova_senha"]
        confirma = request.form["confirmar_senha"]
        hash_atual = cfg["usuarios"][usuario]["senha"]
        if not verificar_senha(hash_atual, atual):
            erro = "Senha atual incorreta."
        elif len(nova) < 6:
            erro = "Nova senha deve ter pelo menos 6 caracteres."
        elif nova != confirma:
            erro = "Nova senha e confirmação não coincidem."
        else:
            novo_hash = bcrypt.hashpw(nova.encode(), bcrypt.gensalt()).decode()
            cfg["usuarios"][usuario]["senha"] = novo_hash
            salvar_config(cfg)
            sucesso = "Senha alterada com sucesso!"
            logging.info(f"Senha alterada: {usuario}")
    return render_template("alterar_senha.html", titulo=cfg["titulo"], erro=erro, sucesso=sucesso)

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    cfg = carregar_config()
    usuario = session["usuario"]
    resultado = None
    if request.method == "POST":
        aluno = request.form.get("aluno")
        nota = request.form.get("nota")
        try:
            nota = float(nota)
            if 0 <= nota <= 10:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO notas (aluno, professor, nota, datahora) VALUES (%s, %s, %s, %s)",
                                    (aluno, usuario, nota, datetime.now().isoformat()))
                    conn.commit()
                resultado = f"Nota registrada com sucesso: {aluno} - {nota}"
                logging.info(f"Nota registrada: {aluno} - {nota} por {usuario}")
            else:
                resultado = "A nota deve estar entre 0 e 10."
        except Exception:
            resultado = "Nota inválida."
    return render_template("index.html", titulo=cfg["titulo"], alunos=cfg["alunos"],
                           usuario=usuario, acesso=cfg["usuarios"][usuario]["acesso_relatorio"],
                           resultado=resultado)

@app.route("/relatorio", methods=["GET", "POST"])
@login_required
def relatorio():
    cfg = carregar_config()
    usuario = session["usuario"]
    if not cfg["usuarios"][usuario]["acesso_relatorio"]:
        return redirect(url_for("index"))
    registros = []
    if request.method == "POST":
        aluno = request.form.get("aluno")
        professor = request.form.get("professor")
        data_ini = request.form.get("data_ini")
        data_fim = request.form.get("data_fim")
        query = "SELECT id, aluno, professor, nota, datahora FROM notas WHERE 1=1"
        params = []
        if aluno:
            query += " AND aluno = %s"
            params.append(aluno)
        if professor:
            query += " AND professor = %s"
            params.append(professor)
        if data_ini:
            query += " AND datahora >= %s"
            params.append(data_ini)
        if data_fim:
            query += " AND datahora <= %s"
            params.append(data_fim + 'T23:59:59')
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                registros = cur.fetchall()
            with open("export_notas.csv", "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows([["Aluno", "Professor", "Nota", "DataHora"]] + registros)
    return render_template("relatorio.html", titulo=cfg["titulo"], alunos=cfg["alunos"],
                           professores=list(cfg["usuarios"].keys()), registros=registros,
                           acesso=cfg["usuarios"][usuario]["acesso_relatorio"])

@app.route("/editar-nota/<int:nota_id>", methods=["GET", "POST"])
@login_required
def editar_nota(nota_id):
    cfg = carregar_config()
    usuario = session["usuario"]
    if not cfg["usuarios"][usuario]["acesso_relatorio"]:
        return redirect(url_for("index"))
    erro = sucesso = None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT aluno, professor, nota FROM notas WHERE id=%s", (nota_id,))
            nota_info = cur.fetchone()
            if not nota_info:
                return "Nota não encontrada."
            aluno, professor, nota_atual = nota_info
            if request.method == "POST":
                try:
                    nova = float(request.form["nova_nota"])
                    if 0 <= nova <= 10:
                        cur.execute("UPDATE notas SET nota=%s WHERE id=%s", (nova, nota_id))
                        conn.commit()
                        sucesso = "Nota atualizada com sucesso!"
                        logging.info(f"Nota editada: {aluno} ({professor}) nova nota {nova} por {usuario}")
                    else:
                        erro = "A nota deve estar entre 0 e 10."
                except Exception:
                    erro = "Nota inválida."
    return render_template("editar_nota.html", aluno=aluno, professor=professor,
                           nota_atual=nota_atual, erro=erro, sucesso=sucesso)

@app.route("/exportar")
@login_required
def exportar():
    return send_file("export_notas.csv", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
