from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.requests import Request
from pydantic import BaseModel
from typing import Optional
import sqlite3
import os
import bcrypt  # Izmantojam tīru bcrypt bez passlib

app = FastAPI(title="Uzskaites Sistēma")
DB_FILE = "sistema.db"

# --- DATUBĀZES INICIALIZĀCIJA ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Lietotāju tabula
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # Prasītā datu tabula
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ieraksti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numurs TEXT,
            uzskaite TEXT,
            nosaukums TEXT,
            izloksne TEXT,
            skaits INTEGER,
            novietojums TEXT,
            piezimes TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- DATU MODEĻI PUSH/PUT REKVESTIEM ---
class IerakstsModel(BaseModel):
    numurs: str
    uzskaite: str
    nosaukums: str
    izloksne: str
    skaits: int
    novietojums: str
    piezimes: str

# --- LIETOTĀJU AUTH API ---
@app.post("/api/register")
def register(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        # Pārbaudām, vai lietotājs jau neeksistē
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Lietotājvārds jau aizņemts")
        
        # Modernā un drošā šifrēšana ar tīru bcrypt
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        hashed_str = hashed_bytes.decode('utf-8') # Saglabāšanai DB kā teksts
        
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_str))
        conn.commit()
        return {"success": True, "message": "Reģistrācija veiksmīga!"}
    except Exception as e:
        print(f"REĢISTRĀCIJAS KĻŪDA: {e}")
        raise HTTPException(status_code=500, detail=f"Sistēmas kļūda: {str(e)}")
    finally:
        conn.close()

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=400, detail="Nepareizs lietotājvārds vai parole")
        
    stored_hash = row[0].encode('utf-8')
    password_bytes = password.encode('utf-8')
    
    # Paroles pārbaude
    if not bcrypt.checkpw(password_bytes, stored_hash):
        raise HTTPException(status_code=400, detail="Nepareizs lietotājvārds vai parole")
        
    return {"success": True, "username": username}

# --- CRUD LIETOJUMPROGRAMMAS API ---
@app.get("/api/ieraksti")
def gauti_ierakstus(
    numurs: Optional[str] = "-", uzskaite: Optional[str] = "-", 
    nosaukums: Optional[str] = "-", izloksne: Optional[str] = "-", 
    skaits: Optional[str] = "-", novietojums: Optional[str] = "-", 
    piezimes: Optional[str] = "-"
):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM ieraksti WHERE 1=1"
    params = []
    
    filters = {
        "numurs": numurs, "uzskaite": uzskaite, "nosaukums": nosaukums,
        "izloksne": izloksne, "skaits": skaits, "novietojums": novietojums, "piezimes": piezimes
    }
    
    for k, v in filters.items():
        if v and v != "-":
            query += f" AND {k} = ?"
            params.append(v)
            
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

@app.post("/api/ieraksti")
def izveidot_ierakstu(data: IerakstsModel):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ieraksti (numurs, uzskaite, nosaukums, izloksne, skaits, novietojums, piezimes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (data.numurs, data.uzskaite, data.nosaukums, data.izloksne, data.skaits, data.novietojums, data.piezimes))
    conn.commit()
    conn.close()
    return {"success": True}

@app.put("/api/ieraksti/{id}")
def labot_ierakstu(id: int, data: IerakstsModel):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE ieraksti SET numurs=?, uzskaite=?, nosaukums=?, izloksne=?, skaits=?, novietojums=?, piezimes=?
        WHERE id=?
    ''', (data.numurs, data.uzskaite, data.nosaukums, data.izloksne, data.skaits, data.novietojums, data.piezimes, id))
    conn.commit()
    conn.close()
    return {"success": True}

@app.delete("/api/ieraksti/{id}")
def dzest_ierakstu(id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ieraksti WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return {"success": True}

# --- SĀKUMA LAPAS MARŠRUTS ---
@app.get("/", response_class=HTMLResponse)
def index():
    file_path = os.path.join("templates", "index.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Fails templates/index.html netika atrasts!")
        
    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)