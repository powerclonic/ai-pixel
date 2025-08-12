"""AI generic trash coded pixel game - single file backend

Implemented features:
 - Single-file FastAPI backend
 - Token auth (HMAC signed compact token) via HttpOnly cookie
 - WebSockets: pixel updates, live ranking, player count, total pixels
 - SQLite persistence (users, board, upgrades, purchased colors)
 - Performance: board cached in memory and synced to SQLite; broadcast only diffs
 - Upgrades: stored pixel capacity, extra color purchases, capacity upgrades
 - Configurable per-pixel cooldown; passive stored pixel regeneration
 - Live ranking by pixels placed
 - Shareable coordinates via query string
 - Configurable parameters via environment variables
 - Simplicity: everything in one file

Run:
	uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from fastapi import (
	Cookie,
	Depends,
	FastAPI,
	HTTPException,
	Request,
	Response,
	WebSocket,
	WebSocketDisconnect,
)
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel

# ===================== CONFIG ===================== #

CONFIG = {
	"BOARD_WIDTH": int(os.getenv("BOARD_WIDTH", 2048)),  # aumentado
	"BOARD_HEIGHT": int(os.getenv("BOARD_HEIGHT", 2048)),  # aumentado
	"BASE_COOLDOWN_SEC": float(os.getenv("BASE_COOLDOWN_SEC", 10.0)),
	"PIXEL_STORAGE_CAPACITY": int(os.getenv("PIXEL_STORAGE_CAPACITY", 60)),
	"PIXEL_STORAGE_REGEN_SEC": float(os.getenv("PIXEL_STORAGE_REGEN_SEC", 10.0)),  # igual ao cooldown base
	"TOKEN_EXP_MIN": int(os.getenv("TOKEN_EXP_MIN", 24 * 60)),
	"SECRET_KEY": os.getenv("SECRET_KEY", secrets.token_hex(32)),
	"INITIAL_CREDITS": int(os.getenv("INITIAL_CREDITS", 100)),
	"COLOR_COST": int(os.getenv("COLOR_COST", 50)),
	"CAPACITY_UPGRADE_COST": int(os.getenv("CAPACITY_UPGRADE_COST", 50)),
	"CAPACITY_UPGRADE_STEP": int(os.getenv("CAPACITY_UPGRADE_STEP", 25)),
	"MAX_COLORS_PURCHASE": int(os.getenv("MAX_COLORS_PURCHASE", 64)),
	"RANKING_TOP_N": int(os.getenv("RANKING_TOP_N", 10)),
}

BASE_PALETTE = [
	"#FFFFFF",
	"#000000",
	"#FF0000",
	"#00FF00",
	"#0000FF",
	"#FFFF00",
	"#FF00FF",
	"#00FFFF",
	"#FFA500",
	"#C0C0C0",
]

EXTRA_COLORS = [
	"#800000",
	"#808000",
	"#008000",
	"#800080",
	"#008080",
	"#000080",
	"#A52A2A",
	"#DC143C",
	"#FF69B4",
	"#FFD700",
	"#ADFF2F",
	"#20B2AA",
	"#87CEEB",
	"#4169E1",
	"#4B0082",
	"#8B4513",
]

DB_PATH = Path(__file__).parent / "data" / "pixel_game.sqlite3"
# Ensure directory exists for easier backups
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ===================== DB / MODELO ===================== #

def get_db() -> sqlite3.Connection:
	conn = sqlite3.connect(DB_PATH)
	conn.row_factory = sqlite3.Row
	return conn


def init_db():
	conn = get_db()
	cur = conn.cursor()
	cur.execute(
		f"""
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			salt TEXT NOT NULL,
			pixels_placed INTEGER NOT NULL DEFAULT 0,
			stored_pixels INTEGER NOT NULL DEFAULT 0,
			-- DEFAULT dinâmico não pode usar placeholder '?', então injetamos valor inteiro já validado
			pixel_capacity INTEGER NOT NULL DEFAULT {int(CONFIG['PIXEL_STORAGE_CAPACITY'])},
			last_place_ts REAL,
			last_regen_ts REAL,
			credits INTEGER NOT NULL DEFAULT 0,
			bought_colors TEXT NOT NULL DEFAULT '[]'
		)
		"""
	)
	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS board (
			x INTEGER NOT NULL,
			y INTEGER NOT NULL,
			color TEXT NOT NULL,
			PRIMARY KEY (x,y)
		)
		"""
	)
	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS meta (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL
		)
		"""
	)
	conn.commit()

	# Preenche board se vazio
	cur.execute("SELECT COUNT(*) AS c FROM board")
	if cur.fetchone()["c"] == 0:
		# Inicializa com branco (#FFFFFF) para economia, opcional não inserir todos -> inserir somente alterados.
		pass  # Board implicitamente branco em memória

	# Pixel total global
	cur.execute("SELECT v FROM meta WHERE k='total_pixels'")
	row = cur.fetchone()
	if not row:
		cur.execute("INSERT INTO meta(k,v) VALUES('total_pixels','0')")
		conn.commit()
	conn.close()


init_db()

# Migration: ensure all existing users have at least the base configured pixel capacity.
def ensure_min_capacity():
	try:
		conn = get_db()
		base_cap = CONFIG["PIXEL_STORAGE_CAPACITY"]
		# Update users whose capacity is below new base; also top up stored_pixels proportionally if they were full before.
		# We simply set stored_pixels to the new cap if stored_pixels >= pixel_capacity (i.e., they were at or above old full state)
		conn.execute(
			"""
			UPDATE users
			SET pixel_capacity = ?,
				stored_pixels = CASE WHEN stored_pixels >= pixel_capacity THEN ? ELSE stored_pixels END
			WHERE pixel_capacity < ?
			""",
			(base_cap, base_cap, base_cap),
		)
		conn.commit()
		conn.close()
	except Exception:
		pass  # silent; non-critical

ensure_min_capacity()

# ===================== AUTH ===================== #


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
	if salt is None:
		salt = secrets.token_hex(16)
	h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
	return base64.b64encode(h).decode(), salt


def create_token(payload: dict) -> str:
	header = {"alg": "HS256", "typ": "JWT"}
	def b64(obj):
		return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()
	header_b64 = b64(header)
	payload_b64 = b64(payload)
	signing_input = f"{header_b64}.{payload_b64}".encode()
	sig = base64.urlsafe_b64encode(
		hmac.new(CONFIG["SECRET_KEY"].encode(), signing_input, hashlib.sha256).digest()
	).rstrip(b"=").decode()
	return f"{header_b64}.{payload_b64}.{sig}"


def verify_token(token: str) -> Optional[dict]:
	try:
		header_b64, payload_b64, sig = token.split(".")
		signing_input = f"{header_b64}.{payload_b64}".encode()
		expected = base64.urlsafe_b64encode(
			hmac.new(CONFIG["SECRET_KEY"].encode(), signing_input, hashlib.sha256).digest()
		).rstrip(b"=").decode()
		if not hmac.compare_digest(expected, sig):
			return None
		pad = lambda s: s + "=" * (-len(s) % 4)
		payload_json = base64.urlsafe_b64decode(pad(payload_b64)).decode()
		payload = json.loads(payload_json)
		if payload.get("exp") and time.time() > payload["exp"]:
			return None
		return payload
	except Exception:
		return None


def issue_token(user_id: int, username: str) -> str:
	exp = time.time() + CONFIG["TOKEN_EXP_MIN"] * 60
	return create_token({"sub": user_id, "username": username, "exp": exp})


def get_user_by_username(conn: sqlite3.Connection, username: str):
	cur = conn.execute("SELECT * FROM users WHERE username=?", (username,))
	return cur.fetchone()


def regen_stored_pixels(user_row: sqlite3.Row) -> Tuple[int, float]:
	now = time.time()
	last_regen = user_row["last_regen_ts"] or now
	capacity = user_row["pixel_capacity"]
	stored = user_row["stored_pixels"]
	if stored >= capacity:
		return stored, last_regen
	regen_interval = CONFIG["PIXEL_STORAGE_REGEN_SEC"]
	gained = int((now - last_regen) / regen_interval)
	if gained <= 0:
		return stored, last_regen
	stored = min(capacity, stored + gained)
	last_regen = last_regen + gained * regen_interval
	return stored, last_regen


async def get_current_user(request: Request, token: Optional[str] = Cookie(None)):
	# Permite também header Authorization: Bearer
	raw = token
	if not raw:
		auth = request.headers.get("Authorization")
		if auth and auth.startswith("Bearer "):
			raw = auth.split(None, 1)[1]
	if not raw:
		raise HTTPException(status_code=401, detail="Not authenticated")
	payload = verify_token(raw)
	if not payload:
		raise HTTPException(status_code=401, detail="Invalid token")
	conn = get_db()
	cur = conn.execute("SELECT * FROM users WHERE id=?", (payload["sub"],))
	user = cur.fetchone()
	if not user:
		conn.close()
		raise HTTPException(status_code=401, detail="User not found")
	# Regenerar armazenados
	stored, last_regen = regen_stored_pixels(user)
	if stored != user["stored_pixels"]:
		conn.execute(
			"UPDATE users SET stored_pixels=?, last_regen_ts=? WHERE id=?",
			(stored, last_regen, user["id"]),
		)
		conn.commit()
		cur = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],))
		user = cur.fetchone()
	conn.close()
	return user


# ===================== APP ===================== #

app = FastAPI(title="AI generic trash coded pixel game")
app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)


@app.get("/")
async def root():
	index_path = Path(__file__).parent / "index.html"
	if not index_path.exists():
		return PlainTextResponse("index.html not found", status_code=404)
	return FileResponse(index_path)


class AuthPayload(BaseModel):
	username: str
	password: str


@app.post("/api/register")
async def register(data: AuthPayload, response: Response):
	if not (3 <= len(data.username) <= 20):
		raise HTTPException(400, "Invalid username length")
	if len(data.password) < 4:
		raise HTTPException(400, "Password too short")
	conn = get_db()
	if get_user_by_username(conn, data.username):
		conn.close()
		raise HTTPException(400, "Username already exists")
	pwd_hash, salt = hash_password(data.password)
	now = time.time()
	cur = conn.execute(
		"""
		INSERT INTO users (username,password_hash,salt,stored_pixels,last_regen_ts,credits)
		VALUES (?,?,?,?,?,?)
		""",
		(
			data.username,
			pwd_hash,
			salt,
			CONFIG["PIXEL_STORAGE_CAPACITY"],  # começa cheio
			now,
			CONFIG["INITIAL_CREDITS"],
		),
	)
	user_id = cur.lastrowid
	conn.commit()
	conn.close()
	token = issue_token(user_id, data.username)
	response.set_cookie(
		"token",
		token,
		httponly=True,
		max_age=CONFIG["TOKEN_EXP_MIN"] * 60,
		samesite="lax",
	)
	return {"ok": True, "username": data.username}


@app.post("/api/login")
async def login(data: AuthPayload, response: Response):
	conn = get_db()
	user = get_user_by_username(conn, data.username)
	if not user:
		conn.close()
		raise HTTPException(400, "Invalid credentials")
	pwd_hash, _ = hash_password(data.password, user["salt"])
	if not hmac.compare_digest(pwd_hash, user["password_hash"]):
		conn.close()
		raise HTTPException(400, "Invalid credentials")
	token = issue_token(user["id"], user["username"])
	conn.close()
	response.set_cookie(
		"token",
		token,
		httponly=True,
		max_age=CONFIG["TOKEN_EXP_MIN"] * 60,
		samesite="lax",
	)
	return {"ok": True, "username": user["username"]}


@app.post("/api/logout")
async def logout(response: Response):
	response.delete_cookie("token")
	return {"ok": True}


def serialize_user(user: sqlite3.Row) -> dict:
	return {
		"id": user["id"],
		"username": user["username"],
		"pixelsPlaced": user["pixels_placed"],
		"storedPixels": user["stored_pixels"],
		"capacity": user["pixel_capacity"],
		"credits": user["credits"],
	"boughtColors": json.loads(user["bought_colors"] or "[]"),
	"lastRegenTs": user["last_regen_ts"],
	"lastPlaceTs": user["last_place_ts"],
	}


@app.get("/api/me")
async def me(user=Depends(get_current_user)):
	return serialize_user(user)


@app.get("/api/config")
async def get_config():
	return {
		"width": CONFIG["BOARD_WIDTH"],
		"height": CONFIG["BOARD_HEIGHT"],
		"baseCooldown": CONFIG["BASE_COOLDOWN_SEC"],
	"regenInterval": CONFIG["PIXEL_STORAGE_REGEN_SEC"],
		"basePalette": BASE_PALETTE,
		"extraColors": EXTRA_COLORS,
		"colorCost": CONFIG["COLOR_COST"],
		"capacityUpgradeCost": CONFIG["CAPACITY_UPGRADE_COST"],
		"capacityUpgradeStep": CONFIG["CAPACITY_UPGRADE_STEP"],
	}


# In-memory board (lazy default white)
BOARD_DEFAULT_COLOR = BASE_PALETTE[0]
board_mem: List[List[str]] = [
	[BOARD_DEFAULT_COLOR for _ in range(CONFIG["BOARD_WIDTH"])]
	for _ in range(CONFIG["BOARD_HEIGHT"])
]


def load_board_into_memory():
	conn = get_db()
	cur = conn.execute("SELECT x,y,color FROM board")
	for row in cur.fetchall():
		if 0 <= row["y"] < CONFIG["BOARD_HEIGHT"] and 0 <= row["x"] < CONFIG["BOARD_WIDTH"]:
			board_mem[row["y"]][row["x"]] = row["color"]
	conn.close()


load_board_into_memory()


@app.get("/api/board")
async def get_board_snapshot():
	# Retorna board comprimido (run-length simples por linhas)
	def rle_line(line: List[str]):
		out = []
		prev = line[0]
		count = 1
		for c in line[1:]:
			if c == prev:
				count += 1
			else:
				out.append([prev, count])
				prev = c
				count = 1
		out.append([prev, count])
		return out

	compressed = [rle_line(row) for row in board_mem]
	return {"rle": compressed}


# ===================== UPGRADES ===================== #


class BuyColorPayload(BaseModel):
	color: str


@app.post("/api/buy_color")
async def buy_color(data: BuyColorPayload, user=Depends(get_current_user)):
	color = data.color.upper()
	if color not in EXTRA_COLORS:
		raise HTTPException(400, "Color not available")
	bought = set(json.loads(user["bought_colors"]))
	if color in bought:
		raise HTTPException(400, "Color already owned")
	if user["credits"] < CONFIG["COLOR_COST"]:
		raise HTTPException(400, "Not enough credits")
	bought.add(color)
	conn = get_db()
	conn.execute(
		"UPDATE users SET credits=credits-?, bought_colors=? WHERE id=?",
		(CONFIG["COLOR_COST"], json.dumps(list(bought)), user["id"]),
	)
	conn.commit()
	cur = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],))
	new_user = cur.fetchone()
	conn.close()
	return serialize_user(new_user)


@app.post("/api/upgrade_capacity")
async def upgrade_capacity(user=Depends(get_current_user)):
	if user["credits"] < CONFIG["CAPACITY_UPGRADE_COST"]:
		raise HTTPException(400, "Not enough credits")
	conn = get_db()
	conn.execute(
		"UPDATE users SET credits=credits-?, pixel_capacity=pixel_capacity+? WHERE id=?",
		(
			CONFIG["CAPACITY_UPGRADE_COST"],
			CONFIG["CAPACITY_UPGRADE_STEP"],
			user["id"],
		),
	)
	conn.commit()
	cur = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],))
	new_user = cur.fetchone()
	conn.close()
	return serialize_user(new_user)


# ===================== WEBSOCKET / TEMPO REAL ===================== #


class ConnectionManager:
	def __init__(self):
		self.active: Set[WebSocket] = set()
		self.user_ids: Dict[WebSocket, int] = {}
		self.lock = asyncio.Lock()

	async def connect(self, ws: WebSocket, user_id: int):
		await ws.accept()
		async with self.lock:
			self.active.add(ws)
			self.user_ids[ws] = user_id
		await self.broadcast_player_count()

	async def disconnect(self, ws: WebSocket):
		async with self.lock:
			self.active.discard(ws)
			self.user_ids.pop(ws, None)
		await self.broadcast_player_count()

	async def send(self, ws: WebSocket, message: dict):
		await ws.send_json(message)

	async def broadcast(self, message: dict):
		dead = []
		for ws in list(self.active):
			try:
				await ws.send_json(message)
			except Exception:
				dead.append(ws)
		for ws in dead:
			await self.disconnect(ws)

	async def broadcast_player_count(self):
		await self.broadcast({"type": "player_count", "count": len(self.active)})


manager = ConnectionManager()


def get_total_pixels(conn: sqlite3.Connection) -> int:
	cur = conn.execute("SELECT v FROM meta WHERE k='total_pixels'")
	return int(cur.fetchone()["v"])


def incr_total_pixels(conn: sqlite3.Connection, n: int = 1) -> int:
	cur = conn.execute("SELECT v FROM meta WHERE k='total_pixels'")
	total = int(cur.fetchone()["v"]) + n
	conn.execute("UPDATE meta SET v=? WHERE k='total_pixels'", (str(total),))
	return total


async def send_ranking():
	conn = get_db()
	cur = conn.execute(
		"SELECT username, pixels_placed FROM users ORDER BY pixels_placed DESC, id ASC LIMIT ?",
		(CONFIG["RANKING_TOP_N"],),
	)
	ranking = [dict(row) for row in cur.fetchall()]
	conn.close()
	await manager.broadcast({"type": "ranking", "ranking": ranking})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
	# Token pode vir via cookie ou query param token=...
	token = ws.cookies.get("token") or ws.query_params.get("token")
	payload = verify_token(token) if token else None
	if not payload:
		await ws.close(code=4401)
		return
	user_id = payload["sub"]
	await manager.connect(ws, user_id)

	def regen_and_fetch(user_id_: int) -> sqlite3.Row:
		conn_local = get_db()
		cur_local = conn_local.execute("SELECT * FROM users WHERE id=?", (user_id_,))
		u = cur_local.fetchone()
		if not u:
			conn_local.close()
			return None
		stored, last_regen = regen_stored_pixels(u)
		if stored != u["stored_pixels"]:
			conn_local.execute(
				"UPDATE users SET stored_pixels=?, last_regen_ts=? WHERE id=?",
				(stored, last_regen, user_id_),
			)
			conn_local.commit()
			cur_local = conn_local.execute("SELECT * FROM users WHERE id=?", (user_id_,))
			u = cur_local.fetchone()
		conn_local.close()
		return u

	# Envia snapshot inicial + dados do usuário
	conn = get_db()
	total_pixels = get_total_pixels(conn)
	cur = conn.execute("SELECT username, pixels_placed FROM users ORDER BY pixels_placed DESC, id ASC LIMIT ?", (CONFIG["RANKING_TOP_N"],))
	ranking = [dict(row) for row in cur.fetchall()]
	conn.close()
	user_row_initial = regen_and_fetch(user_id)
	await ws.send_json({
		"type": "init",
		"width": CONFIG["BOARD_WIDTH"],
		"height": CONFIG["BOARD_HEIGHT"],
		"boardRows": board_mem,  # simples: lista de listas
		"totalPixels": total_pixels,
		"ranking": ranking,
		"user": serialize_user(user_row_initial) if user_row_initial else None,
	})
	try:
		while True:
			data = await ws.receive_json()
			msg_type = data.get("type")
			if msg_type == "place":
				x = int(data.get("x", -1))
				y = int(data.get("y", -1))
				color = str(data.get("color", "")).upper()
				if not (0 <= x < CONFIG["BOARD_WIDTH"] and 0 <= y < CONFIG["BOARD_HEIGHT"]):
					await ws.send_json({"type": "error", "error": "Out of bounds"})
					continue
				allowed_colors = set(BASE_PALETTE)
				# Carregar usuário para verificar colors
				conn = get_db()
				cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
				user = cur.fetchone()
				# regen stored
				stored, last_regen = regen_stored_pixels(user)
				if stored != user["stored_pixels"]:
					conn.execute(
						"UPDATE users SET stored_pixels=?, last_regen_ts=? WHERE id=?",
						(stored, last_regen, user_id),
					)
					conn.commit()
					cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
					user = cur.fetchone()
				bought = set(json.loads(user["bought_colors"]))
				allowed_colors.update(bought)
				if color not in allowed_colors:
					conn.close()
					await ws.send_json({"type": "error", "error": "Color not allowed"})
					continue
				now = time.time()
				can_place = False
				if user["stored_pixels"] > 0:
					can_place = True
					new_stored = user["stored_pixels"] - 1
				else:
					last = user["last_place_ts"] or 0
					if now - last >= CONFIG["BASE_COOLDOWN_SEC"]:
						can_place = True
						new_stored = user["stored_pixels"]
				if not can_place:
					remaining = max(0, CONFIG["BASE_COOLDOWN_SEC"] - (now - (user["last_place_ts"] or 0)))
					conn.close()
					await ws.send_json({"type": "cooldown", "remaining": round(remaining, 2)})
					continue
				# Atualiza board
				board_mem[y][x] = color
				conn.execute(
					"INSERT INTO board(x,y,color) VALUES(?,?,?) ON CONFLICT(x,y) DO UPDATE SET color=excluded.color",
					(x, y, color),
				)
				total_pixels = incr_total_pixels(conn)
				# Se consumiu pixel armazenado, não reinicia cooldown (não atualiza last_place_ts)
				if user["stored_pixels"] > 0:  # estava >0 antes de colocar => usou stored
					conn.execute(
						"UPDATE users SET stored_pixels=?, pixels_placed=pixels_placed+1, credits=credits+1 WHERE id=?",
						(new_stored, user_id),
					)
				else:
					conn.execute(
						"UPDATE users SET last_place_ts=?, stored_pixels=?, pixels_placed=pixels_placed+1, credits=credits+1 WHERE id=?",
						(now, new_stored, user_id),
					)
				conn.commit()
				conn.close()
				await manager.broadcast({
					"type": "pixel",
					"x": x,
					"y": y,
					"color": color,
					"userId": user_id,
					"totalPixels": total_pixels,
				})
				await send_ranking()
			elif msg_type == "ping":
				# Aproveita ping para atualizar regeneração do usuário
				updated = regen_and_fetch(user_id)
				if updated:
					await ws.send_json({"type": "me", "user": serialize_user(updated)})
				await ws.send_json({"type": "pong", "t": time.time()})
	except WebSocketDisconnect:
		await manager.disconnect(ws)
	except Exception as e:
		await ws.send_json({"type": "error", "error": str(e)})
		await manager.disconnect(ws)


# ===================== RANKING POLLER ===================== #


async def ranking_refresher():
	while True:
		await asyncio.sleep(15)
		if manager.active:
			await send_ranking()


@app.on_event("startup")
async def on_startup():
	asyncio.create_task(ranking_refresher())


# ===================== DEV UTIL ===================== #


@app.get("/api/debug/health")
async def health():
	return {"ok": True, "time": time.time()}


if __name__ == "__main__":
	import uvicorn

	uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

