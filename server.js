// server.js
// -----------------------------------------------------------------------------
// Onírico — backend completo en un único archivo, pensado para desplegarse
// fácilmente (Railway, Render, etc.) sin necesidad de muchos archivos.
// Incluye: conexión a MongoDB, modelos, autenticación con JWT en cookie
// httpOnly, API REST del diario/rutina/datos de sueño, chat en tiempo real
// con Socket.IO, y el propio frontend servido como archivo estático desde
// la carpeta /public (así no hace falta desplegar el frontend aparte).
// -----------------------------------------------------------------------------

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const cookie = require("cookie");

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "cambia_esto_en_produccion";

// ---------------------------------------------------------------------------
// 1) CONEXIÓN A MONGODB
// ---------------------------------------------------------------------------
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch((err) => {
    console.error("❌ Error al conectar con MongoDB:", err.message);
    process.exit(1);
  });

// ---------------------------------------------------------------------------
// 2) MODELOS
// ---------------------------------------------------------------------------
const routineItemSchema = new mongoose.Schema(
  { id: String, bloque: String, texto: String, hecho: { type: Boolean, default: false } },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    idiomaPreferido: { type: String, enum: ["es", "ca", "en"], default: "es" },
    avatar: { type: String, default: "🌙" },
    descripcion: { type: String, default: "", maxlength: 280 },
    rutina: { type: [routineItemSchema], default: [] },
    estadisticas: {
      totalSuenosRegistrados: { type: Number, default: 0 },
      totalSuenosLucidos: { type: Number, default: 0 },
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
userSchema.methods.compararPassword = function (candidata) {
  return bcrypt.compare(candidata, this.password);
};
userSchema.methods.toSafeObject = function () {
  return {
    id: this._id,
    nombre: this.nombre,
    email: this.email,
    idiomaPreferido: this.idiomaPreferido,
    avatar: this.avatar,
    descripcion: this.descripcion,
    rutina: this.rutina,
    estadisticas: this.estadisticas,
  };
};
const User = mongoose.model("User", userSchema);

const dreamEntrySchema = new mongoose.Schema(
  {
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    fecha: { type: Date, default: Date.now },
    texto: { type: String, required: true },
    nivelLucidez: { type: Number, min: 0, max: 5, default: 0 },
    senalesOniricas: { type: [String], default: [] },
  },
  { timestamps: true }
);
const DreamEntry = mongoose.model("DreamEntry", dreamEntrySchema);

const chatMessageSchema = new mongoose.Schema(
  {
    autor: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    autorNombre: String,
    autorAvatar: { type: String, default: "🌙" },
    categoria: { type: String, default: "General" },
    texto: { type: String, required: true, maxlength: 1000 },
  },
  { timestamps: true }
);
const ChatMessage = mongoose.model("ChatMessage", chatMessageSchema);

// ---------------------------------------------------------------------------
// 3) AUTENTICACIÓN (JWT en cookie httpOnly)
// ---------------------------------------------------------------------------
function generarToken(id) {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: "30d" });
}
function enviarCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}
function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "No has iniciado sesión." });
  try {
    req.usuarioId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    return res.status(401).json({ error: "Sesión inválida o caducada." });
  }
}

const RUTINA_POR_DEFECTO = [
  { id: "m1", bloque: "manana", texto: "Recordar el sueño antes de moverte" },
  { id: "m2", bloque: "manana", texto: "Escribirlo en el diario" },
  { id: "m3", bloque: "manana", texto: "Valorar la calidad del recuerdo" },
  { id: "d1", bloque: "dia", texto: "Hacer 5 comprobaciones de realidad" },
  { id: "d2", bloque: "dia", texto: "Anotar posibles señales oníricas" },
  { id: "n1", bloque: "noche", texto: "Revisar tu objetivo de la noche" },
  { id: "n2", bloque: "noche", texto: "Practicar MILD" },
  { id: "w1", bloque: "wbtb", texto: "WBTB, solo si te apetece esa noche" },
].map((it) => ({ ...it, hecho: false }));

// ---------------------------------------------------------------------------
// 4) APP EXPRESS
// ---------------------------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"))); // sirve el frontend (index.html, etc.)

// --- Auth ---
app.post("/api/auth/registro", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: "Faltan datos." });
    if (password.length < 6) return res.status(400).json({ error: "La contraseña debe tener 6+ caracteres." });
    if (await User.findOne({ email: email.toLowerCase() })) {
      return res.status(409).json({ error: "Ya existe una cuenta con ese email." });
    }
    const usuario = await User.create({
      nombre,
      email,
      password,
      rutina: RUTINA_POR_DEFECTO,
    });
    enviarCookie(res, generarToken(usuario._id));
    res.status(201).json({ usuario: usuario.toSafeObject() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al registrar." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const usuario = await User.findOne({ email: (email || "").toLowerCase() });
    if (!usuario || !(await usuario.compararPassword(password))) {
      return res.status(401).json({ error: "Email o contraseña incorrectos." });
    }
    enviarCookie(res, generarToken(usuario._id));
    res.json({ usuario: usuario.toSafeObject() });
  } catch (e) {
    res.status(500).json({ error: "Error al iniciar sesión." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/auth/yo", requireAuth, async (req, res) => {
  const usuario = await User.findById(req.usuarioId);
  if (!usuario) return res.status(404).json({ error: "No encontrado." });
  res.json({ usuario: usuario.toSafeObject() });
});

app.put("/api/auth/perfil", requireAuth, async (req, res) => {
  const usuario = await User.findById(req.usuarioId);
  const { nombre, idiomaPreferido, avatar, descripcion } = req.body;
  if (nombre) usuario.nombre = nombre;
  if (idiomaPreferido) usuario.idiomaPreferido = idiomaPreferido;
  if (avatar) usuario.avatar = avatar;
  if (descripcion !== undefined) usuario.descripcion = descripcion.slice(0, 280);
  await usuario.save();
  res.json({ usuario: usuario.toSafeObject() });
});

// --- Diario de sueños ---
app.get("/api/suenos", requireAuth, async (req, res) => {
  const suenos = await DreamEntry.find({ usuario: req.usuarioId }).sort({ fecha: -1 });
  res.json({ suenos });
});
app.post("/api/suenos", requireAuth, async (req, res) => {
  const { fecha, texto, nivelLucidez, senalesOniricas } = req.body;
  if (!texto?.trim()) return res.status(400).json({ error: "El sueño no puede estar vacío." });
  const entrada = await DreamEntry.create({
    usuario: req.usuarioId,
    fecha: fecha || Date.now(),
    texto,
    nivelLucidez: nivelLucidez ?? 0,
    senalesOniricas: senalesOniricas || [],
  });
  const usuario = await User.findById(req.usuarioId);
  usuario.estadisticas.totalSuenosRegistrados += 1;
  if ((nivelLucidez ?? 0) >= 3) usuario.estadisticas.totalSuenosLucidos += 1;
  await usuario.save();
  res.status(201).json({ sueno: entrada });
});
app.put("/api/suenos/:id", requireAuth, async (req, res) => {
  const entrada = await DreamEntry.findOne({ _id: req.params.id, usuario: req.usuarioId });
  if (!entrada) return res.status(404).json({ error: "No encontrado." });
  Object.assign(entrada, req.body);
  await entrada.save();
  res.json({ sueno: entrada });
});
app.delete("/api/suenos/:id", requireAuth, async (req, res) => {
  await DreamEntry.findOneAndDelete({ _id: req.params.id, usuario: req.usuarioId });
  res.json({ ok: true });
});

// --- Rutina (checklist por bloques del día) ---
app.get("/api/rutina", requireAuth, async (req, res) => {
  const usuario = await User.findById(req.usuarioId);
  if (!usuario.rutina || usuario.rutina.length === 0) {
    usuario.rutina = RUTINA_POR_DEFECTO;
    await usuario.save();
  }
  res.json({ rutina: usuario.rutina });
});
app.put("/api/rutina/:id/toggle", requireAuth, async (req, res) => {
  const usuario = await User.findById(req.usuarioId);
  const item = usuario.rutina.find((h) => h.id === req.params.id);
  if (!item) return res.status(404).json({ error: "No encontrado." });
  item.hecho = !item.hecho;
  await usuario.save();
  res.json({ rutina: usuario.rutina });
});

// --- Historial de chat ---
app.get("/api/chat/historial", requireAuth, async (req, res) => {
  const mensajes = await ChatMessage.find().sort({ createdAt: -1 }).limit(80);
  res.json({ mensajes: mensajes.reverse() });
});

// ---------------------------------------------------------------------------
// 5) SERVIDOR HTTP + SOCKET.IO (chat en tiempo real)
// ---------------------------------------------------------------------------
const servidorHttp = http.createServer(app);
const io = new Server(servidorHttp, { cors: { origin: true, credentials: true } });

io.use((socket, next) => {
  try {
    const crudas = socket.handshake.headers.cookie;
    if (!crudas) return next(new Error("No autenticado"));
    const token = cookie.parse(crudas).token;
    socket.usuarioId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    next(new Error("Token inválido"));
  }
});

io.on("connection", (socket) => {
  socket.on("mensaje_nuevo", async (payload) => {
    const texto = typeof payload === "string" ? payload : payload?.texto;
    const categoria = (typeof payload === "object" && payload?.categoria) || "General";
    if (!texto || !texto.trim()) return;
    const usuario = await User.findById(socket.usuarioId);
    if (!usuario) return;
    const mensaje = await ChatMessage.create({
      autor: usuario._id,
      autorNombre: usuario.nombre,
      autorAvatar: usuario.avatar || "🌙",
      categoria,
      texto: texto.trim().slice(0, 1000),
    });
    io.emit("mensaje_recibido", mensaje);
  });
});

servidorHttp.listen(PORT, () => console.log(`🚀 Servidor en marcha en el puerto ${PORT}`));
