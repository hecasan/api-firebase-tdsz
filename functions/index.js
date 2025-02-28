const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
admin.initializeApp();
const db = admin.firestore();
const app = express();
app.use(cors({ origin: true }));
const SECRET_KEY = "chave-secreta";
// Middleware de autenticação JWT
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token ausente" });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido" });
  }
};
// Autenticação
app.post("/auth/login", async (req, res) => {
  const { email, senha } = req.body;
  const snapshot = await db.collection("usuarios").where("email", "==", email).get();
  if (snapshot.empty) return res.status(401).json({ error: "Usuário não encontrado" });
  const user = snapshot.docs[0].data();
  if (user.senha !== senha) return res.status(401).json({ error: "Senha inválida" });
  const token = jwt.sign({ id: snapshot.docs[0].id, perfil: user.perfil }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});
// Endpoint protegido para obter perfil do usuário autenticado
app.get("/pacientes/perfil", authMiddleware, async (req, res) => {
  const userRef = db.collection("usuarios").doc(req.user.id);
  const userDoc = await userRef.get();
  if (!userDoc.exists) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }
  res.json(userDoc.data());
});
// Criar usuário
app.post("/auth/register", async (req, res) => {
  const { nome, email, senha, perfil } = req.body;
  const novoUsuario = await db.collection("usuarios").add({ nome, email, senha, perfil });
  res.json({ id: novoUsuario.id });
});
// Exportando a API para o Firebase Functions
exports.api = functions.https.onRequest(app);