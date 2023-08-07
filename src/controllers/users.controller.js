import bcrypt from "bcrypt";
import { v4 as tokenGenerator } from "uuid";
import { db } from "../database/database.connection.js";

export async function signUp(req, res) {
  const { name, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(422).json({ error: "As senhas apresentadas são diferentes." });
  }

  const hash = bcrypt.hashSync(password, 10);
  try {
    const usuarioPreExistente = await db.query(`SELECT * FROM users WHERE email = $1`, [email]);
    if (usuarioPreExistente.rows.length > 0) {
      return res.status(409).json({ error: "Esse email já está cadastrado." });
    }

    await db.query(`INSERT INTO users (name, email, password) VALUES ($1, $2, $3);`, [name, email, hash]);

    res.status(201).json({ message: "SignUp efetuado com sucesso." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

export async function signIn(req, res) {
  const { email, password } = req.body;
  const token = tokenGenerator();

  try {
    const usuario = (await db.query(`
      SELECT users.*, sessions.token
      FROM users
      LEFT JOIN sessions
      ON users.id = sessions."userId"
      WHERE users.email = $1;
    `, [email])).rows[0];

    if (!usuario) {
      return res.status(401).json({ error: "O email enviado não está cadastrado." });
    }

    const senhaEstaCorreta = bcrypt.compareSync(password, usuario.password);
    if (!senhaEstaCorreta) {
      return res.status(401).json({ error: "A senha enviada não está correta." });
    }

    if (!usuario.token) {
      await db.query(`INSERT INTO sessions("userId", token) VALUES($1, $2);`, [usuario.id, token]);
    }

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

export async function usersMe(req, res) {
  const { session } = res.locals;

  try {
    const { rows } = await db.query(`
      SELECT 
        users.id, 
        users.name, 
        CAST(SUM(urls."visitCount") AS INTEGER) AS "visitCount",
        JSON_AGG(JSON_BUILD_OBJECT(
          'id', urls.id,
          'shortUrl', urls."shortUrl",
          'url', urls.url,
          'visitCount', urls."visitCount"
        ) ORDER BY urls.id) AS "shortenedUrls"
      FROM users
      JOIN urls 
      ON urls."userId"= users.id
      WHERE users.id = $1
      GROUP BY users.id;
    `, [session.id]);

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

export async function ranking(req, res) {
  try {
    const ranking = await db.query(`
      SELECT
        users.id, 
        users.name, 
        CAST(COUNT(urls.url) AS INTEGER) AS "linksCount",
        CAST(SUM(urls."visitCount") AS INTEGER) AS "visitCount"
      FROM users
      LEFT JOIN urls 
      ON urls."userId"= users.id
      GROUP BY users.id
      ORDER BY "visitCount" DESC
      LIMIT 10;
    `);

    res.json(ranking.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
