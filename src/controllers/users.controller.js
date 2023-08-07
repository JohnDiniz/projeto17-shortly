import bcrypt from "bcrypt";
import { v4 as tokenGeneretor } from "uuid";
import { db } from "../database/database.connection.js";
/* Games */

export async function signUp(req, res) {
  const { name, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) return res.status(422).send(" As senhas apresentadas são diferentes. ")

  const hash = bcrypt.hashSync(password, 10);
  try {
    let usuarioPreExistente = await db.query(`SELECT * FROM users WHERE email = $1`, [email]);
    if (usuarioPreExistente.rows.length > 0) return res.status(409).send(" Esse email já está cadastrado ");

    let insert = await db.query(`
    INSERT INTO users 
      (name, email, password)
    VALUES 
      ($1, $2, $3);
    `, [name, email, hash])

    res.status(201).send("SignUp efetuado com sucesso");
  } catch (err) {
    res.status(500).send(err.message);
  }
}

export async function signIn(req, res) {
  const { email, password } = req.body;
  const token = tokenGeneretor();

  try {
    let usuario = (await db.query(`
    SELECT users.*, sessions.token
    FROM users
    LEFT JOIN sessions
    ON users.id = sessions."userId"
    WHERE users.email = $1;
    `, [email])).rows[0];

    if (!usuario) { return res.status(401).send(" O email enviado não está cadastrado. ") };

    const senhaEstaCorreta = bcrypt.compareSync(password, usuario.password);
    if (!senhaEstaCorreta) { return res.status(401).send(" A senha enviada não está correta. ") };

    if (usuario.token !== null) {
      return res.send({ token: usuario.token })
    }
    if (usuario.token === null) {
      await db.query(`INSERT INTO sessions("userId", token) VALUES($1, $2);`, [usuario.id, token]);
      return res.send({ token })
    }
    res.send(usuario);
  } catch (err) {
    res.status(500).send(err.message);
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
    `,[session.id]);

    res.send(rows[0]);
  } catch (err) {
    res.status(500).send(err.message);
  }
}

export async function ranking(req, res) {

  try {
    let ranking = await db.query(`
    SELECT
      users.id, 
      users.name, 
      CAST(COUNT(urls.url)        AS INTEGER) AS "linksCount",
      CAST(SUM(urls."visitCount") AS INTEGER) AS "visitCount"
    FROM users
      LEFT JOIN urls 
      ON urls."userId"= users.id
    GROUP BY users.id
    ORDER BY "visitCount" DESC
    LIMIT 10;
    `)

    res.send(ranking.rows);
  } catch (err) {
    res.status(500).send(err.message);
  }
}

