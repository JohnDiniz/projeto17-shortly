import { customAlphabet } from 'nanoid';
const nanoid = customAlphabet('1234567890abcdef', 10);
import { db } from "../database/database.connection.js";

/* Get Clients */

export async function urlShorten(req, res) {
  const { session } = res.locals;
  const { url } = req.body;
  let shortUrl = nanoid();

  try {
    let urlTabela = (await db.query(`
    SELECT * FROM urls WHERE url = $1;`,
      [url])).rows;

    if (urlTabela.length > 0) {
      let objeto = {
        id: urlTabela[0].id,
        shortUrl: urlTabela[0].shortUrl
      };
      return res.status(201).send(objeto);
    }

    await db.query(`
    INSERT INTO urls
      ("userId", url, "shortUrl", "visitCount")
    VALUES 
      ($1, $2, $3, $4)
    `, [session.id, url, shortUrl, 0]);

    let resposta = (await db.query(`
    SELECT id, "shortUrl" FROM urls WHERE url = $1 ORDER BY id DESC;`,
      [url])).rows[0];

    res.status(201).send(resposta);
  } catch (err) {
    res.status(500).send(err.message);
  }

};

export async function urlId(req, res) {
  const { id } = req.params;


  try {
    let existeUrl = (await db.query(`SELECT id, "shortUrl", url FROM urls WHERE id = $1;`, [id])).rows;
    if (existeUrl.length === 0) return res.status(404).send(" O Id que você está procurando não existe.")
    res.send(existeUrl[0]);
  } catch (err) {
    res.status(500).send(err.message);
  }

};

export async function urlOpen(req, res) {
  const { shortUrl } = req.params;
  let urlExiste;
  /*return res.send(shortUrl);*/

  try {
    let urltentativa = await db.query(`SELECT * FROM urls WHERE "shortUrl" = $1`, [shortUrl]);

    if (urltentativa === undefined) {
      return res.status(404).send(" Essa shortUrl não foi encontrada. ")
    } else if (urltentativa.length === 0) {
      return res.status(404).send(" Essa shortUrl não foi encontrada. ")
    } else {
      urlExiste = urltentativa.rows[0];
      if (urlExiste === undefined) { return res.status(404).send(" Essa shortUrl não foi encontrada. ") }
      let { id, visitCount } = urlExiste;
      visitCount = visitCount + 1;
      await db.query(`UPDATE urls SET "visitCount"=$1 WHERE id = $2;`, [visitCount, id]);
      return res.redirect(urlExiste.url)
    }



  } catch (err) {
    res.status(500).send(err.message);
  }

};

export async function deleteUrlId(req, res) {
  const { id } = req.params;
  const { session } = res.locals;

  try {
    let urlExiste = (await db.query(`SELECT * FROM urls WHERE id = $1;`, [id])).rows;

    if (urlExiste.length === 0) return res.status(404).send("Este id não pertence à nenhuma shortUrl.");
    if (urlExiste[0].userId !== session.id) return res.status(401).send("Este shortUrl não pertence à este usuario.");

    await db.query(`DELETE FROM urls WHERE id = $1;`, [id]);

    res.status(204).send("shortUrl apagada.");
  } catch (err) {
    res.status(500).send(err.message);
  }

};