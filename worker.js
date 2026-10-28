/**
 * Fink Business - Cloudflare Worker
 *
 * Funciones:
 * - Subir imágenes a Cloudflare R2
 * - Eliminar imágenes de R2
 * - Controlar máximo de 7 fotos por tienda
 * - Recuperación de contraseña por WhatsApp + PIN
 * - Acceso administrativo a Firestore y Firebase Auth
 */

const ALLOWED_ORIGIN = "https://kreadu.github.io";

const MAX_STORE_PHOTOS = 7;

const PUBLIC_BUCKET_BASE =
  "https://pub-00bbbb66c4b646c0b33f9ecee959b51a.r2.dev/";

/* =========================================================
   CORS
========================================================= */

function corsHeaders(extra = {}) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    ...extra,
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders({
      "Content-Type": "application/json",
    }),
  });
}

/* =========================================================
   ENTRY POINT
========================================================= */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(),
      });
    }

    if (request.method !== "POST") {
      return new Response("Método no permitido", {
        status: 405,
        headers: corsHeaders(),
      });
    }

    try {
      const formData = await request.formData();

      const action = formData.get("action") || "upload";

      /*
       * Validación temprana de variables de entorno.
       */

      const missingVars = [
        "FIREBASE_PROJECT_ID",
        "FIREBASE_CLIENT_EMAIL",
        "FIREBASE_PRIVATE_KEY",
      ].filter((name) => !env[name]);

      if (missingVars.length) {
        return jsonResponse(
          {
            error:
              `Falta configurar en Cloudflare la(s) variable(s): ` +
              `${missingVars.join(", ")}`,
          },
          500
        );
      }

      /*
       * Eliminar imagen
       */

      if (action === "delete") {
        return await handleDelete(formData, env);
      }

      /*
       * Recuperar contraseña
       */

      if (action === "recoverPassword") {
        return await handleRecoverPassword(formData, env);
      }

      /*
       * Por defecto: subir imagen
       */

      return await handleUpload(formData, env);
    } catch (err) {
      console.error(err);

      return jsonResponse(
        {
          error: err.message || "Error interno del servidor",
        },
        500
      );
    }
  },
};

/* =========================================================
   SUBIR IMAGEN
========================================================= */

async function handleUpload(formData, env) {
  const file = formData.get("file");
  const storeId = formData.get("storeId");

  if (!file) {
    return jsonResponse(
      {
        error: "Falta el archivo",
      },
      400
    );
  }

  if (!storeId) {
    return jsonResponse(
      {
        error: "Falta el identificador de la tienda",
      },
      400
    );
  }

  /*
   * 1. Autenticarse contra Google/Firebase
   * y reservar el cupo de foto.
   */

  const accessToken = await getGoogleAccessToken(env);

  const reservation = await reservePhotoSlot(
    env,
    accessToken,
    storeId
  );

  if (!reservation.ok) {
    return jsonResponse(
      {
        error: reservation.error,
      },
      403
    );
  }

  /*
   * 2. Subir el archivo a R2.
   */

  const key = `${Date.now()}_${file.name}`;

  try {
    await env.PHOTOS_BUCKET.put(
      key,
      file.stream(),
      {
        httpMetadata: {
          contentType: file.type,
        },
      }
    );
  } catch (uploadErr) {
    /*
     * Si falla la subida, devolvemos
     * el cupo reservado.
     */

    await decrementPhotoCounter(
      env,
      accessToken,
      storeId
    ).catch(() => {});

    throw uploadErr;
  }

  const publicUrl =
    `${PUBLIC_BUCKET_BASE}${key}`;

  return jsonResponse(
    {
      url: publicUrl,
    },
    200
  );
}

/* =========================================================
   ELIMINAR IMAGEN
========================================================= */

async function handleDelete(formData, env) {
  const storeId = formData.get("storeId");
  const url = formData.get("url");

  if (!storeId) {
    return jsonResponse(
      {
        error: "Falta el identificador de la tienda",
      },
      400
    );
  }

  if (!url) {
    return jsonResponse(
      {
        error: "Falta la URL de la imagen",
      },
      400
    );
  }

  /*
   * Si la URL no pertenece a nuestro bucket,
   * no hay nada que borrar ni descontar.
   */

  if (!url.startsWith(PUBLIC_BUCKET_BASE)) {
    return jsonResponse({
      ok: true,
      skipped: true,
    });
  }

  const key = url.slice(
    PUBLIC_BUCKET_BASE.length
  );

  const accessToken =
    await getGoogleAccessToken(env);

  try {
    await env.PHOTOS_BUCKET.delete(key);
  } catch (err) {
    throw new Error(
      "No se pudo borrar el archivo de R2: " +
      err.message
    );
  }

  await decrementPhotoCounter(
    env,
    accessToken,
    storeId
  ).catch(() => {});

  return jsonResponse({
    ok: true,
  });
}

/* =========================================================
   RECUPERACIÓN DE CONTRASEÑA POR WHATSAPP + PIN
========================================================= */

async function handleRecoverPassword(formData, env) {
  /*
   * 1. Obtener y normalizar WhatsApp + PIN.
   *
   * El PIN es obligatorio: sin él, cualquiera que conozca el
   * WhatsApp público de la tienda (los clientes lo ven al hacer
   * un pedido) podría recuperar el acceso y tomar la tienda.
   */

  const whatsappRaw =
    formData.get("whatsapp") || "";

  const whatsapp =
    String(whatsappRaw).replace(/\D/g, "");

  if (!whatsapp) {
    return jsonResponse(
      {
        error: "Falta el número de WhatsApp",
      },
      400
    );
  }

  const pinRaw = formData.get("pin") || "";
  const pin = String(pinRaw).trim();

  if (!/^[0-9]{4,6}$/.test(pin)) {
    return jsonResponse(
      {
        error: "Ingresa el PIN de recuperación (4 a 6 dígitos).",
      },
      400
    );
  }

  /*
   * 2. Obtener token administrativo.
   */

  const accessToken =
    await getGoogleAccessToken(env);

  /*
   * 3. Buscar la tienda por WhatsApp.
   */

  const storeDoc =
    await firestoreQueryOne(
      env,
      accessToken,
      "stores",
      "whatsapp",
      whatsapp
    );

  if (!storeDoc) {
    return jsonResponse(
      {
        error:
          "No encontramos ninguna tienda registrada con ese número de WhatsApp.",
      },
      404
    );
  }

  /*
   * ID real de la tienda.
   */

  const storeId =
    docIdFromName(storeDoc.name);

  /*
   * 4. Obtener el UID REAL de Firebase Auth.
   *
   * Las tiendas nuevas creadas desde tu aplicación
   * guardan:
   *
   * ownerUid: cred.user.uid
   */

  let ownerUid =
    getStringField(
      storeDoc,
      "ownerUid"
    ) || "";

  /*
   * 5. Buscar el administrador asociado.
   */

  const adminDoc =
    await firestoreQueryOne(
      env,
      accessToken,
      "admins",
      "storeId",
      storeId
    );

  if (!adminDoc) {
    return jsonResponse(
      {
        error:
          "Esa tienda no tiene un usuario administrador asociado. Contáctanos por soporte.",
      },
      404
    );
  }

  /*
   * 6. Obtener username.
   */

  const username =
    getStringField(
      adminDoc,
      "username"
    ) || "";

  if (!username) {
    return jsonResponse(
      {
        error:
          "No se encontró el usuario administrador de la tienda.",
      },
      500
    );
  }

  /*
   * 6.5. Verificar el PIN de recuperación.
   *
   * El PIN se guarda hasheado (SHA-256 de "pin:uid") en
   * admins/{uid}.pinHash, y nunca se expone al cliente en texto
   * plano. El UID que se usa para el hash es siempre el ID del
   * documento admins/{uid} (igual al UID de Firebase Auth con el
   * que se creó la cuenta).
   */

  const adminUid =
    docIdFromName(adminDoc.name);

  const storedPinHash =
    getStringField(
      adminDoc,
      "pinHash"
    ) || "";

  if (!storedPinHash) {
    return jsonResponse(
      {
        error:
          "Esta cuenta todavía no tiene un PIN de recuperación configurado. Inicia sesión con tu contraseña actual: te pediremos que lo configures automáticamente.",
      },
      403
    );
  }

  const submittedPinHash =
    await sha256Hex(`${pin}:${adminUid}`);

  if (submittedPinHash !== storedPinHash) {
    return jsonResponse(
      {
        error: "El WhatsApp o el PIN no coinciden.",
      },
      403
    );
  }

  /*
   * 7. Compatibilidad con tiendas antiguas.
   *
   * Si la tienda no tiene ownerUid, usamos como
   * respaldo el ID del documento admins/{uid}.
   *
   * En tu estructura actual el ID de admins es
   * precisamente el UID de Firebase Auth.
   */

  if (!ownerUid) {
    ownerUid = adminUid;
  }

  if (!ownerUid) {
    return jsonResponse(
      {
        error:
          "No se pudo determinar el usuario de Firebase Auth asociado a esta tienda.",
      },
      500
    );
  }

  /*
   * 8. Generar contraseña temporal.
   */

  const tempPassword =
    generateTempPassword();

  /*
   * 9. ACTUALIZAR LA CONTRASEÑA REALMENTE
   *    EN FIREBASE AUTH.
   *
   * IMPORTANTE:
   *
   * Usamos el endpoint administrativo:
   *
   * POST
   * /v1/projects/{projectId}/accounts:update
   *
   * No usamos:
   *
   * /v1/accounts:update
   *
   * porque ese endpoint no es el apropiado
   * para esta operación administrativa.
   */

  const authUrl =
    `https://identitytoolkit.googleapis.com/v1/projects/` +
    `${encodeURIComponent(env.FIREBASE_PROJECT_ID)}` +
    `/accounts:update`;

  const updateRes =
    await fetch(authUrl, {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${accessToken}`,

        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        localId: ownerUid,
        password: tempPassword,
        returnSecureToken: false,
      }),
    });

  const updateText =
    await updateRes.text();

  /*
   * 10. Comprobar respuesta de Firebase Auth.
   */

  if (!updateRes.ok) {
    console.error(
      "Firebase Auth update error:",
      updateRes.status,
      updateText
    );

    let message = updateText;

    try {
      const parsed =
        JSON.parse(updateText);

      if (parsed.error?.message) {
        message =
          parsed.error.message;
      }
    } catch (_) {}

    return jsonResponse(
      {
        error:
          "No se pudo restablecer la contraseña en Firebase Auth: " +
          message,
      },
      500
    );
  }

  /*
   * 11. Todo salió correctamente.
   *
   * El frontend actual ya espera exactamente:
   *
   * username
   * tempPassword
   */

  return jsonResponse(
    {
      ok: true,
      username,
      tempPassword,
    },
    200
  );
}

/* =========================================================
   GENERAR CONTRASEÑA TEMPORAL
========================================================= */

function generateTempPassword() {
  /*
   * Sin caracteres ambiguos:
   * 0/O
   * 1/l/I
   */

  const chars =
    "ABCDEFGHJKMNPQRSTUVWXYZ" +
    "abcdefghijkmnpqrstuvwxyz" +
    "23456789";

  const bytes =
    new Uint8Array(10);

  crypto.getRandomValues(bytes);

  let pass = "";

  for (
    let i = 0;
    i < bytes.length;
    i++
  ) {
    pass +=
      chars[bytes[i] % chars.length];
  }

  return pass;
}

/* =========================================================
   HASH SHA-256 (para el PIN de recuperación)
========================================================= */

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/* =========================================================
   FIRESTORE
========================================================= */

function firestoreDocName(
  env,
  storeId
) {
  return (
    `projects/${env.FIREBASE_PROJECT_ID}` +
    `/databases/(default)` +
    `/documents/stores/${storeId}`
  );
}

function docIdFromName(name) {
  return name.split("/").pop();
}

function getStringField(
  doc,
  fieldPath
) {
  return (
    doc.fields &&
    doc.fields[fieldPath] &&
    doc.fields[fieldPath].stringValue
  );
}

/*
 * Busca un único documento en una colección
 * donde fieldPath == value.
 */

async function firestoreQueryOne(
  env,
  accessToken,
  collectionId,
  fieldPath,
  value
) {
  const url =
    `https://firestore.googleapis.com/v1/` +
    `projects/${env.FIREBASE_PROJECT_ID}` +
    `/databases/(default)` +
    `/documents:runQuery`;

  const res =
    await fetch(url, {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${accessToken}`,

        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        structuredQuery: {
          from: [
            {
              collectionId,
            },
          ],

          where: {
            fieldFilter: {
              field: {
                fieldPath,
              },

              op: "EQUAL",

              value: {
                stringValue: value,
              },
            },
          },

          limit: 1,
        },
      }),
    });

  if (!res.ok) {
    const errText =
      await res.text().catch(
        () => ""
      );

    throw new Error(
      `No se pudo consultar la colección "${collectionId}": ${errText}`
    );
  }

  const rows =
    await res.json();

  const match =
    Array.isArray(rows)
      ? rows.find(
          (r) => r.document
        )
      : null;

  return match
    ? match.document
    : null;
}

/* =========================================================
   RESERVAR CUPO DE FOTO
========================================================= */

async function reservePhotoSlot(
  env,
  accessToken,
  storeId,
  attempt = 0
) {
  const docName =
    firestoreDocName(
      env,
      storeId
    );

  const getRes =
    await fetch(
      `https://firestore.googleapis.com/v1/${docName}`,
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
        },
      }
    );

  if (
    !getRes.ok &&
    getRes.status !== 404
  ) {
    throw new Error(
      "No se pudo leer la información de la tienda"
    );
  }

  let current = 0;
  let updateTime = null;

  if (getRes.ok) {
    const doc =
      await getRes.json();

    current = Number(
      (
        doc.fields &&
        doc.fields.photosUploaded &&
        doc.fields.photosUploaded
          .integerValue
      ) || 0
    );

    updateTime =
      doc.updateTime;
  }

  if (
    current >=
    MAX_STORE_PHOTOS
  ) {
    return {
      ok: false,

      error:
        `Límite alcanzado: esta tienda ya subió ` +
        `el máximo de ${MAX_STORE_PHOTOS} fotos permitidas.`,
    };
  }

  const commitUrl =
    `https://firestore.googleapis.com/v1/` +
    `projects/${env.FIREBASE_PROJECT_ID}` +
    `/databases/(default)/documents:commit`;

  const commitRes =
    await fetch(
      commitUrl,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          writes: [
            {
              update: {
                name: docName,

                fields: {
                  photosUploaded: {
                    integerValue:
                      String(
                        current + 1
                      ),
                  },
                },
              },

              updateMask: {
                fieldPaths: [
                  "photosUploaded",
                ],
              },

              currentDocument:
                updateTime
                  ? {
                      updateTime,
                    }
                  : {
                      exists: false,
                    },
            },
          ],
        }),
      }
    );

  if (commitRes.ok) {
    return {
      ok: true,
      count: current + 1,
    };
  }

  /*
   * Otra subida modificó el documento
   * justo antes de nosotros.
   */

  if (
    commitRes.status === 409 &&
    attempt < 3
  ) {
    return reservePhotoSlot(
      env,
      accessToken,
      storeId,
      attempt + 1
    );
  }

  const errBody =
    await commitRes.text()
      .catch(() => "");

  throw new Error(
    "No se pudo actualizar el contador de fotos de la tienda: " +
    errBody
  );
}

/* =========================================================
   DISMINUIR CONTADOR DE FOTOS
========================================================= */

async function decrementPhotoCounter(
  env,
  accessToken,
  storeId,
  attempt = 0
) {
  const docName =
    firestoreDocName(
      env,
      storeId
    );

  const getRes =
    await fetch(
      `https://firestore.googleapis.com/v1/${docName}`,
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
        },
      }
    );

  if (!getRes.ok) {
    return;
  }

  const doc =
    await getRes.json();

  const current =
    Number(
      (
        doc.fields &&
        doc.fields.photosUploaded &&
        doc.fields.photosUploaded
          .integerValue
      ) || 0
    );

  if (current <= 0) {
    return;
  }

  const commitUrl =
    `https://firestore.googleapis.com/v1/` +
    `projects/${env.FIREBASE_PROJECT_ID}` +
    `/databases/(default)/documents:commit`;

  const commitRes =
    await fetch(
      commitUrl,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          writes: [
            {
              update: {
                name: docName,

                fields: {
                  photosUploaded: {
                    integerValue:
                      String(
                        current - 1
                      ),
                  },
                },
              },

              updateMask: {
                fieldPaths: [
                  "photosUploaded",
                ],
              },

              currentDocument: {
                updateTime:
                  doc.updateTime,
              },
            },
          ],
        }),
      }
    );

  if (
    !commitRes.ok &&
    commitRes.status === 409 &&
    attempt < 3
  ) {
    return decrementPhotoCounter(
      env,
      accessToken,
      storeId,
      attempt + 1
    );
  }
}

/* =========================================================
   AUTENTICACIÓN GOOGLE
   CUENTA DE SERVICIO
========================================================= */

let cachedToken = null;

async function getGoogleAccessToken(
  env
) {
  /*
   * Reutilizar token mientras siga vigente.
   */

  if (
    cachedToken &&
    cachedToken.expiresAt >
      Date.now() + 30000
  ) {
    return cachedToken.token;
  }

  const nowSec =
    Math.floor(
      Date.now() / 1000
    );

  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  const claims = {
    iss: env.FIREBASE_CLIENT_EMAIL,

    /*
     * datastore:
     * leer/escribir Firestore
     *
     * identitytoolkit:
     * administrar Firebase Authentication
     */

    scope:
      "https://www.googleapis.com/auth/datastore " +
      "https://www.googleapis.com/auth/identitytoolkit",

    aud:
      "https://oauth2.googleapis.com/token",

    iat: nowSec,

    exp:
      nowSec + 3600,
  };

  const jwt =
    await signJwt(
      header,
      claims,
      env.FIREBASE_PRIVATE_KEY
    );

  const res =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },

        body: new URLSearchParams({
          grant_type:
            "urn:ietf:params:oauth:grant-type:jwt-bearer",

          assertion: jwt,
        }),
      }
    );

  if (!res.ok) {
    const t =
      await res.text()
        .catch(() => "");

    throw new Error(
      "No se pudo autenticar con Firebase: " +
      t
    );
  }

  const data =
    await res.json();

  cachedToken = {
    token: data.access_token,

    expiresAt:
      Date.now() +
      data.expires_in * 1000,
  };

  return data.access_token;
}

/* =========================================================
   FIRMAR JWT
========================================================= */

async function signJwt(
  header,
  claims,
  privateKeyPem
) {
  const encoder =
    new TextEncoder();

  const b64url = (str) =>
    btoa(str)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  const headerB64 =
    b64url(
      JSON.stringify(header)
    );

  const claimsB64 =
    b64url(
      JSON.stringify(claims)
    );

  const unsigned =
    `${headerB64}.${claimsB64}`;

  const key =
    await crypto.subtle.importKey(
      "pkcs8",

      pemToArrayBuffer(
        privateKeyPem
      ),

      {
        name:
          "RSASSA-PKCS1-v1_5",

        hash: "SHA-256",
      },

      false,

      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",

      key,

      encoder.encode(unsigned)
    );

  const signatureB64 =
    btoa(
      String.fromCharCode(
        ...new Uint8Array(
          signature
        )
      )
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  return (
    `${unsigned}.${signatureB64}`
  );
}

/* =========================================================
   CONVERTIR PRIVATE KEY PEM
========================================================= */

function pemToArrayBuffer(
  pem
) {
  const normalized =
    pem.replace(
      /\\n/g,
      "\n"
    );

  const b64 =
    normalized
      .replace(
        "-----BEGIN PRIVATE KEY-----",
        ""
      )
      .replace(
        "-----END PRIVATE KEY-----",
        ""
      )
      .replace(
        /\s/g,
        ""
      );

  const binary =
    atob(b64);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes.buffer;
}
