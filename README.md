# Balance — Equilibra tu dinero, organiza tu vida

Aplicación web (beta) que reúne en un solo panel **tareas, ingresos y gastos, metas de ahorro y Google Calendar**.

- **Demo en línea:** https://balance-nine-olive.vercel.app
- **Autor:** _(escribe aquí tu nombre completo)_
- **Curso / Universidad:** _(escribe aquí la materia y la institución)_

## Funcionalidades

- Registro e inicio de sesión de usuarios.
- Tareas con prioridad (alta, media, baja) y fecha límite.
- Ingresos y gastos por categoría, con presupuesto mensual.
- Metas de ahorro con progreso.
- Calendario con citas y sincronización bidireccional con Google Calendar.
- Copia de seguridad: exportar e importar los datos en JSON.
- Diseño adaptable a computador y celular.

## Tecnologías

| Capa | Tecnología |
|---|---|
| Interfaz | HTML, CSS y JavaScript (todo en `index.html`) |
| Base de datos y autenticación | Supabase (PostgreSQL) |
| Lógica de servidor | Edge Function de Supabase (TypeScript / Deno) |
| Integración externa | Google Calendar API (OAuth 2.0) |
| Publicación | Vercel |

> No se usa PHP: la conexión con la base de datos se hace directamente desde JavaScript con la librería `supabase-js`, y la parte de servidor (Google Calendar) está en una Edge Function.

## Estructura del proyecto

```
balance/
├── index.html                              Aplicación completa (HTML + CSS + JS)
├── og-image.png                            Imagen de vista previa al compartir el enlace
├── database/
│   └── schema.sql                          Estructura de la base de datos SQL
├── supabase/
│   └── functions/
│       └── google-calendar/
│           └── index.ts                    Edge Function (OAuth y sincronización)
└── README.md
```

## Base de datos

El archivo `database/schema.sql` contiene las tablas:

| Tabla | Para qué sirve |
|---|---|
| `profiles` | Nombre visible del usuario |
| `user_settings` | Presupuesto mensual y moneda (COP) |
| `tasks` | Tareas |
| `transactions` | Ingresos y gastos |
| `goals` | Metas de ahorro |
| `appointments` | Citas del calendario |
| `calendar_connections` | Conexión con Google Calendar (tokens cifrados) |

Todas se relacionan con `auth.users` mediante `user_id`. El archivo es una exportación de la estructura, para consulta.

## Cómo ejecutar el proyecto

### Opción rápida: usar la versión ya desplegada
Abrir https://balance-nine-olive.vercel.app y crear una cuenta.

### Opción local
1. Descomprimir el proyecto.
2. Abrir `index.html` en el navegador (o servirlo con cualquier servidor estático, por ejemplo `npx serve .`).
3. Se necesita conexión a internet: la app carga `supabase-js` y las fuentes de Google por CDN y se conecta al proyecto de Supabase configurado en `index.html`.

### Montar el backend en un proyecto propio de Supabase
1. Crear un proyecto en https://supabase.com.
2. Crear las tablas con el contenido de `database/schema.sql` (SQL Editor).
3. En `index.html`, reemplazar `SUPABASE_URL` y `SUPABASE_PUBLISHABLE_KEY` por los de tu proyecto.
4. (Opcional, solo para Google Calendar) Desplegar la función `supabase/functions/google-calendar` sin verificación JWT del gateway y definir estos secretos en Supabase:
   `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `APP_URL`, `TOKEN_ENCRYPTION_KEY`, `STATE_SIGNING_KEY`, `SUPABASE_SERVICE_ROLE_KEY`.
5. En Google Cloud, crear credenciales OAuth y registrar como URI de redirección:
   `https://<tu-proyecto>.supabase.co/functions/v1/google-calendar/callback`

## Seguridad

- La clave incluida en `index.html` es la clave **pública (publishable)** de Supabase; está pensada para usarse en el navegador.
- Las claves secretas (Google y `service_role`) **no están en el código**: viven como secretos en Supabase.
- Los tokens de Google se guardan cifrados (AES-GCM) en la base de datos.

## Notas

- La app está en versión beta y la integración con Google Calendar funciona en modo de pruebas de Google Cloud.
