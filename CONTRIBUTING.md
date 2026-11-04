# 🤝 Guía de Contribución y Acuerdo de Licencia (CLA)

¡Gracias por tu interés en contribuir a **Constantine Antivirus**! Este proyecto busca proporcionar un escudo de defensa activa en kernel de estándar empresarial para el ecosistema Linux.

Para proteger tanto a la comunidad de código abierto como la viabilidad comercial y el crecimiento futuro del proyecto, todas las contribuciones están sujetas al siguiente **Acuerdo de Licencia de Colaborador (CLA)**.

---

## 📜 1. Acuerdo de Licencia de Colaborador (CLA)

Al enviar cualquier contribución (incluyendo código fuente, scripts, documentación, reglas de detección YARA, diseños o parches) mediante un *Pull Request*, *Issue* o cualquier otro medio al repositorio oficial de Constantine Antivirus (`AntonSiMal/Constantine-Antivirus-Linux`), aceptas formalmente los siguientes términos:

1. **Titularidad y Originalidad:** Declaras y garantizas que eres el autor original y único creador de la contribución presentada, o que cuentas con los derechos y autorizaciones legales suficientes para otorgar las licencias aquí descritas.
2. **Concesión de Licencia Perpetua:** Otorgas al creador y mantenedor principal del proyecto (**AntonSiMal** y sucesores legítimos) una licencia perpetua, transferible, irrevocable, de alcance mundial, libre de regalías y no exclusiva para:
   * Reproducir, modificar, adaptar, compilar y distribuir tu contribución.
   * Relicenciar la contribución bajo licencias de código abierto presentes o futuras (como GPL v3.0, AGPL v3.0 o sucesoras).
   * Relicenciar e integrar la contribución dentro de versiones comerciales propietarias, ediciones corporativas (Enterprise), licencias de fabricante de equipos originales (OEM) o en procesos de adquisición corporativa de activos tecnológicos sin restricciones de código abierto.
3. **Ausencia de Obligaciones Financieras:** Reconoces que las contribuciones se realizan de manera voluntaria y altruista en beneficio del proyecto, sin derecho a compensación económica presente o futura por su uso en versiones libres o comerciales.
4. **Protección del Modelo de Doble Licencia:** Comprendes que esta cesión de derechos garantiza que Constantine Antivirus mantenga un modelo de doble licenciamiento sostenible, evitando que disputas de propiedad intelectual fragmentadas impidan el desarrollo, la adopción industrial o acuerdos con empresas.

---

## 🛠️ 2. Normas de Calidad y Desarrollo

Para que tu Pull Request sea aprobado e integrado, debe cumplir con los siguientes estándares de calidad:

### A. Filosofía "Zero-Nag" (Cero Falsos Positivos)
* Ninguna regla de detección o sonda de kernel debe interferir, alertar o bloquear binarios legítimos de las distribuciones oficiales (`apt`, `dpkg`, Flatpak, Snap) en rutas estándar (`/usr/bin`, `/usr/lib`, `/snap`, etc.).
* La velocidad de evaluación del interceptor debe mantenerse en tiempos nativos (< 0.05 ms).

### B. Pruebas Unitarias Obligatorias
* Todo cambio en `core/engine/` o `core/auth/` debe incluir o actualizar su prueba correspondiente en el directorio `tests/`.
* Antes de enviar tu PR, asegúrate de que toda la suite de pruebas se ejecute sin errores:
  ```bash
  python3 -m unittest discover -s tests -p "test_*.py"
  ```

### C. Cumplimiento con GTK 3 & Tema Cupertino macOS
* La interfaz gráfica (`gui/app.py`) sigue estrictamente el estándar de diseño **Apple macOS Cupertino Dark Mode**.
* No uses propiedades CSS no compatibles con el motor de GTK 3 (evita `!important`, `max-width`, `letter-spacing` o sintaxis de navegadores web). Valida siempre los estilos en `assets/style.css`.
* Todo texto dinámico presentado en etiquetas con Pango Markup debe sanitizarse con `GLib.markup_escape_text()`.

---

## 🚀 3. Proceso para Enviar un Pull Request

1. Realiza un **Fork** del repositorio.
2. Crea una rama descriptiva para tu funcionalidad:
   ```bash
   git checkout -b feature/nueva-sonda-ebpf
   ```
3. Realiza tus modificaciones siguiendo las guías de estilo.
4. Ejecuta las pruebas locales:
   ```bash
   python3 -m unittest discover tests
   ```
5. Realiza el commit con un mensaje claro siguiendo el estándar *Conventional Commits*:
   ```bash
   git commit -m "feat(ebpf): agregar sonda para detección de inyección en ptrace"
   ```
6. Empuja la rama a tu fork y abre un **Pull Request** hacia la rama `main` del repositorio oficial.
