# Ideas for Firewall Project Enhancements

## 1. Security Enhancements
- [ ] **CSRF Protection**: Implement `Flask-WTF` to protect forms against Cross-Site Request Forgery.
- [ ] **Rate Limiting**: Add `Flask-Limiter` to prevent brute-force attacks on the login page.
- [ ] **Persistent Secret Key**: Move `app.secret_key` to an environment variable (`.env`) so user sessions persist across server restarts.
- [ ] **Audit Logging**: Record who changed what rule and when (e.g., "User 'admin' deleted rule #5 at 2023-10-27 10:00").
- [ ] **Two-Factor Authentication (2FA)**: Add TOTP support (Google Authenticator) for login.

## 2. New Features
- [ ] **Service Presets**: Quick buttons to "Allow Web (80/443)", "Allow SSH (22)", "Allow Mail", etc.
- [ ] **GeoIP Blocking**: Feature to block or allow traffic based on country codes (requires a GeoIP database).
- [ ] **Traffic Visualization**: Dashboard with charts showing accepted vs. dropped packets over time (parsing iptables counters).
- [ ] **Time-Based Rules**: Support for iptables time module (e.g., "Allow SSH only between 9 AM and 5 PM").
- [ ] **Rule Reordering**: specific iptables rules are sensitive to order. Add "Move Up" / "Move Down" buttons or drag-and-drop in the UI.
- [ ] **System Dashboard**: Show CPU, RAM, and Network interface load on the main page.

## 3. Code Quality & Testing
- [ ] **Standardized Testing**: Convert `test_validation.py` to use `pytest`.
- [ ] **Coverage**: Add tests for rule validation, backup logic, and authentication.
- [ ] **Linting**: Add `flake8` or `pylint` configuration to ensure code style consistency.
- [ ] **Type Hinting**: Add Python type hints to `app.py` for better developer experience.

## 4. DevOps & Deployment
- [ ] **Docker Compose**: Create a `docker-compose.yml` file for one-command deployment.
- [ ] **Environment Configuration**: Use `python-dotenv` to manage configuration (ports, file paths) instead of hardcoding.
- [ ] **CI Pipeline**: Add a GitHub Actions workflow to run tests and linting on push.

## 5. UI/UX Improvements
- [ ] **Real-time Monitoring**: Use HTMX or WebSockets to update the "Active Connections" page without full reloads.
- [ ] **Dark Mode**: Add a theme toggler.
- [ ] **Search/Filter**: Allow users to filter rules by IP, Protocol, or Chain in the rules table.
