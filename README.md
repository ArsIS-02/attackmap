# Attack Map

Живая карта алертов Graylog — одна страница для дежурного экрана, скринкастов
и докладов. Обновление каждые 10 секунд.

## Что на странице

- **Поток алертов** — последние 60 событий, цветная рамка по приоритету
  (high/medium/low), деталь из исходного сообщения;
- **Карта источников** — «радар»: узлы — платформы и свои инструменты
  (Windows, macOS, LNX, CANARY, COWRIE...), в центре Graylog; при новом
  алерте от узла к центру бежит дуга цвета приоритета;
- **Правая колонка** — счётчики по приоритетам за 24 ч, топ-10 правил за
  24 ч, активность по источникам.

Бэкенд — Python stdlib (`http.server`), ходит в Graylog REST
(`/api/events/search`), кеш 8 секунд. Фронт — один HTML без зависимостей.

## Запуск (rootless podman, RED OS 8)

```bash
mkdir -p ~/attackmap
cp app.py index.html Containerfile ~/attackmap/
printf 'GRAYLOG_USER=admin\nGRAYLOG_PASS=***\n' > ~/attackmap/attackmap.env  # не коммитить!
chmod 600 ~/attackmap/attackmap.env
cd ~/attackmap && podman build -t localhost/attackmap:latest .
cp attackmap.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start attackmap.service
sudo firewall-cmd --permanent --add-port=8097/tcp && sudo firewall-cmd --add-port=8097/tcp
```

Страница: `http://<сервер>:8097/`.

## Грабли

- Из rootless-контейнера `https://graylog.apps.monitoring.test` недоступен
  (hairpin на LAN-адрес хоста не работает, SNI на host.containers.internal
  не совпадает) — ходим напрямую: `GRAYLOG_URL=http://host.containers.internal:9000`.
- Учётка Graylog задаётся через `GRAYLOG_USER`/`GRAYLOG_PASS` в quadlet'е —
  для боя заведите отдельного пользователя с ролью только на чтение событий.

## Настройка

| ENV | Умолчание | Назначение |
|---|---|---|
| `GRAYLOG_URL` | `http://host.containers.internal:9000` | адрес API Graylog |
| `GRAYLOG_USER` / `GRAYLOG_PASS` | admin/admin | учётка API |
| `AM_PORT` | 8097 | порт страницы |
