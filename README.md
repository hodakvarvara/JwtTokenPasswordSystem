Парольная система, где аутентификация и авторизация реализованы с использованием двух JWT токенов. Первый токен необходим для авторизации, второй - для обновления пары токенов: токен доступа (Access token) и токен обновления (Refresh token). Пароль в бд хранится в зашифрованом виде (хеш + соль).
