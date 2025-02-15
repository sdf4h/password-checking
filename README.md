# password-checking
# Проверка безопасности пароля и Генератор безопасных паролей

!Python Version
!Flask Version
!License

## Описание

Это веб-приложение на Flask, которое позволяет:

- Проверить безопасность вашего пароля.
- Узнать, был ли пароль скомпрометирован в утечках данных.
- Оценить сложность пароля и приблизительное время его взлома.
- Сгенерировать новый безопасный пароль заданной длины.

Приложение использует современные методы шифрования и хеширования для обеспечения безопасности данных пользователя.

## Особенности

- Проверка на утечки: Использование API Have I Been Pwned для проверки пароля на утечку без отправки полного пароля.
- Оценка сложности: Анализ пароля по различным критериям (длина, наличие цифр, символов, регистр) с выводом оценки в процентах.
- Оценка времени взлома: Приблизительный расчет времени, необходимого для взлома пароля методом брутфорса.
- Хеширование и шифрование: Безопасное хеширование паролей с использованием bcrypt и шифрование сгенерированных паролей с помощью Fernet (cryptography).
- Генерация паролей: Создание случайных безопасных паролей с возможностью указать длину.

### Установка
   git clone https://github.com/sdf4h/password-checking.git
   cd password-checking
   

