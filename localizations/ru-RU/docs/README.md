# YAML Encrypter-Decrypter (`yed`)

![Go version](https://img.shields.io/github/go-mod/go-version/atlet99/yaml-encrypter-decrypter/main?style=flat&label=go-version) [![Docker Image Version](https://img.shields.io/docker/v/zetfolder17/yaml-encrypter-decrypter?label=docker%20image&sort=semver)](https://hub.docker.com/r/zetfolder17/yaml-encrypter-decrypter) ![Docker Image Size](https://img.shields.io/docker/image-size/zetfolder17/yaml-encrypter-decrypter/latest) [![CI](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml/badge.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml) [![GitHub contributors](https://img.shields.io/github/contributors/atlet99/yaml-encrypter-decrypter)](https://github.com/atlet99/yaml-encrypter-decrypter/graphs/contributors/) [![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/yaml-encrypter-decrypter)](https://goreportcard.com/report/github.com/atlet99/yaml-encrypter-decrypter) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atlet99/yaml-encrypter-decrypter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/atlet99/yaml-encrypter-decrypter) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/atlet99/yaml-encrypter-decrypter?sort=semver)

*CLI-инструмент на Go для шифрования и дешифрования конфиденциальных данных в YAML файлах. Использует современные алгоритмы шифрования и надежную систему конфигурации для обеспечения безопасной обработки данных.*

Кросс-платформенная утилита для шифрования/дешифрования значений конфиденциальных данных в YAML файлах.

Утилита особенно актуальна для разработчиков, которые не могут использовать Hashicorp Vault или SOPS, но не хотят хранить конфиденциальные данные в Git репозитории.

## **Возможности**
- Шифрование AES-256 GCM для обеспечения конфиденциальности и целостности данных.
- Argon2 для безопасного получения ключа на основе пароля.
- HMAC для проверки целостности данных.
- Сжатие с использованием gzip для оптимизации хранения данных.
- Поддержка кросс-платформенной сборки (Linux, macOS, Windows).
- Комплексный Makefile для сборки, тестирования и запуска проекта.
- Улучшенная валидация зашифрованных данных и base64 строк.
- Улучшенная обработка ошибок и логирование.
- Комплексное тестовое покрытие с race detection.
- Бенчмарки для операций шифрования/дешифрования.

---

## **Как это работает**

### **Шифрование**
1. Предоставленный открытый текст сжимается с помощью `gzip` для уменьшения размера.
2. Генерируется случайная **соль** (32 байта) для обеспечения уникального шифрования даже с одинаковым паролем.
3. Пароль преобразуется в криптографический ключ с помощью **Argon2** с улучшенными параметрами:
   - **Память**: 256 МБ
   - **Итерации**: 4
   - **Потоки**: 8
4. Открытый текст шифруется с помощью **AES-256 GCM** (128-битный nonce, 256-битный ключ) для обеспечения конфиденциальности и целостности.
5. Вычисляется **HMAC** для проверки целостности зашифрованных данных.
6. Конечный результат объединяет соль, nonce, зашифрованные данные и HMAC.

### **Дешифрование**
1. Зашифрованные данные декодируются и разделяются на компоненты: соль, nonce, шифротекст и HMAC.
2. Пароль используется для регенерации криптографического ключа с использованием извлеченной соли.
3. HMAC пересчитывается и проверяется.
4. Шифротекст дешифруется с помощью **AES-256 GCM**.
5. Распакованные данные возвращаются как открытый текст.

---

## **Начало работы**

### **Требования**
- Установлен Go 1.24.1+.
- Установлен Make в системе.

### **Шаги**
1. Клонируйте репозиторий:
```bash
git clone https://github.com/atlet99/yaml-encrypter-decrypter.git;
cd yaml-encryptor-decryptor
```

2. Установите зависимости:
```bash
make install-deps
```

3. Соберите приложение:
```bash
make build
```

4. Запустите инструмент:
```bash
./bin/yed --help
```

## **Использование**

### **Конфигурация**

Инструмент использует файл `.yed_config.yml` для настраиваемого поведения. Разместите этот файл в рабочей директории.

**Пример `.yed_config.yml`:**
```yaml
encryption:
  key: "my-secure-key"    # ключ шифрования по умолчанию, пожалуйста, не используйте в продакшене, только YED_ENCRYPTION_KEY
  env_blocks:
    - "secure.password"
    - "secure.api_key"
    - "variable.default if sensitive = true" # если условие выполняется
    - "** if len(value) > 0" # шифровать все непустые значения
logging:
  level: "debug"           # Уровень логирования (debug, info, warn, error)
```

### **Переменная окружения**

Переопределите ключ шифрования с помощью `YED_ENCRYPTION_KEY`:
```bash
export YED_ENCRYPTION_KEY="my-super-secure-key"
```
**(!) Минимум 8 символов для пароля.**

### **Интерфейс командной строки**

*Инструмент предоставляет различные опции для шифрования и дешифрования данных:*

**Шифрование одного значения**
```bash
./bin/yed -operation=encrypt -value="MySecretData"
```

**Дешифрование одного значения**
```bash
./bin/yed -operation=decrypt -value="AES256:...encrypted_value..."
```

### **Обработка YAML файла**

**Шифрование или дешифрование определенных блоков в YAML файле:**
```bash
./bin/yed -operation=encrypt -filename="config.yaml" -env-blocks="secure.password,secure.api_key"
```

**Режим сухого прогона:**
```bash
./bin/yed -operation=encrypt -filename="config.yaml" -dry-run
```

---

**Команды Makefile**

| Команда            | Описание                                                    |
| ----------------- | -------------------------------------------------------------- |
| make build        | Сборка приложения для текущей ОС и архитектуры.     |
| make run          | Запуск приложения локально.                                   |
| make build-cross  | Сборка бинарных файлов для нескольких платформ (Linux, macOS, Windows). |
| make test         | Запуск всех тестов с race detection и покрытием.        |
| make test-coverage| Запуск тестов с отчетом о покрытии.                               |
| make test-race    | Запуск тестов с race detector.                                 |
| make test-benchmark| Запуск бенчмарков производительности.                                   |
| make test-all     | Запуск всех тестов и бенчмарков.                                 |
| make quicktest    | Быстрый запуск тестов без дополнительных проверок.                     |
| make fmt          | Проверка форматирования кода с помощью gofmt.                              |
| make vet          | Анализ кода с помощью go vet.                                     |
| make install-deps | Установка зависимостей проекта.                                  |
| make clean        | Удаление артефактов сборки.                                        |
| make help         | Отображение справки по командам Makefile.                 |

### **Сборка кросс-платформенных бинарных файлов**

*Вы можете собрать бинарные файлы для нескольких платформ с помощью:*
```bash
make build-cross
```

*Выходные бинарные файлы будут доступны в директории `bin/`:*
* bin/yed-linux-amd64
* bin/yed-darwin-arm64
* bin/yed-windows-amd64.exe

---

### **Используемые алгоритмы**

1. **AES-256 GCM:**
   * Аутентифицированное шифрование для обеспечения конфиденциальности и целостности данных.
   * Гарантирует, что зашифрованные данные не могут быть изменены.
2. **Argon2:**
   * Безопасное получение ключа на основе пароля.
   * Устойчив к атакам перебором благодаря использованию памяти.
3. **HMAC-SHA256:**
   * Проверка целостности зашифрованных данных.
4. **Сжатие Gzip:**
   * Уменьшение размера открытого текста перед шифрованием.

---

### **Измерение производительности**

**Инструмент автоматически измеряет время, затраченное на шифрование, дешифрование и обработку YAML файлов.**

*Пример:*
```bash
./bin/yed -operation=encrypt -filename=test.tf
```

*Вывод:*
```bash
YAML processing completed in 227.072083ms
File test.tf updated successfully.
```

*Режим сухого прогона:*
```bash
yed -filename test.tf --operation encrypt --dry-run
YAML processing completed in 237.009042ms
Dry-run mode enabled. The following changes would be applied:
- [6]: default = "sensitive_hidden_text"
+ [6]: default = "AES256:BVBBV2l...xxOjYyjGdloHq8bBpg=="
```

### **Лицензия**

Это проект с открытым исходным кодом под лицензией [MIT](https://github.com/atlet99/yaml-encrypter-decrypter/blob/main/LICENSE).