# YAML Encrypter-Decrypter (`yed`)

![Go version](https://img.shields.io/github/go-mod/go-version/atlet99/yaml-encrypter-decrypter/main?style=flat&label=go-version) [![Docker Image Version](https://img.shields.io/docker/v/zetfolder17/yaml-encrypter-decrypter?label=docker%20image&sort=semver)](https://hub.docker.com/r/zetfolder17/yaml-encrypter-decrypter) ![Docker Image Size](https://img.shields.io/docker/image-size/zetfolder17/yaml-encrypter-decrypter/latest) [![CI](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml/badge.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml) [![GitHub contributors](https://img.shields.io/github/contributors/atlet99/yaml-encrypter-decrypter)](https://github.com/atlet99/yaml-encrypter-decrypter/graphs/contributors/) [![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/yaml-encrypter-decrypter)](https://goreportcard.com/report/github.com/atlet99/yaml-encrypter-decrypter) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atlet99/yaml-encrypter-decrypter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/atlet99/yaml-encrypter-decrypter) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/atlet99/yaml-encrypter-decrypter?sort=semver)

*CLI-инструмент на Go для шифрования и дешифрования конфиденциальных данных в YAML файлах. Использует современные алгоритмы шифрования и надежную систему конфигурации для обеспечения безопасной обработки данных.*

Кросс-платформенная утилита для шифрования/дешифрования значений конфиденциальных данных в YAML файлах.

Утилита особенно актуальна для разработчиков, которые не могут использовать Hashicorp Vault или SOPS, но не хотят хранить конфиденциальные данные в Git репозитории.

## **Возможности**
- Шифрование AES-256 GCM для обеспечения конфиденциальности и целостности данных.
- Несколько алгоритмов формирования ключа:
  - Argon2id (по умолчанию) с параметрами, рекомендованными OWASP
  - PBKDF2-SHA256 (совместимый с NIST/FIPS) с 600,000 итераций
  - PBKDF2-SHA512 (совместимый с NIST/FIPS) с 210,000 итераций
- Безопасная обработка памяти с использованием memguard для защиты конфиденциальных данных в памяти.
- HMAC для проверки целостности данных.
- Сжатие с использованием gzip для оптимизации хранения данных.
- Поддержка кросс-платформенной сборки (Linux, macOS, Windows).
- Комплексный Makefile для сборки, тестирования и запуска проекта.
- Улучшенная валидация зашифрованных данных и base64 строк.
- Улучшенная обработка ошибок и расширенное логирование отладки.
- Комплексное тестовое покрытие с race detection.
- Бенчмарки для операций шифрования/дешифрования.

## **Результаты тестирования производительности**

Производительность различных алгоритмов формирования ключа была тщательно протестирована, чтобы помочь вам сделать обоснованный выбор в зависимости от ваших требований безопасности и производительности.

### **Сравнение алгоритмов формирования ключа**

| Алгоритм | Операций/сек | Время (нс/оп) | Память (Б/оп) | Аллокаций/оп |
|-----------|----------------|--------------|---------------|-----------|
| Argon2id | 60 | 18,363,235 | 9,442,344 | 49 |
| PBKDF2-SHA256 | 10,000 | 107,746 | 804 | 11 |
| PBKDF2-SHA512 | 4,830 | 236,775 | 1,380 | 11 |

**Ключевые выводы:**
- **PBKDF2-SHA256** примерно в **170 раз быстрее**, чем Argon2id
- **PBKDF2-SHA512** примерно в **78 раз быстрее**, чем Argon2id
- Оба варианта PBKDF2 используют значительно меньше памяти, чем Argon2id
- Алгоритмы PBKDF2 настроены с достаточным количеством итераций для обеспечения эквивалентной безопасности

### **Сравнение конфигураций Argon2**

| Конфигурация | Операций/сек | Время (нс/оп) | Память (Б/оп) | Аллокаций/оп |
|--------------|----------------|--------------|---------------|-----------|
| OWASP-1-текущая | 67 | 17,818,289 | 9,442,306 | 48 |
| OWASP-2 | 70 | 17,125,754 | 7,345,429 | 56 |
| OWASP-3 | 67 | 17,846,443 | 12,587,776 | 40 |
| Предыдущая-конфигурация | 8 | 138,691,224 | 268,457,400 | 198 |

**Ключевые улучшения:**
- Текущая конфигурация, рекомендованная OWASP, примерно в **8 раз быстрее** предыдущей конфигурации
- Использование памяти уменьшено примерно в **27 раз** при сохранении безопасности
- Все конфигурации, рекомендованные OWASP, обеспечивают сходную производительность с разными компромиссами по памяти/итерациям

### **Базовая производительность шифрования и дешифрования**

| Операция | Операций/сек | Время (нс/оп) | Память (Б/оп) | Аллокаций/оп |
|-----------|----------------|--------------|---------------|-----------|
| Шифрование | 66 | 17,791,645 | 10,260,991 | 88 |
| Дешифрование | 67 | 19,369,065 | 9,490,663 | 71 |

### **Шифрование с разными алгоритмами**

| Алгоритм | Операций/сек | Время (нс/оп) | Память (Б/оп) | Аллокаций/оп |
|-----------|----------------|--------------|---------------|-----------|
| argon2id | 61 | 19,897,308 | 10,259,454 | 89 |
| pbkdf2-sha256 | 6,548 | 191,538 | 817,917 | 51 |
| pbkdf2-sha512 | 3,604 | 340,094 | 818,493 | 51 |

### **Дешифрование с разными алгоритмами**

| Алгоритм | Операций/сек | Время (нс/оп) | Память (Б/оп) | Аллокаций/оп |
|-----------|----------------|--------------|---------------|-----------|
| argon2id | 61 | 20,304,921 | 9,486,333 | 68 |
| pbkdf2-sha256 | 7,838 | 160,589 | 44,796 | 30 |
| pbkdf2-sha512 | 3,909 | 313,596 | 45,372 | 30 |

**Примечание:** Эти тесты производительности были выполнены на процессоре Apple M3 Pro. Производительность может различаться в зависимости от оборудования.

Вы можете сгенерировать отчеты по производительности для вашей системы с помощью:
```bash
make benchmark-report
```

---

## **Как это работает**

### **Шифрование**
1. Предоставленный открытый текст сжимается с помощью `gzip` для уменьшения размера.
2. Генерируется случайная **соль** (32 байта) для обеспечения уникальности шифрования даже при одинаковом пароле.
3. Пароль преобразуется в криптографический ключ с помощью одного из следующих алгоритмов:
   - **Argon2id** (по умолчанию, рекомендации OWASP):
     - **Память**: 9 МБ (9216 KiБ)
     - **Итерации**: 4
     - **Потоки**: 1
   - **PBKDF2-SHA256** (опционально, совместимо с NIST/FIPS):
     - **Итерации**: 600,000
   - **PBKDF2-SHA512** (опционально, совместимо с NIST/FIPS):
     - **Итерации**: 210,000
4. Открытый текст шифруется с помощью **AES-256 GCM** (128-битный nonce, 256-битный ключ) для обеспечения конфиденциальности и целостности.
5. Вычисляется **HMAC** для проверки целостности зашифрованных данных.
6. Конечный результат объединяет соль, nonce, зашифрованные данные и HMAC.

### **Безопасная обработка памяти**
Инструмент реализует надежные меры безопасности памяти для защиты конфиденциальных данных:

1. **Защищенные буферы памяти**: Использует memguard для создания защищенных анклавов памяти для конфиденциальных данных.
2. **Защита памяти**: Память, содержащая конфиденциальные данные, защищена от выгрузки на диск.
3. **Автоматическая очистка**: Все защищенные буферы автоматически уничтожаются после использования.
4. **Обработка сигналов**: Правильно обрабатывает сигналы прерывания, чтобы гарантировать удаление конфиденциальных данных из памяти.
5. **Жизненный цикл буфера**: Управление жизненным циклом буфера с явными вызовами уничтожения для предотвращения утечек памяти.

### **Алгоритмы формирования ключа**
Выберите один из нескольких алгоритмов формирования ключа с помощью флага `--algorithm`:
```bash
./bin/yed --file config.yaml --key="my-secure-key" --operation encrypt --algorithm argon2id
```

Доступные алгоритмы:
- `argon2id` (по умолчанию): Алгоритм с высокими требованиями к памяти, с параметрами, рекомендованными OWASP
- `pbkdf2-sha256`: Совместимый с NIST/FIPS, с 600,000 итераций
- `pbkdf2-sha512`: Совместимый с NIST/FIPS, с 210,000 итераций (обеспечивает наилучший баланс безопасности и производительности)

### **Улучшения режима отладки**
Улучшенный режим отладки предоставляет подробную информацию о процессе шифрования/дешифрования:

```bash
./bin/yed --file config.yaml --key="my-secure-key" --operation encrypt --debug
```

Вывод отладки теперь включает:
- Определение алгоритма для каждого зашифрованного значения
- Информацию о пути к полю для лучшего контекста
- Длину зашифрованных данных
- Улучшенное маскирование конфиденциальных значений

Пример вывода отладки:
```
[DEBUG] Masking encrypted value for field 'smart_config.auth.username' (length: 184, algo: argon2id)
```

Это помогает в устранении неполадок и понимании процесса шифрования без ущерба для безопасности.

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

**Пример `.yed_config.yml**:**
```yaml
encryption:
  rules:
    - name: "skip_axel_fix"
      block: "axel.fix"
      pattern: "**"
      action: "none"
      description: "Пропустить шифрование для всех значений в блоке axel.fix"
    
    - name: "encrypt_smart_config"
      block: "smart_config"
      pattern: "**"
      description: "Шифровать все значения в блоке smart_config"
    
    - name: "encrypt_passwords"
      block: "*"
      pattern: "pass*"
      description: "Шифровать все поля пароля глобально"
  
  unsecure_diff: false  # Установите true, чтобы показывать фактические значения в режиме diff
```

### **Конфигурация правил**

Правила в `.yed_config.yml` определяют, какие части вашего YAML-файла должны быть зашифрованы или пропущены. Каждое правило состоит из:

- `name`: Уникальный идентификатор правила
- `block`: YAML-блок, к которому применяется правило (например, "smart_config" или "*" для любого блока)
- `pattern`: Шаблон для сопоставления полей внутри блока (например, "**" для всех полей, "pass*" для полей, начинающихся с "pass")
- `action`: Необязательно. Используйте "none", чтобы пропустить шифрование для совпадающих путей
- `description`: Понятное человеку описание назначения правила

**Важные детали обработки правил:**

1. **Порядок приоритета**: Правила с `action: none` обрабатываются в первую очередь, чтобы гарантировать, что пути правильно исключены из шифрования.
2. **Рекурсивное исключение**: Когда путь соответствует правилу с `action: none`, все его вложенные пути также исключаются из шифрования.
3. **Сопоставление шаблонов**:
   - `**` соответствует любому количеству вложенных полей
   - `*` соответствует любым символам в пределах одного имени поля
   - Точные совпадения имеют приоритет над шаблонами

**Примеры применения правил:**

```yaml
# Пример структуры YAML
smart_config:
  auth:
    username: "admin"
    password: "secret123"
axel:
  fix:
    name: "test"
    password: "test123"
```

С правилами из примера выше:
- Все поля в `smart_config` будут зашифрованы
- Все поля в `axel.fix` будут пропущены (не зашифрованы)
- Любое поле, соответствующее `pass*` в других блоках, будет зашифровано

### **Переменная окружения**

Переопределите ключ шифрования с помощью `YED_ENCRYPTION_KEY`:
```bash
export YED_ENCRYPTION_KEY="my-super-secure-key"
```
**Требования к паролю:**
- **Минимум**: 8 символов
- **Максимум**: 64 символа (поддерживает парольные фразы)
- **Рекомендация**: Используйте сочетание прописных, строчных букв, цифр и специальных символов
- **Избегайте**: Общеизвестные пароли будут отклонены в целях безопасности

### **Интерфейс командной строки**

*Инструмент предоставляет различные опции для шифрования и дешифрования данных:*

**Шифрование одного значения**
```bash
./bin/yed --operation encrypt --value="MySecretData" --key="my-super-secure-key"
```

**Дешифрование одного значения**
```bash
./bin/yed --operation decrypt --value="AES256:...encrypted_value..." --key="my-super-secure-key"
```

### **Обработка YAML файла**

**Шифрование или дешифрование YAML файла:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt
```

**Режим сухого прогона с diff:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt --dry-run --diff
```

Это покажет предварительный просмотр изменений, которые будут внесены в YAML-файл, включая номера строк для более легкой идентификации:
```
smart_config.auth.username:
  [3] - admin
  [3] + AES256:gt1***A==
smart_config.auth.password:
  [4] - SecRet@osd49
  [4] + AES256:V24***xQ=
```

**Режим отладки:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt --debug
```

---

### **Команды Makefile**

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
2. **Argon2id:**
   * Безопасное получение ключа на основе пароля, победитель конкурса Password Hashing Competition 2015 года.
   * Настроено в соответствии с рекомендациями OWASP для оптимального баланса безопасности и производительности.
   * Требует значительного объема памяти для противостояния атакам перебором, особенно на основе GPU.
3. **HMAC-SHA256:**
   * Проверка целостности зашифрованных данных.
4. **Сжатие Gzip:**
   * Уменьшение размера открытого текста перед шифрованием.

---

### **Измерение производительности**

**Инструмент автоматически измеряет время, затраченное на шифрование, дешифрование и обработку YAML файлов.**

*Пример:*
```bash
./bin/yed --file test.yml --key="my-super-secure-key" --operation encrypt
```

*Вывод:*
```bash
YAML processing completed in 227.072083ms
File test.yml updated successfully.
```

*Режим сухого прогона с diff:*
```bash
./bin/yed --file test.yml --key="my-super-secure-key" --operation encrypt --dry-run --diff
YAML processing completed in 237.009042ms
Dry-run mode: The following changes would be applied:
```

## **Последние обновления**

### **Поддержка YAML форматирования**
- Добавлена расширенная поддержка многострочного YAML:
  - Добавлена комплексная обработка многострочных узлов с сохранением стиля (литеральный `|`, свернутый `>`)
  - Реализовано интеллектуальное определение стиля и его восстановление при циклах шифрования/дешифрования
  - Добавлена специальная обработка PEM-сертификатов и ключей в обоих форматах (литеральный блок и строка с экранированными переносами строк)
  - Создано автоматическое определение типов контента, требующих специального форматирования (сертификаты, табуляции, переносы строк)
  - Добавлены маркеры стиля для сохранения информации о форматировании через циклы шифрования/дешифрования
  - Реализовано умное форматирование при дешифровании на основе типа контента и оригинального стиля

### **Улучшения безопасности**
- Обновлены требования к паролю в соответствии с NIST SP 800-63B:
  - Минимальная длина пароля увеличена до 15 символов
  - Максимальная длина пароля остается 64 символа
- Улучшена защита памяти:
  - Оптимизировано использование защищенной памяти для мастер-ключа шифрования
  - Улучшен расчет HMAC для всех блоков данных
  - Оптимизирована обработка данных с уменьшением количества защищенных копий
  - Упрощена логика сжатия данных
  - Разделен подход для алгоритма шифрования и параметров

### **Улучшения тестирования**
- Добавлены возможности ручного тестирования через Makefile:
  - Добавлена команда `test-manual` для тестирования файлов из директории `.test`
  - Реализовано тестирование сначала в режиме dry-run, затем в режиме отладки
  - Добавлена специальная поддержка тестирования cert-test.yml
  - Изменена команда help для включения новой опции test-manual

### **Docker поддержка**
- Добавлены упрощенные аргументы для сборки и запуска Docker:
  - Улучшено версионирование Docker-образов
  - Улучшена кросс-платформенная совместимость

### **Улучшения производительности**
- Добавлены специализированные цели для бенчмарков в Makefile:
  - `benchmark` - Базовые бенчмарки для пакета шифрования
  - `benchmark-long` - Длительные бенчмарки (5с на тест)
  - `benchmark-encryption` - Бенчмарки для операций шифрования/дешифрования
  - `benchmark-algorithms` - Бенчмарки для алгоритмов формирования ключа
  - `benchmark-argon2` - Бенчмарки для различных конфигураций Argon2
  - `benchmark-report` - Генерация подробного отчета о бенчмарках в формате markdown

### **Улучшения кода**
- Улучшено тестовое покрытие для processing.go
- Добавлена функция cleanerEncrypted для обработки непечатаемых строк
- Улучшена отладочная информация с подробными комментариями по этапам
- Добавлена поддержка пользовательского пути к конфигурационному файлу через флаг `--config`

## **Изменения в последнем обновлении**

### **Гибкость криптографических алгоритмов**
- Добавлена поддержка нескольких алгоритмов формирования ключа:
  - **Argon2id**: Алгоритм по умолчанию, рекомендованный OWASP
  - **PBKDF2-SHA256**: Добавлен для совместимости с NIST/FIPS (600,000 итераций)
  - **PBKDF2-SHA512**: Добавлен для совместимости с NIST/FIPS (210,000 итераций)
- Сравнение производительности:
  - PBKDF2-SHA256 примерно в 180 раз быстрее Argon2id при сопоставимой безопасности
  - PBKDF2-SHA512 примерно в 80 раз быстрее Argon2id при сопоставимой безопасности
- Алгоритм автоматически определяется при дешифровании
- Сохраняет обратную совместимость с ранее зашифрованными данными
- Позволяет указать алгоритм через аргумент командной строки
- Добавлена функция `SetKeyDerivationAlgorithm` в пакет processor для гибкого выбора алгоритма

### **Улучшения безопасности паролей**
- Реализована валидация надежности пароля в соответствии с OWASP:
  - Поддержка паролей длиной до 64 символов для возможности использования парольных фраз
  - Обнаружение и предотвращение использования общих/скомпрометированных паролей
  - Оценка надежности пароля (Низкая/Средняя/Высокая)
  - Интеллектуальные предложения по улучшению пароля
  - Проверка на разнообразие символов (прописные, строчные, цифры, символы)
  - Отсутствие произвольных правил, ограничивающих типы символов

### **Оптимизация производительности**
- Оптимизированы параметры Argon2id в соответствии с рекомендациями OWASP:
  - Объем памяти уменьшен с 256 МБ до 9 МБ (9216 KiБ)
  - Количество потоков уменьшено с 8 до 1 при сохранении 4 итераций
  - Вывод ключа примерно в 8 раз быстрее (уменьшено с ~136 мс до ~17 мс)
  - Использование памяти уменьшено в 27 раз (с ~268 МБ до ~10 МБ)
  - Поддерживает тот же уровень безопасности при значительном снижении потребления ресурсов
  - Улучшена производительность на устройствах с ограниченными ресурсами
  - Снижен риск DoS-атак на основе памяти

### **Улучшения системы сборки**
- Исправлен Makefile для правильной компиляции всех исходных файлов:
  - Обновлены цели сборки для корректного включения всех исходных файлов
  - Изменены команды сборки для работы с директориями вместо отдельных файлов
  - Добавлены правильные префиксы путей для корректного разрешения модулей Go
  - Обеспечена стабильная сборка на всех поддерживаемых платформах

### **Улучшенный вывод diff**
- Добавлены номера строк в вывод diff для более легкой идентификации изменений
- Формат вывода теперь показывает: `[номер_строки] - старое_значение` и `[номер_строки] + новое_значение`
- Добавлена поддержка маскирования конфиденциальной информации в выводе отладки и режиме diff

### **Улучшения безопасности**
- Добавлено правильное маскирование конфиденциальных значений в выводе отладки и режиме diff
- Реализовано настраиваемое маскирование через параметр `unsecure_diff`
- Улучшена защита зашифрованных значений с частичным отображением

### **Исправления ошибок и улучшения**
- Исправлен порядок аргументов в вызовах функций шифрования/дешифрования для правильной обработки параметров ключа и значения
- Улучшена обработка коротких значений, которые ранее не могли быть зашифрованы из-за путаницы с параметрами
- Уменьшена когнитивная сложность функций для лучшей поддерживаемости
- Улучшена обработка правил с `action: none` для правильного исключения путей из шифрования
- Переведены все комментарии в коде на английский язык для лучшего международного сотрудничества
- Добавлена константа `MaskedValue` для устранения дублирования строковых литералов

### **Улучшения конфигурации**
- Добавлены более понятные примеры конфигурации правил
- Улучшена обработка правил исключения
- Добавлена подробная документация для параметров правил
- Добавлен параметр `unsecure_diff` для управления видимостью конфиденциальных значений в выводе diff

---

### **Лицензия**

Это проект с открытым исходным кодом под лицензией [MIT](https://github.com/atlet99/yaml-encrypter-decrypter/blob/main/LICENSE).